"""Investigation-team runs for the web UI: started in the background, polled.

A team run is several model round-trips per role and routinely takes minutes.
The web server is single-threaded on purpose (see app.py), so a synchronous
request would freeze every other page for that long. Instead a run goes on a
daemon thread - the same shape as a live-capture session - and the frontend
polls its status, exactly as it polls capture status.

The finished result is written to cases/<id>/team/latest.json, so it survives a
page reload or a server restart and the investigator can accept findings from it
later. Only the latest run is kept: it is a working set of proposals, and every
accepted one becomes a Finding with its own audit trail. The API key used for the
run is never written anywhere.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

TEAM_DIRNAME = "team"
LATEST_FILENAME = "latest.json"

_RUNS = {}  # case_id -> TeamRun (running, or finished this process)
_RUNS_LOCK = threading.Lock()


class TeamRunError(Exception):
    """Raised when a run cannot be started (e.g. one is already running)."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def latest_path(case_dir):
    return Path(case_dir) / TEAM_DIRNAME / LATEST_FILENAME


def load_latest(case_dir):
    """The last finished run for a case, or None."""
    path = latest_path(case_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _evidence_key(finding):
    return frozenset(
        (c.get("kind"), c.get("evidence_id"), str(c.get("reference"))) for c in finding.get("citations") or []
    )


def carry_over_accepted(previous, findings):
    """{new_index: finding_id} for new findings resting on exactly the evidence
    of one already accepted in the previous run.

    Each run replaces the last, so without this a re-run would offer "Accept"
    again on a finding the investigator already recorded - one click from a
    duplicate. Matching is on cited evidence, not wording: models rephrase
    titles between runs, but the same evidence is the same finding.
    """
    if not previous:
        return {}
    old = previous.get("findings") or []
    accepted_keys = {}
    for index, finding_id in (previous.get("accepted") or {}).items():
        if index.isdigit() and int(index) < len(old):
            accepted_keys[_evidence_key(old[int(index)])] = finding_id
    carried = {}
    for index, finding in enumerate(findings):
        key = _evidence_key(finding)
        if key and key in accepted_keys:
            carried[str(index)] = accepted_keys[key]
    return carried


def save_latest(case_dir, record):
    path = latest_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


class TeamRun:
    """One background run. snapshot() is what the status endpoint returns."""

    def __init__(self, case_id, case_dir, roles, provider, model):
        self.case_id = case_id
        self.case_dir = Path(case_dir)
        self.roles = roles
        self.provider = provider
        self.model = model
        self.state = "running"
        self.started_at = _now()
        self.finished_at = None
        self.current_role = None
        self.completed_roles = []
        self.error = None
        self._lock = threading.Lock()

    def progress(self, role):
        with self._lock:
            if self.current_role:
                self.completed_roles.append(self.current_role)
            self.current_role = role.name

    def finish(self, error=None):
        with self._lock:
            if self.current_role:
                self.completed_roles.append(self.current_role)
            self.current_role = None
            self.state = "failed" if error else "done"
            self.error = str(error) if error else None
            self.finished_at = _now()

    def snapshot(self):
        with self._lock:
            return {
                "state": self.state,
                "provider": self.provider,
                "model": self.model,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "roles": [role.name for role in self.roles],
                "current_role": self.current_role,
                "completed_roles": list(self.completed_roles),
                "error": self.error,
            }


def get_run(case_id):
    with _RUNS_LOCK:
        return _RUNS.get(case_id)


def start_run(case_id, case_dir, *, roles, evidence_types, provider, api_key, model, base_url, actor,
              investigate=None, record=None):
    """Start a team run on a daemon thread. Raises TeamRunError if one is
    already running for this case.

    `investigate` and `record` default to the real agents.investigate and
    agents.records.record_team_run; tests pass fakes so no provider is called.
    """
    if investigate is None:
        from netforensicai.agents import investigate
    if record is None:
        from netforensicai.agents.records import record_team_run as record

    # Progress lists only the roles that will actually run: a role with no
    # evidence to read is skipped by investigate() and must not sit in the
    # panel as "queued" for the whole run.
    shown = roles
    if evidence_types is not None:
        from netforensicai.agents.coordinator import scope_roles

        shown, _skipped = scope_roles(roles, evidence_types)

    with _RUNS_LOCK:
        existing = _RUNS.get(case_id)
        if existing is not None and existing.state == "running":
            raise TeamRunError("An investigation team run is already in progress for this case.")
        run = TeamRun(case_id, case_dir, shown, provider, model)
        _RUNS[case_id] = run

    def work():
        from netforensicai.core.store import GLOBAL_WRITE_LOCK

        result, error = None, None
        try:
            result = investigate(
                case_dir,
                roles=roles,
                provider=provider,
                api_key=api_key,
                model=model,
                base_url=base_url,
                evidence_types=evidence_types,
                progress=run.progress,
            )
            ran = [r for r in result.role_results if not (r.note or "").startswith("skipped")]
            if ran and all((r.note or "").startswith("provider failed") for r in ran):
                error = ran[0].note
        except Exception as e:  # a crash must end the run, not leave it "running" forever
            error = e

        record_data = {
            "provider": provider,
            "model": model,
            "started_at": run.started_at,
            "finished_at": _now(),
            "error": str(error) if error else None,
            **(result.to_dict() if result is not None else {"role_results": [], "findings": []}),
        }
        record_data["accepted"] = carry_over_accepted(load_latest(case_dir), record_data["findings"])
        try:
            # Audit and result writes happen under the same lock the capture
            # thread and every locked_store() user take - this thread runs
            # concurrently with web requests.
            with GLOBAL_WRITE_LOCK:
                save_latest(case_dir, record_data)
                if record_data["role_results"] and any(
                    not (r.get("note") or "").startswith("skipped") for r in record_data["role_results"]
                ):
                    record(case_dir, record_data, provider, model, actor=actor, error=error)
        finally:
            run.finish(error)

    threading.Thread(target=work, daemon=True, name=f"team-{case_id}").start()
    return run


def status(case_id, case_dir):
    """What the panel needs: the live run if one is in progress, and the latest
    saved result (which is what a finished run produced)."""
    run = get_run(case_id)
    return {
        "run": run.snapshot() if run is not None else None,
        "latest": load_latest(case_dir),
    }
