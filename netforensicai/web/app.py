"""Local web UI for browsing cases: evidence, timeline, entity graph,
findings, reports, and live capture - a thin visualization layer over the
same core modules the CLI uses, not a second implementation of any of it.

Local-first and single-user by design: binds to 127.0.0.1 by default,
has no authentication, and Flask's debug/reloader mode is never enabled
here (it exposes an interactive in-browser debugger capable of arbitrary
code execution - a serious risk if this process were ever reachable from
a network). Only pass a different --host if you understand and accept
exposing this to other machines.

Every state-changing route requires the X-Requested-With header (see
CSRF_HEADER below) - not because this app has sessions or cookies to
steal, but because a browser tab open on an unrelated malicious page can
still reach 127.0.0.1 with a "simple" cross-origin POST (multipart form
upload, or JSON sent as text/plain) that needs no CORS preflight. Without
this check, that page could silently submit forged "evidence" into a real
case - undermining the chain-of-custody model this whole tool is built
around - or start a live capture without the analyst's knowledge. A
custom header forces the browser into a CORS preflight; since this app
never sends Access-Control-Allow-Origin, the preflight fails and the
browser never sends the real request. The frontend (app.js) sets this
header on every POST it makes.

Write surface is deliberately narrow. Evidence upload and analyze mirror
`netforensic evidence add` / `analyze` exactly (same EvidenceManager /
pipeline calls) - not a second ingestion path. Threat-intel check and AI
hypothesis trigger the same explicit, opt-in external lookups
`investigate --vt-api` / `--ai` already perform. Live capture start/stop
control a CaptureSession (core/capture.py) the same way `netforensic
capture` does. Creating or updating a Finding calls straight into
FindingManager, the same as `netforensic finding create/update` - still
always an explicit, investigator-initiated action, just from either
interface.

All CaseStore access here goes through locked_store() rather than
CaseStore(...) directly: a live capture session's background ingestion
thread can be writing to a case's DuckDB file at the same moment a
browser request reads it, and DuckDB is single-writer - see
core/store.py's GLOBAL_WRITE_LOCK.
"""

import logging
import shutil
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from netforensicai.core.case import CaseError, CaseManager
from netforensicai.core.correlation import DEFAULT_MAX_PAIRS as CORRELATION_MAX_PAIRS
from netforensicai.core.evidence import EvidenceError, EvidenceManager
from netforensicai.core.event import parse_timestamp
from netforensicai.core.finding import FindingManager
from netforensicai.core.investigate import investigate_entity
from netforensicai.core.report import RENDERERS, build_report
from netforensicai.core.store import locked_store
from netforensicai.core.timeline import build_timeline, filter_timeline

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

REPORT_MIMETYPES = {"markdown": "text/markdown", "json": "application/json", "html": "text/html"}

# Generous but bounded - evidence files (especially pcaps) can be large,
# but an unbounded upload is a disk-exhaustion DoS against a local tool
# with no auth in front of it.
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024

# See the CSRF paragraph in the module docstring.
CSRF_HEADER = "X-Requested-With"
CSRF_HEADER_VALUE = "NetForensicAI"


class ApiError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def create_app(cases_dir="cases"):
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    case_manager = CaseManager(cases_dir)

    def _load_case(case_id):
        try:
            return case_manager.load(case_id)
        except CaseError as e:
            raise ApiError(str(e), 404)

    def _case_dir(case):
        return Path(cases_dir) / case.case_id

    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return jsonify({"error": err.message}), err.status_code

    @app.before_request
    def _require_csrf_header_on_writes():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.headers.get(CSRF_HEADER) != CSRF_HEADER_VALUE:
                raise ApiError(
                    f"Missing or invalid {CSRF_HEADER} header - refused to prevent cross-site request forgery.",
                    403,
                )

    @app.errorhandler(413)
    def handle_too_large(_err):
        return jsonify({"error": f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)."}), 413

    # --- static frontend ---

    @app.route("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(STATIC_DIR, filename)

    # --- cases ---

    @app.route("/api/cases")
    def list_cases():
        return jsonify([c.to_dict() for c in case_manager.list()])

    @app.route("/api/cases/<case_id>")
    def get_case(case_id):
        case = _load_case(case_id)
        evidence_items = EvidenceManager(_case_dir(case)).list()
        with locked_store(_case_dir(case)) as store:
            event_count = store.count_events()
            entity_count = store.count_entities()
            detection_count = store.count_detections()
            correlation_count = store.count_correlation_links()
            correlation_by_type = store.count_correlation_links_by_type()
            # A count that lands exactly on the budget means correlation
            # stopped, not that the case holds precisely that many
            # relationships. Displaying the round number as a finding is
            # the kind of false precision a forensics tool must not print.
            correlation_capped = correlation_count >= CORRELATION_MAX_PAIRS
        finding_count = len(FindingManager(_case_dir(case)).list())

        data = case.to_dict()
        data.update(
            evidence_count=len(evidence_items),
            event_count=event_count,
            entity_count=entity_count,
            finding_count=finding_count,
            detection_count=detection_count,
            correlation_count=correlation_count,
            correlation_capped=correlation_capped,
            # Split as well as totalled: `related` (shared entity plus time
            # proximity) and `possible_relationship` (proximity alone) are
            # different strengths of claim, and a single number reads as
            # though they were the same.
            correlation_by_type=correlation_by_type,
            artifact_count=len(case.artifacts),
        )
        return jsonify(data)

    @app.route("/api/cases/<case_id>", methods=["DELETE"])
    def delete_case(case_id):
        """Delete a case and everything in it.

        Requires the case ID echoed back in the body. That is not
        ceremony: this removes the evidence copies, the store, the carved
        artifacts AND the chain of custody, and a confirmation the caller
        has to reproduce is what separates the case they meant from the
        one that happened to be selected.
        """
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        try:
            summary = case_manager.delete(case.case_id, confirm_case_id=payload.get("confirm"))
        except CaseError as e:
            raise ApiError(str(e))
        return jsonify(summary)

    @app.route("/api/cases/<case_id>/status", methods=["POST"])
    def set_case_status(case_id):
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        status = (payload.get("status") or "").strip()
        try:
            updated = case_manager.update_status(case.case_id, status)
        except CaseError as e:
            raise ApiError(str(e))
        return jsonify(updated.to_dict())

    # --- evidence ---

    @app.route("/api/cases/<case_id>/evidence")
    def list_evidence(case_id):
        case = _load_case(case_id)
        items = EvidenceManager(_case_dir(case)).list()
        return jsonify([e.to_dict() for e in items])

    @app.route("/api/cases/<case_id>/evidence", methods=["POST"])
    def upload_evidence(case_id):
        case = _load_case(case_id)
        if "file" not in request.files:
            raise ApiError("No file provided (expected multipart field 'file').")
        uploaded = request.files["file"]
        filename = secure_filename(uploaded.filename or "")
        if not filename:
            raise ApiError("No file selected, or filename is invalid.")

        staging_dir = Path(tempfile.mkdtemp(prefix="netforensic_upload_"))
        try:
            staging_path = staging_dir / filename
            uploaded.save(staging_path)

            evidence_manager = EvidenceManager(_case_dir(case))
            try:
                evidence = evidence_manager.add(staging_path, case_id=case.case_id)
            except EvidenceError as e:
                raise ApiError(str(e))
            case_manager.register_evidence(case.case_id, evidence.evidence_id)
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

        return jsonify(evidence.to_dict()), 201

    # --- analyze (parse every evidence item + correlate, mirrors `netforensic analyze`) ---

    @app.route("/api/cases/<case_id>/analyze", methods=["POST"])
    def analyze_case(case_id):
        case = _load_case(case_id)
        from netforensicai.core.correlation import correlate_case
        from netforensicai.core.detections import scan_case as scan_detections
        from netforensicai.core.pipeline import parse_evidence_item

        payload = request.get_json(force=True, silent=True) or {}
        # Same knobs as `netforensic analyze --engine ...`. Threaded
        # through parse_evidence_item rather than applied here so a case
        # analyzed from the web UI records the identical audit detail as
        # one analyzed from the CLI.
        parse_options = {
            "engine": payload.get("engine") or None,
            "display_filter": payload.get("display_filter") or None,
        }

        items = EvidenceManager(_case_dir(case)).list()
        results = []
        with locked_store(_case_dir(case)) as store:
            for evidence in items:
                event_count, entity_count, error = parse_evidence_item(
                    evidence, _case_dir(case), case_manager, case.case_id, store, parse_options
                )
                results.append(
                    {
                        "evidence_id": evidence.evidence_id,
                        "evidence_type": evidence.evidence_type,
                        "event_count": event_count,
                        "entity_count": entity_count,
                        "error": error,
                    }
                )
            correlate_case(store)
            # Bundled detection rules: local, deterministic, zero-cost -
            # runs automatically here just like correlation does, unlike
            # ATT&CK mapping which stays behind an explicit scan action.
            detections = scan_detections(store)
            total_entities = store.count_entities()
            total_events = store.count_events()

        return jsonify(
            {
                "results": results,
                "total_events": total_events,
                "total_entities": total_entities,
                "detection_count": len(detections),
            }
        )

    # --- detections (read-only; recomputed automatically by /analyze) ---

    @app.route("/api/cases/<case_id>/detections")
    def list_detections(case_id):
        case = _load_case(case_id)
        severity = request.args.get("severity") or None
        with locked_store(_case_dir(case)) as store:
            detections = store.list_detections(severity=severity)
        for d in detections:
            d["detected_at"] = d["detected_at"].isoformat() if d["detected_at"] else None
        return jsonify(detections)

    # --- timeline ---

    @app.route("/api/cases/<case_id>/timeline")
    def get_timeline(case_id):
        case = _load_case(case_id)
        with locked_store(_case_dir(case)) as store:
            entries = build_timeline(store)

        time_from = parse_timestamp(request.args.get("from")) if request.args.get("from") else None
        time_to = parse_timestamp(request.args.get("to")) if request.args.get("to") else None
        entries = filter_timeline(
            entries,
            time_from=time_from,
            time_to=time_to,
            user=request.args.get("user"),
            ip=request.args.get("ip"),
            hostname=request.args.get("hostname"),
            process=request.args.get("process"),
            file=request.args.get("file"),
            event_type=request.args.get("type"),
            evidence_id=request.args.get("evidence"),
        )
        return jsonify([e.to_dict() for e in entries])

    # --- entities ---

    @app.route("/api/cases/<case_id>/entities")
    def list_entities(case_id):
        case = _load_case(case_id)
        entity_type = request.args.get("type") or None
        query = request.args.get("q", "").strip().lower()
        with locked_store(_case_dir(case)) as store:
            items = store.list_entities(entity_type=entity_type)
            # Two aggregates for the whole case rather than a query per
            # entity: ranking entities needs a count on every row, and the
            # per-row alternative is thousands of round trips.
            event_counts = store.entity_event_counts()
            link_counts = store.entity_link_counts()
        if query:
            items = [e for e in items if query in e["value"].lower()]
        for item in items:
            item["event_count"] = event_counts.get(item["entity_id"], 0)
            item["link_count"] = link_counts.get(item["entity_id"], 0)
        if request.args.get("sort") == "events":
            items.sort(key=lambda e: (e["event_count"], e["link_count"]), reverse=True)
        # A dashboard panel showing six rows should not be sent eighteen
        # thousand. Applied after sorting so `limit` means "the top N",
        # not "an arbitrary N".
        limit = request.args.get("limit")
        if limit:
            try:
                items = items[: max(int(limit), 0)]
            except ValueError:
                raise ApiError("limit must be a number")
        return jsonify(items)

    @app.route("/api/cases/<case_id>/entities/<entity_id>/graph")
    def entity_graph(case_id, entity_id):
        case = _load_case(case_id)
        with locked_store(_case_dir(case)) as store:
            entity = store.get_entity(entity_id)
            if entity is None:
                raise ApiError(f"Entity not found: {entity_id}", 404)
            related = store.related_entities(entity_id)
        return jsonify({"entity": entity, "related": related})

    # --- investigate ---

    @app.route("/api/cases/<case_id>/investigate")
    def investigate(case_id):
        case = _load_case(case_id)
        entity_type = request.args.get("type")
        value = request.args.get("value")
        if not entity_type or not value:
            raise ApiError("type and value query parameters are required")

        with locked_store(_case_dir(case)) as store:
            result = investigate_entity(store, entity_type, value)
            if result is None:
                raise ApiError(f"No evidence of {entity_type} '{value}' found in this case", 404)
            return jsonify(
                {
                    "entity": result.entity,
                    "evidence_ids": result.evidence_ids,
                    "timeline": [e.to_dict() for e in result.timeline_entries],
                    "related_entities": result.related_entities,
                    "correlation_links": result.correlation_links,
                    "leads": result.leads,
                }
            )

    # --- threat intel (opt-in, explicit external call) ---

    @app.route("/api/cases/<case_id>/threat-intel", methods=["POST"])
    def check_threat_intel(case_id):
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        entity_id = payload.get("entity_id")
        entity_type = payload.get("entity_type")
        value = payload.get("value")
        if not all([entity_id, entity_type, value]):
            raise ApiError("entity_id, entity_type, and value are required")

        from netforensicai.core import threat_intel
        from netforensicai.intel import virustotal

        resolved_key = virustotal.get_api_key(payload.get("api_key"))
        with locked_store(_case_dir(case)) as store:
            result = threat_intel.check_entity(store, entity_id, entity_type, value, resolved_key)
        if result is None:
            raise ApiError(f"No threat intelligence source for entity type '{entity_type}'")
        return jsonify(result)

    # --- AI hypothesis (opt-in, explicit external call) ---

    # --- settings (API keys / provider preferences) ---
    # Keys are stored outside any case directory (see core/config.py) so
    # they never ride along in a `case export` archive, and are never sent
    # back to the browser in full - only "is it set" plus a masked hint.

    @app.route("/api/settings")
    def get_settings():
        from netforensicai.core import config

        return jsonify(config.masked_settings())

    @app.route("/api/settings", methods=["POST"])
    def update_settings():
        from netforensicai.core import config

        payload = request.get_json(force=True, silent=True) or {}
        config.save_settings(payload)
        return jsonify(config.masked_settings())

    @app.route("/api/settings/test", methods=["POST"])
    def test_settings():
        """Verify a saved/entered credential actually works, rather than
        leaving the investigator to find out mid-investigation. Makes one
        real, minimal request to the named provider."""
        payload = request.get_json(force=True, silent=True) or {}
        target = payload.get("target")

        if target == "virustotal":
            from netforensicai.intel import virustotal

            key = virustotal.get_api_key(payload.get("api_key"))
            if not key:
                return jsonify({"ok": False, "message": "No VirusTotal API key set."})
            # 8.8.8.8 is a stable, uncontroversial lookup target - this is
            # only checking that the credential is accepted.
            result = virustotal.check_ip("8.8.8.8", key)
            if result.get("error"):
                return jsonify({"ok": False, "message": f"VirusTotal rejected the request: {result['error']}"})
            return jsonify({"ok": True, "message": "VirusTotal key works."})

        if target in ("anthropic", "openai", "gemini", "ollama"):
            from netforensicai.core.ai_assistant import AssistantError, generate_hypothesis
            from netforensicai.core.event import Event

            probe = Event(
                event_id="EVT-PROBE-0001",
                evidence_id="EV-PROBE",
                source="probe",
                event_type="authentication",
                message="Connectivity probe - not real evidence.",
            )
            try:
                generate_hypothesis(
                    [probe],
                    provider=target,
                    api_key=payload.get("api_key") or None,
                    model=payload.get("model") or None,
                    base_url=payload.get("base_url") or None,
                )
            except AssistantError as e:
                return jsonify({"ok": False, "message": str(e)})
            return jsonify({"ok": True, "message": f"{target} responded successfully."})

        raise ApiError(f"Unknown test target '{target}'.")

    @app.route("/api/ai-providers")
    def list_ai_providers():
        from netforensicai.core.ai_assistant import DEFAULT_MODELS, SUPPORTED_PROVIDERS

        return jsonify({"providers": list(SUPPORTED_PROVIDERS), "default_models": DEFAULT_MODELS})

    @app.route("/api/cases/<case_id>/ai-hypothesis", methods=["POST"])
    def ai_hypothesis(case_id):
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        entity_type = payload.get("entity_type")
        value = payload.get("value")

        if not entity_type or not value:
            raise ApiError("entity_type and value are required")

        from netforensicai.core.ai_assistant import AssistantError, generate_hypothesis

        with locked_store(_case_dir(case)) as store:
            result = investigate_entity(store, entity_type, value)
            if result is None:
                raise ApiError(f"No evidence of {entity_type} '{value}' found in this case", 404)
            events = result.events

        try:
            hypothesis = generate_hypothesis(
                events,
                provider=payload.get("provider") or "anthropic",
                api_key=payload.get("api_key"),
                model=payload.get("model") or None,
                base_url=payload.get("base_url") or None,
            )
        except AssistantError as e:
            raise ApiError(str(e), 502)
        return jsonify(hypothesis.model_dump())

    @app.route("/api/cases/<case_id>/chat", methods=["POST"])
    def ai_chat(case_id):
        """Ask a question about the case, with the assistant retrieving
        evidence through read-only tools.

        Every claim is checked against what those tools actually returned;
        an answer citing anything else is refused by core/chat.py and
        surfaced here as an error rather than as an answer with a caveat.
        A 502 is the right shape for that: the provider produced something
        unusable, and there is no partial result worth showing.
        """
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        question = (payload.get("question") or "").strip()
        if not question:
            raise ApiError("question is required")

        from netforensicai.core import chat as chat_module

        try:
            result = chat_module.ask(
                question,
                _case_dir(case),
                provider=payload.get("provider") or "anthropic",
                api_key=payload.get("api_key"),
                model=payload.get("model") or None,
                base_url=payload.get("base_url") or None,
                max_steps=int(payload.get("max_steps") or chat_module.MAX_STEPS),
            )
        except chat_module.ChatError as e:
            raise ApiError(str(e), 502)
        return jsonify(result.to_dict())

    # --- findings ---
    # Creating/updating a finding remains an explicit, investigator-owned
    # action (see core/finding.py's module docstring) - the web UI is a
    # second way to perform that same action, not a second implementation
    # of it. Both routes call straight into FindingManager, exactly like
    # `netforensic finding create/update` do.

    @app.route("/api/cases/<case_id>/findings")
    def list_findings(case_id):
        case = _load_case(case_id)
        findings = FindingManager(_case_dir(case)).list()
        return jsonify([f.to_dict() for f in findings])

    @app.route("/api/cases/<case_id>/findings", methods=["POST"])
    def create_finding(case_id):
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        title = (payload.get("title") or "").strip()
        if not title:
            raise ApiError("title is required")

        event_ids = payload.get("event_ids") or []
        evidence_refs = []
        with locked_store(_case_dir(case)) as store:
            valid_event_ids = {e.event_id for e in store.all_events()}
            for event_id in event_ids:
                event = store.get_event(event_id)
                if event is None:
                    raise ApiError(f"event_id '{event_id}' not found in {case.case_id}.")
                evidence_refs.append({"evidence_id": event.evidence_id, "event_id": event.event_id})

        from netforensicai.core.finding import FindingError

        finding_manager = FindingManager(_case_dir(case))
        try:
            finding = finding_manager.create(
                case_id=case.case_id,
                title=title,
                created_by=payload.get("investigator") or "web-ui",
                severity=payload.get("severity") or "Medium",
                status=payload.get("status") or "Open",
                assessment=payload.get("assessment") or "",
                evidence_refs=evidence_refs,
                valid_event_ids=valid_event_ids,
            )
        except FindingError as e:
            raise ApiError(str(e))

        case_manager.register_finding(case.case_id, finding.finding_id)
        return jsonify(finding.to_dict()), 201

    @app.route("/api/cases/<case_id>/findings/<finding_id>", methods=["POST"])
    def update_finding(case_id, finding_id):
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        status = payload.get("status")
        note = payload.get("note")
        if not status and not note:
            raise ApiError("status and/or note is required")

        from netforensicai.core.finding import FindingError

        finding_manager = FindingManager(_case_dir(case))
        try:
            finding = None
            if status:
                finding = finding_manager.update_status(finding_id, status)
            if note:
                finding = finding_manager.add_note(finding_id, note, payload.get("investigator") or "web-ui")
        except FindingError as e:
            raise ApiError(str(e), 404 if "not found" in str(e).lower() else 400)

        return jsonify(finding.to_dict())

    # --- ATT&CK technique mappings (read-only; run/validate via the CLI) ---

    @app.route("/api/cases/<case_id>/attack")
    def list_attack_techniques(case_id):
        case = _load_case(case_id)
        with locked_store(_case_dir(case)) as store:
            techniques = store.list_techniques()
        for t in techniques:
            t["created_at"] = t["created_at"].isoformat() if t["created_at"] else None
            t["updated_at"] = t["updated_at"].isoformat() if t["updated_at"] else None
        return jsonify(techniques)

    # --- chain of custody (read-only; append-only by construction) ---

    @app.route("/api/cases/<case_id>/audit")
    def get_audit_log(case_id):
        from netforensicai.core import audit

        case = _load_case(case_id)
        case_dir = _case_dir(case)
        intact, problems = audit.verify(case_dir)
        return jsonify(
            {"intact": intact, "problems": problems, "entries": audit.read_entries(case_dir)}
        )

    # --- reports ---

    @app.route("/api/cases/<case_id>/report/<fmt>")
    def get_report(case_id, fmt):
        case = _load_case(case_id)
        fmt = fmt.lower()
        if fmt not in RENDERERS:
            raise ApiError(f"Unsupported format '{fmt}'. Choose from: {', '.join(RENDERERS)}")
        report = build_report(case, _case_dir(case))
        content = RENDERERS[fmt](report)
        return app.response_class(content, mimetype=REPORT_MIMETYPES[fmt])

    # --- live capture ---
    # Polled by the frontend rather than streamed (SSE): a persistent
    # streaming connection would need a threaded server, which conflicts
    # with keeping DuckDB access serialized through one global lock - see
    # the module docstring. ~1.5s polling is plenty responsive for this.

    @app.route("/api/interfaces")
    def api_list_interfaces():
        from netforensicai.core import capture as capture_module

        try:
            return jsonify(capture_module.list_interfaces())
        except Exception as e:
            raise ApiError(f"Could not list network interfaces: {e}", 500)

    @app.route("/api/cases/<case_id>/capture/status")
    def capture_status(case_id):
        case = _load_case(case_id)
        from netforensicai.core import capture as capture_module

        session = capture_module.get_session(case.case_id)
        if session is None:
            return jsonify({"running": False})
        return jsonify(session.snapshot())

    @app.route("/api/cases/<case_id>/capture/start", methods=["POST"])
    def capture_start(case_id):
        case = _load_case(case_id)
        from netforensicai.core import capture as capture_module

        payload = request.get_json(force=True, silent=True) or {}
        rotate_seconds = payload.get("rotate_seconds") or capture_module.DEFAULT_ROTATE_SECONDS
        try:
            rotate_seconds = int(rotate_seconds)
        except (TypeError, ValueError):
            raise ApiError("rotate_seconds must be an integer")

        try:
            capture_module.start_capture(
                case.case_id,
                _case_dir(case),
                case_manager,
                interface=payload.get("interface") or None,
                bpf_filter=payload.get("filter") or None,
                rotate_seconds=rotate_seconds,
                engine=payload.get("engine") or None,
            )
        except capture_module.CaptureError as e:
            status = 409 if "already running" in str(e) else 400
            raise ApiError(str(e), status)
        return jsonify({"started": True})

    @app.route("/api/cases/<case_id>/capture/stop", methods=["POST"])
    def capture_stop(case_id):
        case = _load_case(case_id)
        from netforensicai.core import capture as capture_module

        try:
            capture_module.stop_capture(case.case_id)
        except capture_module.CaptureError as e:
            raise ApiError(str(e), 404)
        return jsonify({"stopped": True})

    # --- dig: content search, stream reassembly, triage ---
    #
    # These wrap core/search.py, core/streams.py and core/ctf.py, which
    # until now were reachable only from the CLI. All three are READ-ONLY
    # questions asked of a capture file: none of them touches the store,
    # writes an artifact, or creates a finding. That is why they are plain
    # GET/POST reads with no audit entry - recording that someone looked
    # at evidence is not what the chain of custody is for.

    def _capture_path(case, evidence_id):
        """Resolve a pcap evidence item to its stored copy.

        Always the stored copy, never the path it was added from: that is
        the one that was hashed into the chain of custody.
        """
        manager = EvidenceManager(_case_dir(case))
        captures = [item for item in manager.list() if item.evidence_type == "pcap"]
        if not captures:
            raise ApiError("This case has no capture evidence.", 404)
        if evidence_id:
            for item in captures:
                if item.evidence_id == evidence_id:
                    return item, manager.stored_file_path(item.evidence_id)
            raise ApiError(f"No capture evidence {evidence_id} in this case.", 404)
        return captures[0], manager.stored_file_path(captures[0].evidence_id)

    @app.route("/api/cases/<case_id>/search", methods=["POST"])
    def search_case(case_id):
        """Content search over a capture's raw bytes."""
        case = _load_case(case_id)
        from netforensicai.core import search as search_module

        payload = request.get_json(force=True, silent=True) or {}
        pattern = (payload.get("pattern") or "").strip()
        if not pattern:
            raise ApiError("pattern is required")

        evidence, path = _capture_path(case, payload.get("evidence_id"))
        try:
            result = search_module.search_capture(
                path,
                pattern,
                mode=payload.get("mode") or search_module.TEXT,
                case_sensitive=bool(payload.get("case_sensitive")),
                max_hits=int(payload.get("max_hits") or search_module.DEFAULT_MAX_HITS),
                display_filter=payload.get("display_filter") or None,
            )
        except search_module.SearchError as e:
            # A bad pattern or a missing tshark is the caller's problem to
            # fix, not a server fault - 400 rather than 500.
            raise ApiError(str(e))

        data = result.to_dict()
        data["evidence_id"] = evidence.evidence_id
        return jsonify(data)

    @app.route("/api/cases/<case_id>/streams")
    def list_case_streams(case_id):
        case = _load_case(case_id)
        from netforensicai.core import streams as streams_module

        evidence, path = _capture_path(case, request.args.get("evidence"))
        try:
            found = streams_module.list_streams(
                path,
                protocol=request.args.get("protocol") or streams_module.TCP,
                display_filter=request.args.get("filter") or None,
                limit=int(request.args.get("limit") or streams_module.DEFAULT_STREAM_LIMIT),
            )
        except streams_module.StreamError as e:
            raise ApiError(str(e))
        return jsonify({"evidence_id": evidence.evidence_id, "streams": [s.to_dict() for s in found]})

    @app.route("/api/cases/<case_id>/streams/<int:index>")
    def follow_case_stream(case_id, index):
        case = _load_case(case_id)
        from netforensicai.core import streams as streams_module

        evidence, path = _capture_path(case, request.args.get("evidence"))
        try:
            followed = streams_module.follow_stream(
                path,
                protocol=request.args.get("protocol") or streams_module.TCP,
                index=index,
                max_bytes=int(request.args.get("max_bytes") or streams_module.DEFAULT_MAX_BYTES),
            )
        except streams_module.StreamError as e:
            raise ApiError(str(e), 404)
        data = followed.to_dict()
        data["evidence_id"] = evidence.evidence_id
        return jsonify(data)

    @app.route("/api/cases/<case_id>/triage")
    def triage_case(case_id):
        """Run the triage presets over a capture.

        Deliberately does NOT extract files: object export writes to disk,
        and a GET that a dashboard polls must not have that side effect.
        Recovered files are still reported (name, size, hash) - saving
        them stays the explicit `--extract-to` action on the CLI.
        """
        case = _load_case(case_id)
        from netforensicai.core import ctf as ctf_module

        evidence, path = _capture_path(case, request.args.get("evidence"))
        try:
            report = ctf_module.triage(
                path,
                max_hits=int(request.args.get("max_hits") or ctf_module.DEFAULT_MAX_HITS_PER_CATEGORY),
                display_filter=request.args.get("filter") or None,
                output_dir=None,
            )
        except ctf_module.CtfError as e:
            raise ApiError(str(e))
        data = report.to_dict()
        data["evidence_id"] = evidence.evidence_id
        return jsonify(data)

    @app.route("/api/cases/<case_id>/artifacts")
    def list_artifacts(case_id):
        """Files carved out of evidence, with the sizes the dashboard shows.

        case.artifacts holds paths relative to the case directory; the
        names and sizes have to come from the files themselves. A path
        registered for a file that has since been removed is reported with
        a null size rather than skipped - a missing artifact is something
        an investigator needs to see, not something to hide.
        """
        case = _load_case(case_id)
        case_dir = _case_dir(case)

        rows = []
        for relative in case.artifacts:
            path = case_dir / relative
            rows.append(
                {
                    "path": relative,
                    "name": Path(relative).name,
                    "protocol": Path(relative).parent.name,
                    "size_bytes": path.stat().st_size if path.is_file() else None,
                    "missing": not path.is_file(),
                }
            )
        return jsonify(rows)

    # --- Wireshark integration ---
    #
    # The GUI pivot is deliberately NOT a "launch Wireshark" endpoint. The
    # web UI is served over HTTP and a browser page must not be able to
    # spawn a desktop application on the machine running the server - that
    # is a remote-process-launch primitive, and the fact that this server
    # is normally bound to localhost is a deployment detail, not a
    # guarantee. So this returns the display filter and the exact command,
    # and the analyst runs it (or uses `netforensic wireshark open`, where
    # the intent to launch is unambiguous because they typed it).

    @app.route("/api/wireshark/status")
    def wireshark_status():
        from netforensicai.integrations import wireshark
        from netforensicai.parsers import pcap_engine

        info = wireshark.status()
        info["parse_engine"] = pcap_engine.engine_status()
        return jsonify(info)

    @app.route("/api/wireshark/check-filter", methods=["POST"])
    def wireshark_check_filter():
        from netforensicai.integrations import wireshark

        payload = request.get_json(force=True, silent=True) or {}
        display_filter = (payload.get("display_filter") or "").strip()
        if not display_filter:
            raise ApiError("display_filter is required.")
        valid, error = wireshark.validate_display_filter(display_filter)
        return jsonify({"valid": valid, "error": error})

    @app.route("/api/cases/<case_id>/events/<event_id>/wireshark")
    def wireshark_pivot(case_id, event_id):
        """The display filter and command that isolate one event's packets."""
        case = _load_case(case_id)
        from netforensicai.integrations import wireshark

        with locked_store(_case_dir(case)) as store:
            event = store.get_event(event_id)
        if event is None:
            raise ApiError(f"No event {event_id} in {case.case_id}.", 404)

        evidence_manager = EvidenceManager(_case_dir(case))
        try:
            evidence = evidence_manager.load(event.evidence_id)
        except EvidenceError as e:
            raise ApiError(str(e), 404)
        if evidence.evidence_type != "pcap":
            raise ApiError(
                f"{event_id} came from {evidence.evidence_type} evidence, which has no packets to open.",
                400,
            )

        stored_path = evidence_manager.stored_file_path(evidence.evidence_id)
        display_filter = wireshark.filter_for_event(event)
        return jsonify(
            {
                "event_id": event_id,
                "evidence_id": evidence.evidence_id,
                "display_filter": display_filter,
                "command": wireshark.gui_command(stored_path, display_filter),
                "gui_available": wireshark.gui_path() is not None,
            }
        )

    @app.route("/api/cases/<case_id>/evidence/<evidence_id>/slice", methods=["POST"])
    def wireshark_slice(case_id, evidence_id):
        """Carve the packets matching a display filter into a new, hashed
        evidence item.

        Adding the slice back as evidence rather than streaming it to the
        browser is the point: a filtered view someone screenshotted is not
        reproducible, and a hashed capture recorded against its parent
        filter is.
        """
        case = _load_case(case_id)
        from netforensicai.core import audit
        from netforensicai.integrations import wireshark

        payload = request.get_json(force=True, silent=True) or {}
        display_filter = (payload.get("display_filter") or "").strip()
        if not display_filter:
            raise ApiError("display_filter is required.")

        evidence_manager = EvidenceManager(_case_dir(case))
        try:
            evidence = evidence_manager.load(evidence_id)
        except EvidenceError as e:
            raise ApiError(str(e), 404)
        if evidence.evidence_type != "pcap":
            raise ApiError(f"{evidence_id} is {evidence.evidence_type} evidence, not a capture file.")

        stored_path = evidence_manager.stored_file_path(evidence.evidence_id)
        staging_dir = Path(tempfile.mkdtemp(prefix="netforensic_slice_"))
        try:
            try:
                slice_path, packet_count = wireshark.extract_slice(
                    stored_path, display_filter, staging_dir / f"{evidence.evidence_id}-slice.pcap"
                )
            except wireshark.WiresharkError as e:
                raise ApiError(str(e))

            if packet_count == 0:
                # A valid answer to the filter, but adding an empty capture
                # to the chain of custody would imply something was found.
                return jsonify({"packet_count": 0, "evidence_id": None, "display_filter": display_filter})

            try:
                new_evidence = evidence_manager.add(slice_path, case_id=case.case_id)
            except EvidenceError as e:
                raise ApiError(str(e))
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

        case_manager.register_evidence(case.case_id, new_evidence.evidence_id)
        audit.record(
            _case_dir(case),
            audit.EVIDENCE_SLICED,
            {
                "evidence_id": new_evidence.evidence_id,
                "derived_from": evidence.evidence_id,
                "display_filter": display_filter,
                "packet_count": packet_count,
            },
        )
        return jsonify(
            {
                "packet_count": packet_count,
                "evidence_id": new_evidence.evidence_id,
                "display_filter": display_filter,
            }
        ), 201

    return app
