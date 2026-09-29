"""`netforensic team` - the CLI entry point for the investigation team.

The provider is replaced by a scripted model (ai_assistant.call_model is what
run_role calls in production), so these run the real command, the real roles,
the real read-only tools and the real citation checks - only the model's
replies are canned. Nothing here reaches a network.
"""

import json

import pytest
from typer.testing import CliRunner

from netforensicai.cli import app
from netforensicai.core import ai_assistant
from netforensicai.core.case import CaseManager
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.finding import FindingManager
from netforensicai.core.store import CaseStore
from netforensicai.parsers.generic import JsonParser

runner = CliRunner()


def _add_json_case(tmp_path, suffix=".json"):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="Team CLI case", investigator="analyst")
    case_dir = cases_dir / case.case_id
    source = tmp_path / f"events{suffix}"
    source.write_text(
        json.dumps(
            [
                {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe", "src_ip": "192.168.1.10"},
                {"timestamp": "2026-08-27T09:00:30Z", "type": "network_connection", "src_ip": "192.168.1.10",
                 "dst_ip": "203.0.113.7", "dst_port": 4444},
            ]
        ),
        encoding="utf-8",
    )
    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)
    events = JsonParser().parse(EvidenceManager(case_dir).stored_file_path(evidence.evidence_id), evidence_id=evidence.evidence_id)
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence(evidence.evidence_id, events)
        extract_and_store(store, events)
    return cases_dir, case.case_id, evidence.evidence_id, events


class _ScriptedModel:
    """Per role (identified from its system prompt): search, then report.

    `cite` decides what each role cites; a role can be made to cite an event
    no tool returned, which the real ledger check must drop.
    """

    def __init__(self, evidence_id, cite):
        self.evidence_id = evidence_id
        self.cite = cite
        self.turns = {}
        self.roles_called = []

    def __call__(self, system_prompt, user_prompt, **_kwargs):
        slug = "network" if "Network Forensics analyst" in system_prompt else "host"
        turn = self.turns.get(slug, 0)
        self.turns[slug] = turn + 1
        if turn == 0:
            self.roles_called.append(slug)
            return {"action": "tool", "tool": "search_events", "arguments": {}}
        reference = self.cite(slug)
        if reference is None:
            return {"action": "findings", "findings": []}
        return {
            "action": "findings",
            "findings": [{
                "title": "Outbound connection to port 4444",
                "severity": "High" if slug == "network" else "Info",
                "confidence": "medium",
                "assessment": f"{slug}: a connection to a port commonly used by Metasploit handlers.",
                "citations": [{"kind": "event", "evidence_id": self.evidence_id, "reference": reference}],
            }],
        }


@pytest.fixture
def json_case(tmp_path):
    return _add_json_case(tmp_path)


def _run(cases_dir, *args):
    return runner.invoke(app, ["team", "--cases-dir", str(cases_dir), *args])


def test_team_runs_roles_merges_and_prints_cited_findings(json_case, monkeypatch):
    cases_dir, case_id, evidence_id, events = json_case
    model = _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id)
    monkeypatch.setattr(ai_assistant, "call_model", model)

    result = _run(cases_dir, "--case", case_id)

    assert result.exit_code == 0, result.output
    # JSON evidence is readable by both roles, so both ran.
    assert model.roles_called == ["network", "host"]
    assert "Findings (1)" in result.output  # both cited the same event -> merged
    assert "[High] Outbound connection to port 4444" in result.output
    assert "network, host" in result.output
    assert f"event {events[1].event_id}" in result.output
    assert "nothing was written" in result.output
    assert FindingManager(cases_dir / case_id).list() == []


def test_unciteable_finding_is_dropped(json_case, monkeypatch):
    cases_dir, case_id, evidence_id, _events = json_case
    model = _ScriptedModel(evidence_id, cite=lambda slug: "EVT-EV-0001-999999")
    monkeypatch.setattr(ai_assistant, "call_model", model)

    result = _run(cases_dir, "--case", case_id)

    assert result.exit_code == 0, result.output
    assert "Findings (" not in result.output
    assert "unciteable" in result.output


def test_save_findings_records_open_findings_with_event_refs(json_case, monkeypatch):
    cases_dir, case_id, evidence_id, events = json_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))

    result = _run(cases_dir, "--case", case_id, "--save-findings", "--investigator", "alice")

    assert result.exit_code == 0, result.output
    saved = FindingManager(cases_dir / case_id).list()
    assert len(saved) == 1
    finding = saved[0]
    assert finding.status == "Open"  # proposed, never confirmed
    assert finding.severity == "High"
    assert finding.created_by == "alice"
    assert finding.evidence_refs == [{"evidence_id": evidence_id, "event_id": events[1].event_id}]
    assert "Proposed by the investigation team" in finding.assessment
    assert finding.finding_id in result.output


def test_roles_option_limits_the_team(json_case, monkeypatch):
    cases_dir, case_id, evidence_id, events = json_case
    model = _ScriptedModel(evidence_id, cite=lambda slug: None)
    monkeypatch.setattr(ai_assistant, "call_model", model)

    result = _run(cases_dir, "--case", case_id, "--roles", "host")

    assert result.exit_code == 0, result.output
    assert model.roles_called == ["host"]
    assert "No cited findings" in result.output


def test_unknown_role_is_an_error(json_case):
    cases_dir, case_id, _evidence_id, _events = json_case
    result = _run(cases_dir, "--case", case_id, "--roles", "network,wizard")
    assert result.exit_code == 1
    assert "unknown role" in result.output
    assert "network" in result.output


def test_host_role_is_skipped_without_host_evidence(tmp_path, monkeypatch):
    # A Suricata-only case: the Host analyst has nothing to read, so it must
    # not be sent to the provider at all.
    from netforensicai.agents.coordinator import scope_roles
    from netforensicai.agents.roles import all_roles

    to_run, skipped = scope_roles(all_roles(), {"suricata"})
    assert [r.slug for r in to_run] == ["network"]
    assert [r.slug for r in skipped] == ["host"]
    assert "skipped: no evtx/json/csv evidence" in skipped[0].note

    to_run, skipped = scope_roles(all_roles(), {"evtx"})
    assert [r.slug for r in to_run] == ["host"]


def test_explicit_roles_are_not_scoped_away(tmp_path, monkeypatch):
    from netforensicai.agents import investigate
    from netforensicai.agents.roles import HOST

    cases_dir, case_id, _evidence_id, _events = _add_json_case(tmp_path)
    called = []

    def call_for(role):
        called.append(role.slug)
        return lambda system_prompt, user_prompt: {"action": "findings", "findings": []}

    investigate(cases_dir / case_id, roles=[HOST], call_for=call_for)
    assert called == ["host"]


def test_every_role_failing_the_provider_exits_nonzero(json_case, monkeypatch):
    cases_dir, case_id, _evidence_id, _events = json_case

    def broken(*_args, **_kwargs):
        raise ai_assistant.AssistantError("No API key configured for anthropic")

    monkeypatch.setattr(ai_assistant, "call_model", broken)
    result = _run(cases_dir, "--case", case_id)

    assert result.exit_code == 1
    assert "provider failed" in result.output
    assert "every role failed" in result.output


def test_json_output(json_case, monkeypatch):
    cases_dir, case_id, evidence_id, events = json_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))

    result = _run(cases_dir, "--case", case_id, "--json")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [r["slug"] for r in payload["role_results"]] == ["network", "host"]
    assert payload["findings"][0]["reported_by"] == ["network", "host"]
    assert payload["saved_findings"] == []


def test_max_steps_is_applied_per_role(json_case, monkeypatch):
    cases_dir, case_id, _evidence_id, _events = json_case
    calls = []

    def always_tool(system_prompt, user_prompt, **_kwargs):
        calls.append(system_prompt[:40])
        return {"action": "tool", "tool": "search_events", "arguments": {}}

    monkeypatch.setattr(ai_assistant, "call_model", always_tool)
    result = _run(cases_dir, "--case", case_id, "--max-steps", "2", "--roles", "network")

    assert result.exit_code == 0, result.output
    assert len(calls) == 2
    assert "step budget" in result.output


def test_case_without_evidence_is_an_error(tmp_path):
    cases_dir = tmp_path / "cases"
    case = CaseManager(cases_dir).create(name="Empty", investigator="analyst")
    result = _run(cases_dir, "--case", case.case_id)
    assert result.exit_code == 1
    assert "no evidence" in result.output
