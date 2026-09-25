"""Tests for the agent foundation (netforensicai/agents/base.py).

No provider is ever called: run_role takes an injectable `call`, so each test
scripts exact model behaviour - including the case that matters most, a role
that cites evidence no tool returned, which must be dropped.
"""

import json

import pytest

from netforensicai.agents import AgentError, Role, run_role
from netforensicai.core.case import CaseManager
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.store import CaseStore


def _script(*responses):
    calls = []

    def call(system_prompt, user_prompt):
        calls.append(user_prompt)
        return responses[min(len(calls) - 1, len(responses) - 1)]

    call.prompts = calls
    return call


@pytest.fixture
def case(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    created = manager.create(name="Agent case", investigator="analyst")
    case_dir = cases_dir / created.case_id

    source = tmp_path / "events.json"
    source.write_text(
        json.dumps(
            [
                {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe", "src_ip": "192.168.1.10"},
                {"timestamp": "2026-08-27T09:00:30Z", "type": "network_connection", "src_ip": "192.168.1.10", "dst_ip": "203.0.113.7", "dst_port": 4444},
            ]
        ),
        encoding="utf-8",
    )
    evidence = EvidenceManager(case_dir).add(source, case_id=created.case_id)
    manager.register_evidence(created.case_id, evidence.evidence_id)
    from netforensicai.parsers.generic import JsonParser

    events = JsonParser().parse(EvidenceManager(case_dir).stored_file_path(evidence.evidence_id), evidence_id=evidence.evidence_id)
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence(evidence.evidence_id, events)
        extract_and_store(store, events)
    return case_dir, evidence, events


NET_ROLE = Role(
    name="Network Forensics",
    slug="network",
    mission="Network flows, DNS, TLS and exfil.",
    tools=("search_events", "list_entities"),
)


def _finding(event_id, evidence_id, title="Outbound to a suspicious port"):
    return {
        "title": title,
        "severity": "High",
        "confidence": "medium",
        "assessment": "A connection to port 4444 may indicate C2.",
        "citations": [{"kind": "event", "evidence_id": evidence_id, "reference": event_id}],
    }


def test_a_role_reports_findings_cited_from_retrieved_events(case):
    case_dir, evidence, events = case
    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {"event_type": "network_connection"}},
        {"action": "findings", "findings": [_finding(events[1].event_id, evidence.evidence_id)]},
    )
    result = run_role(NET_ROLE, case_dir, call=call)
    assert result.slug == "network"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "High"
    assert result.findings[0].citations[0].reference == events[1].event_id


def test_a_finding_citing_unretrieved_evidence_is_dropped(case):
    case_dir, evidence, events = case
    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {"event_type": "network_connection"}},
        {"action": "findings", "findings": [_finding("EVT-9999", evidence.evidence_id)]},
    )
    result = run_role(NET_ROLE, case_dir, call=call)
    assert result.findings == []
    assert "dropped" in (result.note or "")


def test_a_finding_with_no_citations_is_dropped(case):
    case_dir, evidence, events = case
    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {}},
        {"action": "findings", "findings": [{"title": "Vibes", "assessment": "It feels bad.", "citations": []}]},
    )
    result = run_role(NET_ROLE, case_dir, call=call)
    assert result.findings == []


def test_empty_findings_is_a_valid_result(case):
    case_dir, _evidence, _events = case
    call = _script({"action": "findings", "findings": []})
    result = run_role(NET_ROLE, case_dir, call=call)
    assert result.findings == []
    assert result.note == "no findings in scope"


def test_out_of_scope_tool_is_refused_and_not_run(case):
    case_dir, evidence, events = case
    # follow_stream is not in NET_ROLE.tools; the loop must refuse it, then the
    # role reports from what it could retrieve.
    call = _script(
        {"action": "tool", "tool": "follow_stream", "arguments": {"stream": 0}},
        {"action": "tool", "tool": "search_events", "arguments": {"event_type": "network_connection"}},
        {"action": "findings", "findings": [_finding(events[1].event_id, evidence.evidence_id)]},
    )
    result = run_role(NET_ROLE, case_dir, call=call)
    assert [c["tool"] for c in result.tool_calls] == ["search_events"]  # follow_stream never ran
    assert len(result.findings) == 1


def test_provider_failure_returns_a_note_not_a_crash(case):
    case_dir, _evidence, _events = case

    def boom(system_prompt, user_prompt):
        raise RuntimeError("provider exploded")

    result = run_role(NET_ROLE, case_dir, call=boom)
    assert result.findings == []
    assert "provider failed" in (result.note or "")


def test_a_role_with_an_unknown_tool_is_rejected():
    with pytest.raises(AgentError):
        Role(name="Bad", slug="bad", mission="x", tools=("search_events", "not_a_tool"))
