"""Tests for the specialist roles (netforensicai/agents/roles.py).

The runner itself is covered in test_agents.py; here we check the role table is
well formed, the registry helpers behave, and each role actually runs over a
seeded case (with a scripted model) and returns cited findings within its scope.
"""

import json

import pytest

from netforensicai.agents import ROLES, all_roles, get_role, resolve_roles, run_role
from netforensicai.agents.roles import HOST, NETWORK
from netforensicai.core.case import CaseManager
from netforensicai.core.chat import TOOL_SPECS
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.store import CaseStore


def _script(*responses):
    calls = []

    def call(system_prompt, user_prompt):
        calls.append((system_prompt, user_prompt))
        return responses[min(len(calls) - 1, len(responses) - 1)]

    call.calls = calls
    return call


@pytest.fixture
def case(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    created = manager.create(name="Roles case", investigator="analyst")
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


def test_the_two_phase2_roles_are_registered_in_order():
    assert [r.slug for r in all_roles()] == ["network", "host"]
    assert get_role("network") is NETWORK
    assert get_role("host") is HOST
    assert get_role("does-not-exist") is None


def test_every_role_only_scopes_real_tools():
    for role in all_roles():
        assert role.tools, f"{role.slug} has no tools"
        assert set(role.tools) <= set(TOOL_SPECS), f"{role.slug} scopes an unknown tool"


def test_the_host_role_is_scoped_tighter_than_network():
    # Host analysis is over normalized events; it should not reach for the
    # packet-level capture tools the network role needs.
    assert "follow_stream" in NETWORK.tools
    assert "follow_stream" not in HOST.tools
    assert "search_packets" not in HOST.tools


def test_resolve_roles_selects_and_validates():
    assert resolve_roles() == all_roles()
    assert [r.slug for r in resolve_roles(["host"])] == ["host"]
    with pytest.raises(KeyError):
        resolve_roles(["network", "nope"])


def test_network_role_runs_and_reports_a_cited_finding(case):
    case_dir, evidence, events = case
    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {"event_type": "network_connection"}},
        {
            "action": "findings",
            "findings": [
                {
                    "title": "Outbound connection to port 4444",
                    "severity": "High",
                    "confidence": "medium",
                    "assessment": "A connection to 203.0.113.7:4444 may indicate command-and-control.",
                    "citations": [{"kind": "event", "evidence_id": evidence.evidence_id, "reference": events[1].event_id}],
                }
            ],
        },
    )
    result = run_role(NETWORK, case_dir, call=call)
    assert result.slug == "network"
    assert len(result.findings) == 1
    assert result.findings[0].citations[0].reference == events[1].event_id
    # The role's mission text reached the model (scoping the prompt).
    assert "Network Forensics" in call.calls[0][0]


def test_host_role_runs_over_the_same_case(case):
    case_dir, evidence, events = case
    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {"event_type": "authentication"}},
        {
            "action": "findings",
            "findings": [
                {
                    "title": "Interactive logon by jdoe",
                    "severity": "Info",
                    "confidence": "low",
                    "assessment": "An authentication event for jdoe was recorded.",
                    "citations": [{"kind": "event", "evidence_id": evidence.evidence_id, "reference": events[0].event_id}],
                }
            ],
        },
    )
    result = run_role(HOST, case_dir, call=call)
    assert result.slug == "host"
    assert len(result.findings) == 1
    assert "Host & Endpoint" in call.calls[0][0]
