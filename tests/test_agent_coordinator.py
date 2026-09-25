"""Tests for the coordinator (netforensicai/agents/coordinator.py).

The merge logic is tested directly with hand-built RoleResults, and the whole
investigate() flow with scripted per-role models over a seeded case.
"""

import json

import pytest

from netforensicai.agents import investigate, merge_findings
from netforensicai.agents.base import AgentFinding, RoleResult
from netforensicai.agents.roles import HOST, NETWORK
from netforensicai.core.case import CaseManager
from netforensicai.core.chat import Citation
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.store import CaseStore


def _cite(evidence_id, reference, kind="event"):
    return Citation(kind=kind, evidence_id=evidence_id, reference=reference)


def _finding(title, severity, citations, assessment="x", confidence="medium"):
    return AgentFinding(title=title, severity=severity, confidence=confidence, assessment=assessment, citations=citations)


def _result(slug, findings):
    return RoleResult(role=slug, slug=slug, findings=findings)


# --- merge_findings (unit) ---------------------------------------------------

def test_two_roles_flagging_the_same_event_merge_into_one_corroborated_finding():
    shared = [_cite("EV-0001", "EVT-0002")]
    results = [
        _result("network", [_finding("C2 beacon", "High", shared, assessment="looks like C2")]),
        _result("host", [_finding("Suspicious outbound", "Medium", shared, assessment="process X did it")]),
    ]
    merged = merge_findings(results)
    assert len(merged) == 1
    m = merged[0]
    assert m.severity == "High"  # strongest wins
    assert set(m.reported_by) == {"network", "host"}
    assert len(m.citations) == 1  # unioned, deduped
    assert "[network]" in m.assessment and "[host]" in m.assessment


def test_findings_on_different_evidence_stay_separate_and_rank_by_severity():
    results = [
        _result("network", [_finding("Low thing", "Low", [_cite("EV-0001", "EVT-0001")])]),
        _result("host", [_finding("Bad thing", "High", [_cite("EV-0001", "EVT-0009")])]),
    ]
    merged = merge_findings(results)
    assert [m.title for m in merged] == ["Bad thing", "Low thing"]  # severe first


def test_more_corroborated_finding_ranks_above_a_solo_one_of_equal_severity():
    shared = [_cite("EV-0001", "EVT-0002")]
    results = [
        _result("network", [_finding("Corroborated", "Medium", shared)]),
        _result("host", [_finding("Corroborated", "Medium", shared)]),
        _result("network", [_finding("Solo", "Medium", [_cite("EV-0001", "EVT-0005")])]),
    ]
    merged = merge_findings(results)
    assert merged[0].title == "Corroborated" and len(merged[0].reported_by) == 2
    assert merged[1].title == "Solo"


def test_no_findings_merges_to_nothing():
    assert merge_findings([_result("network", []), _result("host", [])]) == []


# --- investigate (integration with scripted models) --------------------------

@pytest.fixture
def case(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    created = manager.create(name="Team case", investigator="analyst")
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


def _scripted(responses):
    seq = {"i": 0}

    def call(system_prompt, user_prompt):
        r = responses[min(seq["i"], len(responses) - 1)]
        seq["i"] += 1
        return r
    return call


def test_investigate_runs_both_roles_and_merges_on_the_shared_event(case):
    case_dir, evidence, events = case
    net_event = events[1].event_id

    def call_for(role):
        # Both roles retrieve, then flag the same network_connection event.
        finding = {
            "action": "findings",
            "findings": [{
                "title": f"{role.slug} view of the outbound",
                "severity": "High" if role.slug == "network" else "Medium",
                "confidence": "medium",
                "assessment": f"{role.slug} assessment",
                "citations": [{"kind": "event", "evidence_id": evidence.evidence_id, "reference": net_event}],
            }],
        }
        return _scripted([
            {"action": "tool", "tool": "search_events", "arguments": {"event_type": "network_connection"}},
            finding,
        ])

    result = investigate(case_dir, roles=[NETWORK, HOST], call_for=call_for)
    assert [r.slug for r in result.role_results] == ["network", "host"]
    assert len(result.findings) == 1  # merged on the shared event
    assert set(result.findings[0].reported_by) == {"network", "host"}
    assert result.findings[0].severity == "High"
