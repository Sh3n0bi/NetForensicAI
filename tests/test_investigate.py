from datetime import datetime, timedelta, timezone

from netforensicai.core.correlation import correlate_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.event import Event
from netforensicai.core.investigate import investigate_entity
from netforensicai.core.store import CaseStore

BASE = datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)


def _event(event_id, offset_minutes=0, evidence_id="EV-0001", **overrides):
    fields = dict(
        event_id=event_id,
        evidence_id=evidence_id,
        source="json",
        event_type="network_connection",
        timestamp=BASE + timedelta(minutes=offset_minutes),
    )
    fields.update(overrides)
    return Event(**fields)


def _seeded_store(tmp_path, events_by_evidence):
    store = CaseStore(tmp_path)
    all_events = []
    for evidence_id, events in events_by_evidence.items():
        store.replace_events_for_evidence(evidence_id, events)
        all_events.extend(events)
    extract_and_store(store, all_events)
    correlate_case(store)
    return store


def test_investigate_unknown_entity_returns_none(tmp_path):
    with CaseStore(tmp_path) as store:
        result = investigate_entity(store, "ip_address", "10.0.0.5")

    assert result is None


def test_investigate_returns_entity_info(tmp_path):
    events = {"EV-0001": [_event("EVT-0001", user="alice", src_ip="10.0.0.5")]}
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "ip_address", "10.0.0.5")

    assert result is not None
    assert result.entity["entity_type"] == "ip_address"
    assert result.entity["value"] == "10.0.0.5"
    assert len(result.events) == 1
    assert result.evidence_ids == ["EV-0001"]


def test_investigate_timeline_scoped_to_entitys_events_only(tmp_path):
    events = {
        "EV-0001": [
            _event("EVT-0001", offset_minutes=0, src_ip="10.0.0.5"),
            _event("EVT-0002", offset_minutes=5, src_ip="10.0.0.9"),  # unrelated IP
        ]
    }
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "ip_address", "10.0.0.5")

    assert [e.event_id for e in result.timeline_entries] == ["EVT-0001"]


def test_investigate_related_entities_ranked_by_shared_events(tmp_path):
    events = {
        "EV-0001": [
            _event("EVT-0001", offset_minutes=0, user="alice", hostname="ws01"),
            _event("EVT-0002", offset_minutes=1, user="alice", hostname="ws01"),
            _event("EVT-0003", offset_minutes=2, user="alice", hostname="ws02"),
        ]
    }
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "user", "alice")

    hostnames = [r for r in result.related_entities if r["entity_type"] == "hostname"]
    assert hostnames[0]["value"] == "ws01"
    assert hostnames[0]["shared_event_count"] == 2
    assert hostnames[1]["value"] == "ws02"
    assert hostnames[1]["shared_event_count"] == 1


def test_investigate_evidence_across_multiple_sources_generates_lead(tmp_path):
    events = {
        "EV-0001": [_event("EVT-0001", evidence_id="EV-0001", src_ip="10.0.0.5")],
        "EV-0002": [_event("EVT-0002", evidence_id="EV-0002", src_ip="10.0.0.5")],
    }
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "ip_address", "10.0.0.5")

    assert result.evidence_ids == ["EV-0001", "EV-0002"]
    assert any("separate evidence" in lead for lead in result.leads)


def test_investigate_ip_address_gets_threat_intel_lead(tmp_path):
    events = {"EV-0001": [_event("EVT-0001", src_ip="10.0.0.5")]}
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "ip_address", "10.0.0.5")

    assert any("VirusTotal" in lead for lead in result.leads)


def test_investigate_hash_gets_threat_intel_lead(tmp_path):
    events = {"EV-0001": [_event("EVT-0001", file_hash="deadbeef")]}
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "hash", "deadbeef")

    assert any("VirusTotal" in lead for lead in result.leads)


def test_investigate_isolated_entity_gets_fallback_lead(tmp_path):
    events = {"EV-0001": [_event("EVT-0001", hostname="lonely-host")]}
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "hostname", "lonely-host")

    assert any("No additional automated leads" in lead for lead in result.leads)


def test_investigate_correlation_links_included(tmp_path):
    events = {
        "EV-0001": [
            _event("EVT-0001", offset_minutes=0, user="alice", src_ip="10.0.0.5"),
            _event("EVT-0002", offset_minutes=1, user="alice", src_ip="10.0.0.9"),
        ]
    }
    with _seeded_store(tmp_path, events) as store:
        result = investigate_entity(store, "user", "alice")

    assert len(result.correlation_links) == 1
    assert result.correlation_links[0]["relationship_type"] == "related"
    assert any("event pair" in lead for lead in result.leads)
