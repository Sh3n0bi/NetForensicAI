from datetime import datetime, timedelta, timezone

from netforensicai.core.entities import extract_and_store
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore
from netforensicai.core.timeline import (
    CONFIDENCE_OBSERVED,
    build_timeline,
    filter_timeline,
    save_timeline,
)

BASE = datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)


def _event(event_id, offset_minutes=0, **overrides):
    fields = dict(
        event_id=event_id,
        evidence_id="EV-0001",
        source="json",
        event_type="network_connection",
        timestamp=BASE + timedelta(minutes=offset_minutes),
    )
    fields.update(overrides)
    return Event(**fields)


def _seeded_store(tmp_path, events):
    store = CaseStore(tmp_path)
    store.replace_events_for_evidence("EV-0001", events)
    extract_and_store(store, events)
    return store


def test_build_timeline_includes_entity_references_and_observed_confidence(tmp_path):
    events = [_event("EVT-0001", user="alice", src_ip="10.0.0.5")]
    with _seeded_store(tmp_path, events) as store:
        entries = build_timeline(store)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.confidence == CONFIDENCE_OBSERVED
    assert entry.evidence_id == "EV-0001"
    assert entry.timestamp == BASE
    entity_types = {ref["entity_type"] for ref in entry.entity_references}
    assert "user" in entity_types
    assert "ip_address" in entity_types


def test_build_timeline_sorted_chronologically(tmp_path):
    events = [
        _event("EVT-0003", offset_minutes=20),
        _event("EVT-0001", offset_minutes=0),
        _event("EVT-0002", offset_minutes=10),
    ]
    with _seeded_store(tmp_path, events) as store:
        entries = build_timeline(store)

    assert [e.event_id for e in entries] == ["EVT-0001", "EVT-0002", "EVT-0003"]


def test_build_timeline_handles_missing_timestamp(tmp_path):
    events = [Event(event_id="EVT-0001", evidence_id="EV-0001", source="json", event_type="unknown")]
    with _seeded_store(tmp_path, events) as store:
        entries = build_timeline(store)

    assert entries[0].timestamp is None
    assert entries[0].entity_references == []


def test_filter_by_time_range():
    entries = build_timeline_from_events(
        [
            _event("EVT-0001", offset_minutes=0),
            _event("EVT-0002", offset_minutes=10),
            _event("EVT-0003", offset_minutes=20),
        ]
    )

    filtered = filter_timeline(entries, time_from=BASE + timedelta(minutes=5), time_to=BASE + timedelta(minutes=15))

    assert [e.event_id for e in filtered] == ["EVT-0002"]


def test_filter_by_user_matches_denormalized_field():
    entries = build_timeline_from_events([_event("EVT-0001", user="alice"), _event("EVT-0002", user="bob")])

    filtered = filter_timeline(entries, user="alice")

    assert [e.event_id for e in filtered] == ["EVT-0001"]


def test_filter_by_ip_matches_src_or_dst():
    entries = build_timeline_from_events(
        [
            _event("EVT-0001", src_ip="10.0.0.5"),
            _event("EVT-0002", dst_ip="10.0.0.5"),
            _event("EVT-0003", src_ip="10.0.0.6"),
        ]
    )

    filtered = filter_timeline(entries, ip="10.0.0.5")

    assert {e.event_id for e in filtered} == {"EVT-0001", "EVT-0002"}


def test_filter_by_event_type_case_insensitive():
    entries = build_timeline_from_events(
        [_event("EVT-0001", event_type="authentication"), _event("EVT-0002", event_type="dns_query")]
    )

    filtered = filter_timeline(entries, event_type="Authentication")

    assert [e.event_id for e in filtered] == ["EVT-0001"]


def test_filter_by_evidence_id():
    entries = build_timeline_from_events(
        [_event("EVT-0001", evidence_id="EV-0001"), _event("EVT-0002", evidence_id="EV-0002")]
    )

    filtered = filter_timeline(entries, evidence_id="EV-0002")

    assert [e.event_id for e in filtered] == ["EVT-0002"]


def test_filter_combines_multiple_criteria_with_and():
    entries = build_timeline_from_events(
        [
            _event("EVT-0001", user="alice", hostname="ws01"),
            _event("EVT-0002", user="alice", hostname="ws02"),
        ]
    )

    filtered = filter_timeline(entries, user="alice", hostname="ws02")

    assert [e.event_id for e in filtered] == ["EVT-0002"]


def test_filter_matches_via_entity_reference_when_field_not_denormalized():
    # file entity comes only from file_name; filtering by "file" should
    # still find it even though TimelineEntry.file_path is unset here.
    entries = build_timeline_from_events([_event("EVT-0001", file_name="payload.exe")])

    filtered = filter_timeline(entries, file="payload.exe")

    assert [e.event_id for e in filtered] == ["EVT-0001"]


def test_save_timeline_writes_json_snapshot(tmp_path):
    events = [_event("EVT-0001", user="alice")]
    with _seeded_store(tmp_path, events) as store:
        entries = build_timeline(store)

    output_path = save_timeline(entries, tmp_path)

    assert output_path == tmp_path / "timeline" / "timeline.json"
    assert output_path.exists()
    import json

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["event_id"] == "EVT-0001"
    assert data[0]["timestamp"] == BASE.isoformat()
    assert data[0]["confidence"] == CONFIDENCE_OBSERVED


def build_timeline_from_events(events):
    """Helper: seed a throwaway store and build its timeline, for filter
    tests that don't care about persistence details."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        with _seeded_store(tmp, events) as store:
            return build_timeline(store)
