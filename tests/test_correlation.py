from datetime import datetime, timedelta, timezone

from netforensicai.core.correlation import (
    POSSIBLE_RELATIONSHIP,
    RELATED,
    correlate_case,
)
from netforensicai.core.entities import extract_and_store
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore

BASE = datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)


def _event(event_id, offset_seconds=0, **overrides):
    fields = dict(
        event_id=event_id,
        evidence_id="EV-0001",
        source="json",
        event_type="network_connection",
        timestamp=BASE + timedelta(seconds=offset_seconds),
    )
    fields.update(overrides)
    return Event(**fields)


def _seeded_store(tmp_path, events):
    store = CaseStore(tmp_path)
    store.replace_events_for_evidence("EV-0001", events)
    extract_and_store(store, events)
    return store


def test_shared_entity_within_window_is_related(tmp_path):
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        _event("EVT-0002", 30, src_ip="10.0.0.5"),
    ]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300)

    assert len(links) == 1
    link = links[0]
    assert link["relationship_type"] == RELATED
    assert link["shared_entity_type"] == "ip_address"
    assert link["shared_entity_value"] == "10.0.0.5"
    assert link["confidence"] == "medium"
    assert link["event_id_a"] == "EVT-0001"
    assert link["event_id_b"] == "EVT-0002"
    assert link["time_delta_seconds"] == 30


def test_no_shared_entity_within_window_is_possible_relationship(tmp_path):
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        _event("EVT-0002", 30, src_ip="10.0.0.6"),
    ]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300)

    assert len(links) == 1
    link = links[0]
    assert link["relationship_type"] == POSSIBLE_RELATIONSHIP
    assert link["shared_entity_id"] is None
    assert link["confidence"] == "low"


def test_events_outside_window_produce_no_link(tmp_path):
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        _event("EVT-0002", 9999, src_ip="10.0.0.5"),
    ]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300)

    assert links == []


def test_events_without_timestamp_are_excluded(tmp_path):
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        Event(event_id="EVT-0002", evidence_id="EV-0001", source="json", event_type="unknown", src_ip="10.0.0.5"),
    ]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300)

    assert links == []


def test_same_entity_far_apart_in_time_is_not_linked(tmp_path):
    # Same IP, but 10x outside the window - should NOT appear as a link at
    # all (not even possible_relationship): entity_events already answers
    # "same entity" queries; correlation_links is only for the time-window
    # cases.
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        _event("EVT-0002", 3000, src_ip="10.0.0.5"),
    ]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300)

    assert links == []


def test_correlate_case_is_idempotent_rebuild(tmp_path):
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        _event("EVT-0002", 30, src_ip="10.0.0.5"),
    ]
    with _seeded_store(tmp_path, events) as store:
        correlate_case(store, time_window_seconds=300)
        correlate_case(store, time_window_seconds=300)

        assert store.count_correlation_links() == 1


def test_links_persisted_and_queryable_via_store(tmp_path):
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        _event("EVT-0002", 30, src_ip="10.0.0.5"),
        _event("EVT-0003", 31, dst_ip="1.2.3.4"),
    ]
    with _seeded_store(tmp_path, events) as store:
        correlate_case(store, time_window_seconds=300)

        # EVT-0001 is within the window of both EVT-0002 (shared IP) and
        # EVT-0003 (no shared entity), so it appears in two links.
        for_evt1 = store.list_correlation_links(event_id="EVT-0001")
        assert len(for_evt1) == 2

        related_only = store.list_correlation_links(relationship_type=RELATED)
        assert len(related_only) == 1
        assert related_only[0]["event_id_a"] == "EVT-0001"


def test_three_pairwise_close_events_produce_three_links(tmp_path):
    events = [
        _event("EVT-0001", 0),
        _event("EVT-0002", 10),
        _event("EVT-0003", 20),
    ]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300)

    pairs = {(link["event_id_a"], link["event_id_b"]) for link in links}
    assert pairs == {
        ("EVT-0001", "EVT-0002"),
        ("EVT-0001", "EVT-0003"),
        ("EVT-0002", "EVT-0003"),
    }
    assert all(link["relationship_type"] == POSSIBLE_RELATIONSHIP for link in links)


def test_max_pairs_cap_limits_output(tmp_path):
    events = [_event(f"EVT-{i:04d}", offset_seconds=i) for i in range(20)]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300, max_pairs=5)

    assert len(links) == 5
