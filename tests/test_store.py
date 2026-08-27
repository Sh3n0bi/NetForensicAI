from datetime import datetime, timezone

from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore


def _event(event_id, evidence_id="EV-0001", **overrides):
    fields = dict(
        event_id=event_id,
        evidence_id=evidence_id,
        source="json",
        event_type="network_connection",
        timestamp=datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.5",
        src_port=443,
        dst_ip="8.8.8.8",
        dst_port=53,
        raw_event_reference={"record_index": 0},
    )
    fields.update(overrides)
    return Event(**fields)


def test_replace_events_for_evidence_stores_and_round_trips(tmp_path):
    with CaseStore(tmp_path) as store:
        events = [_event("EVT-0001"), _event("EVT-0002")]
        store.replace_events_for_evidence("EV-0001", events)

        stored = store.all_events()

        assert len(stored) == 2
        assert {e.event_id for e in stored} == {"EVT-0001", "EVT-0002"}
        first = next(e for e in stored if e.event_id == "EVT-0001")
        assert first.timestamp == datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)
        assert first.src_ip == "10.0.0.5"
        assert first.raw_event_reference == {"record_index": 0}


def test_replace_events_for_evidence_is_idempotent_across_reparse(tmp_path):
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001")])
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001-new")])

        stored = store.all_events()

        assert [e.event_id for e in stored] == ["EVT-0001-new"]


def test_events_scoped_to_different_evidence_are_independent(tmp_path):
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001", evidence_id="EV-0001")])
        store.replace_events_for_evidence("EV-0002", [_event("EVT-0002", evidence_id="EV-0002")])

        store.replace_events_for_evidence("EV-0001", [])  # re-parse produces nothing this time

        remaining = store.all_events()
        assert [e.event_id for e in remaining] == ["EVT-0002"]


def test_events_for_evidence_filters_correctly(tmp_path):
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001", evidence_id="EV-0001")])
        store.replace_events_for_evidence("EV-0002", [_event("EVT-0002", evidence_id="EV-0002")])

        assert [e.event_id for e in store.events_for_evidence("EV-0001")] == ["EVT-0001"]
        assert store.count_events() == 2


def test_timestamps_are_returned_in_utc_regardless_of_host_timezone(tmp_path):
    # DuckDB's TIMESTAMPTZ defaults to converting to the host machine's local
    # timezone on read; the store pins the session to UTC so this holds no
    # matter which machine opens the case.
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001")])

        stored = store.all_events()[0]

        assert stored.timestamp.utcoffset().total_seconds() == 0


def test_event_with_null_fields_round_trips(tmp_path):
    with CaseStore(tmp_path) as store:
        event = Event(
            event_id="EVT-0001",
            evidence_id="EV-0001",
            source="json",
            event_type="unknown",
        )
        store.replace_events_for_evidence("EV-0001", [event])

        stored = store.all_events()[0]

        assert stored.timestamp is None
        assert stored.src_ip is None
        assert stored.raw_event_reference is None


def test_upsert_entity_and_link_event(tmp_path):
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001")])
        store.upsert_entity("ENT-ip_address-abc", "ip_address", "10.0.0.5")
        store.link_entity_event("ENT-ip_address-abc", "EVT-0001", "src_ip")

        entities = store.list_entities()
        assert len(entities) == 1
        assert entities[0]["value"] == "10.0.0.5"

        linked_events = store.events_for_entity("ENT-ip_address-abc")
        assert [e.event_id for e in linked_events] == ["EVT-0001"]
        assert store.count_entities() == 1


def test_upsert_entity_is_idempotent(tmp_path):
    with CaseStore(tmp_path) as store:
        store.upsert_entity("ENT-1", "ip_address", "10.0.0.5")
        store.upsert_entity("ENT-1", "ip_address", "10.0.0.5")

        assert store.count_entities() == 1


def test_link_entity_event_does_not_duplicate(tmp_path):
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001")])
        store.upsert_entity("ENT-1", "ip_address", "10.0.0.5")
        store.link_entity_event("ENT-1", "EVT-0001", "src_ip")
        store.link_entity_event("ENT-1", "EVT-0001", "src_ip")

        assert len(store.events_for_entity("ENT-1")) == 1


def test_replace_events_cleans_up_entity_links(tmp_path):
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001")])
        store.upsert_entity("ENT-1", "ip_address", "10.0.0.5")
        store.link_entity_event("ENT-1", "EVT-0001", "src_ip")

        store.replace_events_for_evidence("EV-0001", [])

        assert store.events_for_entity("ENT-1") == []


def test_list_entities_filters_by_type(tmp_path):
    with CaseStore(tmp_path) as store:
        store.upsert_entity("ENT-1", "ip_address", "10.0.0.5")
        store.upsert_entity("ENT-2", "user", "alice")

        ip_entities = store.list_entities(entity_type="ip_address")

        assert [e["entity_id"] for e in ip_entities] == ["ENT-1"]
