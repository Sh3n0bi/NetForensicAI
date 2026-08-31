from datetime import datetime, timezone

from netforensicai.core.entities import extract_and_store, extract_entities, generate_entity_id
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore


def _event(event_id, **overrides):
    fields = dict(
        event_id=event_id,
        evidence_id="EV-0001",
        source="json",
        event_type="authentication",
        timestamp=datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc),
    )
    fields.update(overrides)
    return Event(**fields)


def test_generate_entity_id_is_deterministic():
    assert generate_entity_id("ip_address", "10.0.0.5") == generate_entity_id("ip_address", "10.0.0.5")


def test_generate_entity_id_is_case_and_whitespace_insensitive():
    assert generate_entity_id("user", "Alice") == generate_entity_id("user", " alice ")


def test_generate_entity_id_differs_by_type():
    assert generate_entity_id("user", "8.8.8.8") != generate_entity_id("ip_address", "8.8.8.8")


def test_extract_entities_pulls_expected_fields():
    event = _event(
        "EVT-0001",
        user="alice",
        hostname="workstation01",
        src_ip="10.0.0.5",
        src_port=51000,
        dst_ip="8.8.8.8",
        dst_port=443,
        process_name="powershell.exe",
        file_name="payload.exe",
        file_hash="deadbeef",
        domain="example.com",
    )

    found = extract_entities(event)
    by_type = {entity_type: value for _, entity_type, value, _ in found}

    assert by_type["user"] == "alice"
    assert by_type["hostname"] == "workstation01"
    assert by_type["process"] == "powershell.exe"
    assert by_type["file"] == "payload.exe"
    assert by_type["hash"] == "deadbeef"
    assert by_type["domain"] == "example.com"
    assert "network_connection" in by_type
    # The HOST PAIR, not the flow tuple. Including the ports made this
    # entity unique per flow, so it could never be shared between two
    # events - an entity that by construction correlates with nothing.
    assert by_type["network_connection"] == "10.0.0.5->8.8.8.8"

    # dst_port identifies a service and is indexed; src_port is ephemeral
    # and is not. Both remain fields on the event either way.
    ports = [v for _, t, v, _ in found if t == "port"]
    assert ports == ["443"]

    # ip_address appears twice (src_ip and dst_ip) - both extracted.
    ip_entries = [v for _, t, v, _ in found if t == "ip_address"]
    assert set(ip_entries) == {"10.0.0.5", "8.8.8.8"}


def test_extract_entities_skips_none_and_empty_fields():
    event = _event("EVT-0001")  # no user/ip/etc set

    found = extract_entities(event)

    assert found == []


def test_extract_entities_no_network_connection_without_both_ips():
    event = _event("EVT-0001", src_ip="10.0.0.5")  # dst_ip missing

    found = extract_entities(event)

    assert all(entity_type != "network_connection" for _, entity_type, _, _ in found)


def test_extract_and_store_persists_entities_and_links(tmp_path):
    events = [
        _event("EVT-0001", user="alice", src_ip="10.0.0.5"),
        _event("EVT-0002", user="alice", src_ip="10.0.0.6"),
    ]

    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        touched = extract_and_store(store, events)

        entities = store.list_entities()
        user_entities = [e for e in entities if e["entity_type"] == "user"]

        assert len(user_entities) == 1  # same "alice" across both events -> one entity
        assert touched == len(entities)

        alice_id = user_entities[0]["entity_id"]
        linked = store.events_for_entity(alice_id)
        assert {e.event_id for e in linked} == {"EVT-0001", "EVT-0002"}


def test_extract_and_store_is_idempotent_on_rerun(tmp_path):
    events = [_event("EVT-0001", user="alice")]

    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        extract_and_store(store, events)
        extract_and_store(store, events)

        entities = store.list_entities()
        assert len(entities) == 1
        assert len(store.events_for_entity(entities[0]["entity_id"])) == 1


def test_a_shared_port_is_not_treated_as_a_correlation(tmp_path):
    """A port is worth indexing but not worth correlating on.

    "Show me everything touching port 4444" is a good use of an entity;
    "these two events are related because both involved port 80" is not a
    relationship - on an HTTP capture it is true of nearly every pair.
    Measured before this rule, 38,782 of 50,000 links on a 3,000-packet
    capture were shared-port links, 29,333 of them port 80 alone.
    """
    from netforensicai.core.correlation import correlate_case
    from netforensicai.core.store import CaseStore

    events = [
        _event("EVT-0001", src_ip="10.0.0.5", dst_ip="93.184.216.34", dst_port=80),
        # Same service port, entirely different hosts - not a relationship.
        _event("EVT-0002", src_ip="172.16.0.9", dst_ip="203.0.113.7", dst_port=80),
    ]
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        extract_and_store(store, events)
        links = correlate_case(store, time_window_seconds=300, include_possible=False)

    assert links == [], "two events sharing only a port must not be `related`"


def test_two_events_between_the_same_hosts_still_correlate(tmp_path):
    """The other half of the same change: keying the connection entity on
    the host pair is what makes it shareable at all."""
    from netforensicai.core.correlation import RELATED, correlate_case
    from netforensicai.core.store import CaseStore

    events = [
        _event("EVT-0001", src_ip="10.0.0.5", dst_ip="93.184.216.34", src_port=44001, dst_port=80),
        # A different flow - different source port - between the same pair.
        _event("EVT-0002", src_ip="10.0.0.5", dst_ip="93.184.216.34", src_port=44002, dst_port=80),
    ]
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        extract_and_store(store, events)
        links = correlate_case(store, time_window_seconds=300, include_possible=False)

    assert len(links) == 1
    assert links[0]["relationship_type"] == RELATED
    assert links[0]["shared_entity_type"] in ("ip_address", "network_connection")
