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


def test_pair_finder_consumes_an_iterator_and_bounds_its_window():
    """Correlation must not need the whole event set in memory: it takes an
    iterator and retains only events still inside the time window. Feeding
    it a generator proves it never indexes or re-reads the sequence."""
    from netforensicai.core.correlation import _find_time_window_pairs

    # 400 events one second apart, with a 5s window: any given event can only
    # pair with a handful of neighbours, however long the sequence runs.
    def stream():
        for i in range(400):
            yield _event(f"EVT-{i:04d}", i)

    pairs = list(_find_time_window_pairs(stream(), window_seconds=5, max_scanned_pairs=10_000))

    assert pairs, "a generator input produced no pairs at all"
    # Every pair is genuinely within the window, and none spans the whole run.
    assert all(0 < delta <= 5 for _a, _b, delta in pairs)
    # 400 events x 5s window is ~5 partners each; an implementation that kept
    # everything would produce the full O(n^2) ~80,000 instead.
    assert len(pairs) < 2500


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


# --- Link budget: strong signal is never crowded out by weak -------------


def test_time_proximity_links_never_displace_shared_entity_links(tmp_path):
    """The failure this guards against was found running a live capture.

    On a dense source almost every pair inside the time window shares no
    entity, so a single undifferentiated budget gets spent almost entirely
    on `possible_relationship` - temporal proximity alone, explicitly weak
    - while the shared-entity links an investigation actually turns on are
    never reached.
    """
    # 40 events one second apart. Two of them share an IP and sit at the
    # very end, so a chronological budget would exhaust itself on the weak
    # pairs long before reaching them.
    events = [_event(f"EVT-{i:04d}", i) for i in range(38)]
    events.append(_event("EVT-0038", 38, src_ip="10.0.0.5"))
    events.append(_event("EVT-0039", 39, src_ip="10.0.0.5"))

    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300, max_pairs=20)

    assert len(links) == 20
    related = [link for link in links if link["relationship_type"] == RELATED]
    assert related, "the shared-entity link was crowded out by time-proximity noise"
    assert any(
        {link["event_id_a"], link["event_id_b"]} == {"EVT-0038", "EVT-0039"} for link in related
    )


def test_excluding_the_weak_tier_keeps_only_shared_entity_links(tmp_path):
    events = [
        _event("EVT-0001", 0, src_ip="10.0.0.5"),
        _event("EVT-0002", 10, src_ip="10.0.0.5"),
        _event("EVT-0003", 20, src_ip="192.168.1.1"),
    ]
    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300, include_possible=False)

    assert links
    assert {link["relationship_type"] for link in links} == {RELATED}


def test_no_single_entity_can_consume_the_link_budget(tmp_path):
    """Correlation is pairwise, so a high-degree entity produces links
    quadratically - a DNS resolver in three thousand events can fill the
    budget by itself. Measured before this cap, one address took 49,536 of
    50,000 links, leaving 100 for every domain in the case combined.
    """
    events = [_event(f"EVT-{i:04d}", i, src_ip="10.0.0.5") for i in range(30)]

    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300, max_pairs=100)

    # 30 events sharing one address is 435 candidate pairs; the ceiling is
    # a tenth of the budget, so that entity gets 10 and not 100.
    assert len(links) == 10
    assert all(link["relationship_type"] == RELATED for link in links)


def test_the_budget_is_shared_across_entities_rather_than_taken_by_one(tmp_path):
    """The point of the cap: a busy hub must leave room for everything
    else, so the result is a picture of the case rather than of its
    busiest node."""
    events = []
    # A hub: many events all sharing one address.
    for i in range(40):
        events.append(_event(f"EVT-hub-{i:04d}", i, src_ip="10.0.0.5"))
    # A quieter pair sharing a domain, late in the window.
    events.append(_event("EVT-dom-0001", 41, domain="evil.example.com"))
    events.append(_event("EVT-dom-0002", 42, domain="evil.example.com"))

    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300, max_pairs=50, include_possible=False)

    kinds = {link["shared_entity_type"] for link in links}
    assert "domain" in kinds, "the hub crowded out the only domain link"


def test_the_link_budget_is_never_exceeded(tmp_path):
    """A strong link displaces a weak one rather than being appended past
    the budget - otherwise the cap silently overshoots."""
    events = [_event(f"EVT-{i:04d}", i) for i in range(20)]
    events += [
        _event("EVT-0020", 20, src_ip="10.0.0.5"),
        _event("EVT-0021", 21, src_ip="10.0.0.5"),
    ]

    with _seeded_store(tmp_path, events) as store:
        links = correlate_case(store, time_window_seconds=300, max_pairs=15)

    assert len(links) <= 15


def test_pair_finder_offers_the_closest_predecessor_first():
    from netforensicai.core.correlation import _find_time_window_pairs

    events = [_event(f"EVT-{i:04d}", i) for i in range(5)]
    pairs = list(_find_time_window_pairs(iter(events), window_seconds=300))

    # For the last event, the first candidate offered must be its immediate
    # predecessor, not the oldest event in the window.
    for_last = [(a, b, d) for a, b, d in pairs if b.event_id == "EVT-0004"]
    assert for_last[0][0].event_id == "EVT-0003"
    assert for_last[0][2] < for_last[-1][2]
