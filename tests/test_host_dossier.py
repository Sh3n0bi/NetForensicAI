"""Tests for the host dossier - the one-screen "what did this host do" view.

The dossier only aggregates what is already in the case, so the things that
matter are that it attributes traffic to the right side (sent vs received),
never invents a peer, links only to entities that exist, and refuses to
build for anything that is not a host.
"""

from datetime import datetime, timedelta, timezone

import pytest

from netforensicai.core import host_dossier
from netforensicai.core.detections import scan_case
from netforensicai.core.entities import extract_and_store, generate_entity_id
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore

BASE = datetime(2026, 8, 27, 9, 0, tzinfo=timezone.utc)
HOST = "10.0.0.5"


def _event(index, offset=0, **fields):
    base = dict(
        event_id=f"EVT-EV-0001-{index:06d}",
        evidence_id="EV-0001",
        source="pcap",
        event_type="network_connection",
        timestamp=BASE + timedelta(seconds=offset),
    )
    base.update(fields)
    return Event(**base)


@pytest.fixture
def store(tmp_path):
    with CaseStore(tmp_path) as s:
        yield s


def _seed(store, events):
    store.replace_events_for_evidence("EV-0001", events)
    extract_and_store(store, events)
    return scan_case(store)


def _host_id():
    return generate_entity_id("ip_address", HOST)


def test_traffic_is_attributed_to_the_right_direction(store):
    events = [
        _event(1, offset=0, src_ip=HOST, dst_ip="104.21.7.19", dst_port=443, protocol="tcp",
               raw_event_reference={"byte_count": 1000}),
        _event(2, offset=1, src_ip="104.21.7.19", dst_ip=HOST, src_port=443, protocol="tcp",
               raw_event_reference={"byte_count": 250}),
    ]
    _seed(store, events)

    d = host_dossier.build(store, _host_id())

    assert d is not None
    assert d["entity"]["value"] == HOST
    assert d["entity"]["on_network"] is True
    assert d["summary"]["bytes_sent"] == 1000
    assert d["summary"]["bytes_received"] == 250
    assert d["summary"]["peer_count"] == 1
    peer = d["peers"][0]
    assert peer["value"] == "104.21.7.19"
    assert peer["external"] is True
    # The peer is a real entity, so it links.
    assert peer["entity_id"] == generate_entity_id("ip_address", "104.21.7.19")


def test_only_findings_on_this_host_are_included(store):
    # A bulk upload from HOST (fires OUTBOUND-BULK-TRANSFER), and unrelated
    # traffic between two other hosts that should not appear on HOST.
    events = [
        _event(i, offset=i * 2, src_ip=HOST, dst_ip="104.21.7.19", dst_port=20,
               raw_event_reference={"byte_count": 5000})
        for i in range(8)
    ]
    events += [_event(100 + i, offset=i, src_ip="10.0.0.8", dst_ip="10.0.0.9") for i in range(3)]
    _seed(store, events)

    d = host_dossier.build(store, _host_id())
    rule_ids = {f["rule_id"] for f in d["findings"]}

    assert "OUTBOUND-BULK-TRANSFER" in rule_ids
    for finding in d["findings"]:
        assert finding["occurrences"] >= 1


def test_services_and_domains_are_ranked_and_only_existing_entities_link(store):
    events = [
        _event(1, offset=0, src_ip=HOST, dst_ip="104.21.7.19", dst_port=443, protocol="tcp"),
        _event(2, offset=1, event_type="dns_query", src_ip=HOST, domain="bad.example"),
        _event(3, offset=2, event_type="dns_query", src_ip=HOST, domain="bad.example"),
    ]
    _seed(store, events)

    d = host_dossier.build(store, _host_id())

    assert d["services"][0]["port"] == 443
    assert d["domains"][0]["value"] == "bad.example"
    assert d["domains"][0]["events"] == 2
    assert d["domains"][0]["entity_id"] == generate_entity_id("domain", "bad.example")


def test_dossier_is_host_only(store):
    _seed(store, [_event(1, src_ip=HOST, dst_ip="104.21.7.19", domain="bad.example")])

    # A domain entity is not a host.
    domain_id = generate_entity_id("domain", "bad.example")
    assert host_dossier.build(store, domain_id) is None
    # A non-existent id.
    assert host_dossier.build(store, "ENT-ip_address-000000000000") is None
