"""Tests for the case narrative and the network detection rules.

The narrative is the one output an investigator reads before anything
else, so what it must never do matters more than what it does: invent a
fact, overstate what the evidence carries, or bury the story under
repetition.
"""

from datetime import datetime, timedelta, timezone

import pytest

from netforensicai.core import narrative as narrative_module
from netforensicai.core.detections import scan_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore

BASE = datetime(2026, 8, 27, 9, 0, tzinfo=timezone.utc)


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


# --- detection rules ----------------------------------------------------


def test_a_cleartext_credential_is_detected_from_the_derived_event(store):
    """Normalized events carry no payload, so this rule can only work off
    the parser's credential_exposure event - which holds a hash of the
    secret, never the secret."""
    events = [
        _event(1, event_type="credential_exposure", user="svc_backup",
               src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=80,
               raw_event_reference={"field": "password", "protocol": "HTTP", "secret_sha256": "a" * 64}),
    ]
    rules = {d["rule_id"] for d in _seed(store, events)}

    assert "CLEARTEXT-CREDENTIALS" in rules


def test_the_same_credential_on_two_protocols_is_reported_as_reuse(store):
    """The join that no single-event rule can make."""
    digest = "b" * 64
    events = [
        _event(1, 0, event_type="credential_exposure", src_ip="10.0.0.5", dst_ip="45.33.32.156",
               dst_port=80, raw_event_reference={"protocol": "HTTP", "secret_sha256": digest}),
        _event(2, 60, event_type="credential_exposure", src_ip="10.0.0.5", dst_ip="104.21.7.19",
               dst_port=21, raw_event_reference={"protocol": "FTP", "secret_sha256": digest}),
    ]
    rules = {d["rule_id"] for d in _seed(store, events)}

    assert "CREDENTIAL-REUSE" in rules


def test_two_different_credentials_are_not_reuse(store):
    events = [
        _event(1, 0, event_type="credential_exposure", src_ip="10.0.0.5", dst_ip="45.33.32.156",
               dst_port=80, raw_event_reference={"protocol": "HTTP", "secret_sha256": "c" * 64}),
        _event(2, 60, event_type="credential_exposure", src_ip="10.0.0.5", dst_ip="104.21.7.19",
               dst_port=21, raw_event_reference={"protocol": "FTP", "secret_sha256": "d" * 64}),
    ]
    rules = {d["rule_id"] for d in _seed(store, events)}

    assert "CREDENTIAL-REUSE" not in rules


def test_an_executable_over_https_is_not_flagged(store):
    """What makes a download a finding is the cleartext, not the file
    type. Flagging every .exe would train people to ignore the rule."""
    plain = [_event(1, url="http://bad.example/setup.exe", dst_port=80, event_type="http_request")]
    secure = [_event(1, url="https://vendor.example/setup.exe", dst_port=443, event_type="http_request")]

    assert "EXECUTABLE-DOWNLOAD" in {d["rule_id"] for d in _seed(store, plain)}
    assert "EXECUTABLE-DOWNLOAD" not in {d["rule_id"] for d in _seed(store, secure)}


def test_a_burst_of_connections_is_not_a_beacon(store):
    """Flows a fraction of a second apart are one burst. Calling a 0s
    interval "near-constant" is how a rule earns distrust."""
    events = [
        _event(i, offset=0, src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=443,
               raw_event_reference={"byte_count": 100})
        for i in range(8)
    ]
    rules = {d["rule_id"] for d in _seed(store, events)}

    assert "PERIODIC-BEACON" not in rules


def test_regular_low_volume_contact_is_a_beacon(store):
    events = [
        _event(i, offset=i * 30, src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=443,
               raw_event_reference={"byte_count": 120})
        for i in range(8)
    ]
    rules = {d["rule_id"] for d in _seed(store, events)}

    assert "PERIODIC-BEACON" in rules


def test_an_internal_transfer_is_not_exfiltration(store):
    """Volume to another internal host is a file copy. Flagging it would
    bury the case that is not."""
    events = [
        _event(i, offset=i, src_ip="10.0.0.5", dst_ip="10.0.0.9",
               raw_event_reference={"byte_count": 50_000})
        for i in range(4)
    ]
    rules = {d["rule_id"] for d in _seed(store, events)}

    assert "OUTBOUND-BULK-TRANSFER" not in rules


def test_a_chunked_upload_is_not_also_reported_as_a_beacon(store):
    """One activity, one finding: a chunked upload is regular by nature,
    so it satisfies "periodic" too - but naming it twice sends an analyst
    chasing two leads to one place."""
    events = [
        _event(i, offset=i * 2, src_ip="10.0.0.5", dst_ip="104.21.7.19", dst_port=20,
               raw_event_reference={"byte_count": 1_500})
        for i in range(8)
    ]
    rules = {d["rule_id"] for d in _seed(store, events)}

    assert "OUTBOUND-BULK-TRANSFER" in rules
    assert "PERIODIC-BEACON" not in rules


# --- the narrative ------------------------------------------------------


def test_a_case_with_no_detections_says_so_rather_than_claiming_nothing_happened(store):
    _seed(store, [_event(1, src_ip="10.0.0.5", dst_ip="10.0.0.9")])

    narrative = narrative_module.build(store)

    assert narrative.severity == "none"
    assert "not the same as" in narrative.assessment
    assert narrative.phases == []


def test_repeated_matches_of_one_rule_become_a_single_beat(store):
    """Eight identical rows for one domain are one thing that happened.
    Listing them eight times is how a report becomes unreadable."""
    events = [
        _event(i, offset=i, event_type="dns_query", domain="bad.top", src_ip="10.0.0.5")
        for i in range(8)
    ]
    _seed(store, events)

    narrative = narrative_module.build(store)
    tld_beats = [b for b in narrative.beats if b.rule_id == "SUSPICIOUS-TLD"]

    assert len(tld_beats) == 1
    assert tld_beats[0].occurrences == 8


def test_beats_are_ordered_by_when_they_happened(store):
    events = [
        _event(1, offset=300, src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=80,
               event_type="http_request", url="http://bad.top/x.exe"),
        _event(2, offset=0, event_type="dns_query", domain="bad.top", src_ip="10.0.0.5"),
    ]
    _seed(store, events)

    narrative = narrative_module.build(store)
    stamped = [b.first_seen for b in narrative.beats if b.first_seen]

    assert stamped == sorted(stamped)


def test_beats_are_grouped_into_the_stages_of_an_intrusion(store):
    events = [
        _event(1, 0, event_type="dns_query", domain="bad.top", src_ip="10.0.0.5"),
        _event(2, 10, event_type="http_request", url="http://bad.top/x.exe", dst_port=80,
               src_ip="10.0.0.5", dst_ip="45.33.32.156"),
    ]
    _seed(store, events)

    phases = {key for key, _title, _beats in narrative_module.build(store).phases}

    assert "reconnaissance" in phases
    assert "delivery" in phases


def test_the_assessment_escalates_with_what_the_evidence_supports(store):
    """An assessment must rest on the phases actually present, not on a
    count of detections."""
    recon_only = [_event(1, event_type="dns_query", domain="bad.top", src_ip="10.0.0.5")]
    _seed(store, recon_only)
    assert narrative_module.build(store).severity == "low"

    with_exfil = recon_only + [
        _event(i + 10, offset=i, event_type="credential_exposure", src_ip="10.0.0.5",
               dst_ip="45.33.32.156", dst_port=80,
               raw_event_reference={"protocol": "HTTP", "secret_sha256": "e" * 64})
        for i in range(1)
    ] + [
        _event(i + 20, offset=i, src_ip="10.0.0.5", dst_ip="104.21.7.19",
               raw_event_reference={"byte_count": 30_000})
        for i in range(2)
    ]
    _seed(store, with_exfil)
    narrative = narrative_module.build(store)

    assert narrative.severity == "critical"
    assert "leaving this network" in narrative.assessment


def test_every_beat_carries_the_evidence_it_rests_on(store):
    """The whole point: a sentence in the summary must be walkable back
    to a packet."""
    events = [
        _event(1, event_type="http_request", url="http://bad.top/x.exe", dst_port=80,
               src_ip="10.0.0.5", dst_ip="45.33.32.156"),
    ]
    _seed(store, events)

    for beat in narrative_module.build(store).beats:
        assert beat.event_ids, beat.rule_id
        assert beat.evidence_ids == ["EV-0001"]


def test_the_headline_counts_rather_than_characterises(store):
    """"4 findings, 2 high" is checkable; "a serious compromise" is an
    opinion the evidence may not carry."""
    events = [
        _event(1, event_type="http_request", url="http://bad.top/x.exe", dst_port=80,
               src_ip="10.0.0.5", dst_ip="45.33.32.156"),
    ]
    _seed(store, events)

    headline = narrative_module.build(store).headline

    assert "finding" in headline
    assert "high severity" in headline


def test_render_text_is_readable_and_cites_events(store):
    events = [
        _event(1, event_type="http_request", url="http://bad.top/x.exe", dst_port=80,
               src_ip="10.0.0.5", dst_ip="45.33.32.156"),
    ]
    _seed(store, events)

    text = narrative_module.render_text(narrative_module.build(store))

    assert "Assessment [" in text
    assert "DELIVERY" in text
    assert "evidence: EVT-EV-0001-000001" in text
