from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from netforensicai.core.event import COMMON_EVENT_TYPES, Event, generate_event_id


def _minimal_event(**overrides):
    fields = dict(
        event_id="EVT-EV-0001-000001",
        evidence_id="EV-0001",
        source="pcap",
        event_type="network_connection",
    )
    fields.update(overrides)
    return Event(**fields)


def test_minimal_event_requires_only_identity_fields():
    event = _minimal_event()

    assert event.event_id == "EVT-EV-0001-000001"
    assert event.timestamp is None
    assert event.src_ip is None
    assert event.message is None


def test_missing_required_field_raises():
    with pytest.raises(ValidationError):
        Event(evidence_id="EV-0001", source="pcap", event_type="network_connection")


@pytest.mark.parametrize("field", ["event_id", "evidence_id", "source", "event_type"])
def test_blank_required_field_raises(field):
    with pytest.raises(ValidationError):
        _minimal_event(**{field: "   "})


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        _minimal_event(made_up_field="oops")


def test_naive_timestamp_is_assumed_utc():
    naive = datetime(2026, 8, 27, 9, 0, 0)

    event = _minimal_event(timestamp=naive)

    assert event.timestamp.tzinfo == timezone.utc


def test_aware_timestamp_is_preserved():
    aware = datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)

    event = _minimal_event(timestamp=aware)

    assert event.timestamp == aware


def test_port_out_of_range_raises():
    with pytest.raises(ValidationError):
        _minimal_event(src_port=70000)


def test_negative_process_id_raises():
    with pytest.raises(ValidationError):
        _minimal_event(process_id=-1)


def test_full_event_round_trips_through_dict():
    event = _minimal_event(
        timestamp=datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc),
        user="alice",
        hostname="workstation01",
        src_ip="10.0.0.5",
        src_port=443,
        dst_ip="8.8.8.8",
        dst_port=53,
        protocol="udp",
        process_name="powershell.exe",
        process_id=1234,
        file_name="payload.exe",
        file_hash="deadbeef",
        domain="example.com",
        severity="high",
        message="Suspicious DNS query",
        raw_event_reference={"packet_number": 42},
    )

    restored = Event.model_validate(event.model_dump())

    assert restored == event


def test_generate_event_id_is_deterministic_and_traceable():
    assert generate_event_id("EV-0001", 1) == "EVT-EV-0001-000001"
    assert generate_event_id("EV-0001", 42) == "EVT-EV-0001-000042"


def test_common_event_types_are_plain_strings():
    assert all(isinstance(t, str) for t in COMMON_EVENT_TYPES)
    # Not enforced - an arbitrary event_type must still be accepted.
    _minimal_event(event_type="some_new_parser_specific_type")
