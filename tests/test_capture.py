"""Tests for the live capture module.

Real network capture (AsyncSniffer actually opening an interface) is
always mocked or bypassed - this environment has no Npcap/libpcap driver,
and even where one exists, live capture needs privileges this test suite
should never require. Packet OBJECTS (not live capture) are built with
real scapy, same as test_parsers.py, and PcapWriter/rdpcap (file I/O, not
live capture) run for real - only the actual "open a network interface"
call is ever mocked.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from netforensicai.core.capture import (
    CaptureError,
    CaptureSession,
    _protocol_name,
    get_session,
    list_interfaces,
    start_capture,
    stop_capture,
)
from netforensicai.core.case import CaseManager


def _packet(layer):
    pkt = IP(src="10.0.0.5", dst="8.8.8.8") / layer
    pkt.time = time.time()
    return pkt


def _tcp_packet(payload=b"hello world"):
    return _packet(TCP(sport=1234, dport=80) / Raw(load=payload))


def _udp_packet():
    return _packet(UDP(sport=1234, dport=53))


def _icmp_packet():
    return _packet(ICMP())


def test_protocol_name_tcp():
    assert _protocol_name(_tcp_packet()) == "TCP"


def test_protocol_name_udp():
    assert _protocol_name(_udp_packet()) == "UDP"


def test_protocol_name_icmp():
    assert _protocol_name(_icmp_packet()) == "ICMP"


def test_protocol_name_unknown_defaults_to_other():
    assert _protocol_name(Ether()) == "other"


@pytest.fixture
def case_setup(tmp_path):
    case_manager = CaseManager(tmp_path / "cases")
    case = case_manager.create(name="Capture test case")
    case_dir = tmp_path / "cases" / case.case_id
    return case_manager, case, case_dir


def test_session_feeds_packets_and_tracks_window_stats(case_setup):
    case_manager, case, case_dir = case_setup
    session = CaptureSession(case.case_id, case_dir, case_manager, interface="fake0", rotate_seconds=3600)
    session._open_new_window()
    session._running = True

    session._on_packet(_tcp_packet())
    session._on_packet(_udp_packet())

    snap = session.snapshot()
    assert snap["window_packet_count"] == 2
    assert snap["total_packet_count"] == 2
    assert snap["window_protocols"]["TCP"] == 1
    assert snap["window_protocols"]["UDP"] == 1

    session._writer.close()


def test_ignores_packets_when_not_running(case_setup):
    case_manager, case, case_dir = case_setup
    session = CaptureSession(case.case_id, case_dir, case_manager, interface="fake0", rotate_seconds=3600)
    session._open_new_window()
    session._running = False

    session._on_packet(_tcp_packet())

    assert session.snapshot()["window_packet_count"] == 0
    session._writer.close()


def test_rotation_triggers_ingestion_and_produces_evidence(case_setup):
    case_manager, case, case_dir = case_setup
    session = CaptureSession(case.case_id, case_dir, case_manager, interface="fake0", rotate_seconds=0)
    session._open_new_window()
    session._running = True

    session._on_packet(_tcp_packet())  # rotate_seconds=0 -> rotates on the very first packet

    # Ingestion (evidence add -> parse -> correlate) runs on its own
    # background thread; poll on recent_events, which _record_event()
    # only appends to once that full pipeline has actually finished -
    # polling on case.evidence instead is a premature signal (it's
    # populated partway through, before parsing/correlation complete).
    deadline = time.time() + 5
    while time.time() < deadline and not session.recent_events:
        time.sleep(0.05)

    assert len(session.recent_events) == 1
    assert "error" not in session.recent_events[0]
    assert session.recent_events[0]["event_count"] >= 1

    reloaded = case_manager.load(case.case_id)
    assert len(reloaded.evidence) == 1

    session._writer.close()


def test_start_raises_if_already_running(case_setup):
    case_manager, case, case_dir = case_setup
    session = CaptureSession(case.case_id, case_dir, case_manager)
    session._running = True

    with pytest.raises(CaptureError, match="already running"):
        session.start()


def test_start_wraps_sniffer_failure_as_capture_error(case_setup):
    case_manager, case, case_dir = case_setup
    session = CaptureSession(case.case_id, case_dir, case_manager, interface="does-not-exist")

    with patch("scapy.all.AsyncSniffer") as mock_sniffer_cls:
        mock_sniffer_cls.return_value.start.side_effect = OSError("no such device")
        with pytest.raises(CaptureError, match="Failed to start capture"):
            session.start()


def test_start_stop_lifecycle_with_mocked_sniffer(case_setup):
    case_manager, case, case_dir = case_setup
    session = CaptureSession(case.case_id, case_dir, case_manager, interface="fake0", rotate_seconds=3600)

    with patch("scapy.all.AsyncSniffer") as mock_sniffer_cls:
        mock_instance = MagicMock()
        mock_sniffer_cls.return_value = mock_instance

        session.start()
        assert session.snapshot()["running"] is True
        mock_instance.start.assert_called_once()

        session.stop()
        assert session.snapshot()["running"] is False
        mock_instance.stop.assert_called_once()


def test_registry_start_stop_get(case_setup):
    case_manager, case, case_dir = case_setup

    with patch("scapy.all.AsyncSniffer") as mock_sniffer_cls:
        mock_sniffer_cls.return_value = MagicMock()

        session = start_capture(case.case_id, case_dir, case_manager, interface="fake0")
        assert get_session(case.case_id) is session

        with pytest.raises(CaptureError, match="already running"):
            start_capture(case.case_id, case_dir, case_manager, interface="fake0")

        stop_capture(case.case_id)
        assert get_session(case.case_id).snapshot()["running"] is False


def test_stop_unknown_case_raises():
    with pytest.raises(CaptureError, match="No capture session"):
        stop_capture("INC-9999-does-not-exist")


def test_list_interfaces_returns_a_list():
    assert isinstance(list_interfaces(), list)
