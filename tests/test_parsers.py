"""Tests for the pcap parser, using synthetic pcap files built with scapy
so nothing here depends on tshark, a real capture, or sensitive data."""

import hashlib
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw, wrpcap

from netforensicai.parsers.pcap import PcapParseError, PcapParser


def _packet(src_ip, dst_ip, src_port, dst_port, payload, timestamp):
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / Raw(load=payload)
    pkt.time = timestamp
    return pkt


def _write_pcap(tmp_path, name, packets):
    path = tmp_path / name
    wrpcap(str(path), packets)
    return path


def test_network_connection_events_from_tcp_payload(tmp_path):
    packets = [
        _packet("10.0.0.5", "8.8.8.8", 55123, 80, b"GET / HTTP/1.1\r\n", 1_700_000_000.0),
        _packet("8.8.8.8", "10.0.0.5", 80, 55123, b"HTTP/1.1 200 OK\r\n", 1_700_000_000.5),
    ]
    pcap_path = _write_pcap(tmp_path, "http.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0001")

    connections = [e for e in events if e.event_type == "network_connection"]
    assert len(connections) == 2
    first = connections[0]
    assert first.evidence_id == "EV-0001"
    assert first.source == "pcap"
    assert first.src_ip == "10.0.0.5"
    assert first.src_port == 55123
    assert first.dst_ip == "8.8.8.8"
    assert first.dst_port == 80
    assert first.protocol == "tcp"
    assert first.message.startswith("GET / HTTP/1.1")
    assert first.raw_event_reference == {"packet_number": 1}
    assert first.timestamp is not None


def test_file_transfer_event_detects_embedded_signature_and_hashes_content(tmp_path):
    file_bytes = b"%PDF-1.4 fake pdf body for testing purposes only"
    packets = [_packet("10.0.0.5", "203.0.113.9", 51000, 443, file_bytes, 1_700_000_100.0)]
    pcap_path = _write_pcap(tmp_path, "download.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0002")

    file_events = [e for e in events if e.event_type == "file_transfer"]
    assert len(file_events) == 1
    event = file_events[0]
    assert event.file_name.endswith(".pdf")
    assert event.file_hash == hashlib.sha256(file_bytes).hexdigest()
    assert event.src_ip == "10.0.0.5"
    assert event.dst_ip == "203.0.113.9"
    assert event.file_path is None  # no output_dir requested


def test_file_transfer_event_saves_file_when_output_dir_given(tmp_path):
    file_bytes = b"PK\x03\x04fake zip body"
    packets = [_packet("10.0.0.5", "203.0.113.9", 51000, 443, file_bytes, 1_700_000_200.0)]
    pcap_path = _write_pcap(tmp_path, "zip.pcap", packets)
    output_dir = tmp_path / "extracted"

    events = PcapParser().parse(pcap_path, evidence_id="EV-0003", output_dir=output_dir)

    file_event = next(e for e in events if e.event_type == "file_transfer")
    saved_path = Path(file_event.file_path)
    assert saved_path.exists()
    assert saved_path.read_bytes() == file_bytes


def test_reassembles_file_split_across_multiple_packets(tmp_path):
    payload = b"%PDF-" + b"A" * 2000
    packets = [
        _packet("10.0.0.5", "203.0.113.9", 51000, 443, payload[:10], 1_700_000_300.0),
        _packet("10.0.0.5", "203.0.113.9", 51000, 443, payload[10:], 1_700_000_300.2),
    ]
    pcap_path = _write_pcap(tmp_path, "split.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0004")

    file_event = next(e for e in events if e.event_type == "file_transfer")
    assert file_event.file_hash == hashlib.sha256(payload).hexdigest()
    assert file_event.raw_event_reference["packet_numbers"] == [1, 2]


def test_non_matching_stream_produces_no_file_transfer_event(tmp_path):
    packets = [_packet("10.0.0.5", "8.8.8.8", 51000, 80, b"just plain text, not a file", 1_700_000_400.0)]
    pcap_path = _write_pcap(tmp_path, "plain.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0005")

    assert [e for e in events if e.event_type == "file_transfer"] == []


def test_anomaly_detection_flags_outlier_packet(tmp_path):
    base_time = 1_700_001_000.0
    packets = [
        _packet("10.0.0.5", "10.0.0.6", 5000, 6000, b"x" * 40, base_time + i * 0.1) for i in range(30)
    ]
    # Clear outlier: huge payload, unusual destination/port, far separated in time.
    packets.append(_packet("10.0.0.5", "203.0.113.50", 5000, 61234, b"y" * 5000, base_time + 500))
    pcap_path = _write_pcap(tmp_path, "anomaly.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0006")

    anomalies = [e for e in events if e.event_type == "anomaly"]
    flagged_packet_numbers = {e.raw_event_reference["packet_number"] for e in anomalies}
    assert 31 in flagged_packet_numbers
    for event in anomalies:
        assert event.severity == "medium"
        assert "size" in event.raw_event_reference
        assert "inter_arrival" in event.raw_event_reference


def test_events_all_reference_given_evidence_id_with_unique_ids(tmp_path):
    packets = [_packet("10.0.0.5", "8.8.8.8", 1234, 80, b"data", 1_700_002_000.0)]
    pcap_path = _write_pcap(tmp_path, "ids.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0007")

    assert all(e.evidence_id == "EV-0007" for e in events)
    assert len(events) == len({e.event_id for e in events})


def test_parse_missing_file_raises():
    with pytest.raises(PcapParseError):
        PcapParser().parse("does/not/exist.pcap", evidence_id="EV-0001")


def test_pcap_parser_is_registered_in_base_registry():
    from netforensicai.parsers import base

    assert isinstance(base.get_parser("pcap"), PcapParser)
