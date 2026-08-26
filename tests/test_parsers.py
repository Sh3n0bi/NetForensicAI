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


# --- JSON / CSV normalization ---

import csv as csv_module  # noqa: E402
import json  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

from netforensicai.parsers.generic import CsvParser, JsonParser, NormalizationError  # noqa: E402


def _write_json(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_csv(tmp_path, name, fieldnames, rows):
    path = tmp_path / name
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv_module.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_json_array_of_records_normalizes_each_into_an_event(tmp_path):
    data = [
        {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "alice", "src_ip": "10.0.0.5"},
        {"timestamp": "2026-08-27T09:05:00Z", "type": "process_start", "process": "powershell.exe", "pid": "1234"},
    ]
    path = _write_json(tmp_path, "events.json", data)

    events = JsonParser().parse(path, evidence_id="EV-0001")

    assert len(events) == 2
    assert events[0].event_type == "authentication"
    assert events[0].user == "alice"
    assert events[0].src_ip == "10.0.0.5"
    assert events[0].timestamp == datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)
    assert events[1].process_name == "powershell.exe"
    assert events[1].process_id == 1234
    assert events[0].evidence_id == "EV-0001"
    assert events[0].source == "json"
    assert events[0].raw_event_reference == {"record_index": 0}
    assert events[1].raw_event_reference == {"record_index": 1}


def test_json_wrapped_in_events_key(tmp_path):
    data = {"events": [{"type": "dns_query", "domain": "example.com"}]}
    path = _write_json(tmp_path, "wrapped.json", data)

    events = JsonParser().parse(path, evidence_id="EV-0002")

    assert len(events) == 1
    assert events[0].domain == "example.com"


def test_json_single_object_becomes_one_record(tmp_path):
    data = {"type": "anomaly", "message": "single record, no wrapper"}
    path = _write_json(tmp_path, "single.json", data)

    events = JsonParser().parse(path, evidence_id="EV-0003")

    assert len(events) == 1
    assert events[0].message == "single record, no wrapper"


def test_json_invalid_syntax_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(NormalizationError):
        JsonParser().parse(path, evidence_id="EV-0004")


def test_json_top_level_scalar_raises(tmp_path):
    path = _write_json(tmp_path, "scalar.json", 42)

    with pytest.raises(NormalizationError):
        JsonParser().parse(path, evidence_id="EV-0005")


def test_json_record_not_object_raises(tmp_path):
    path = _write_json(tmp_path, "badrecord.json", [{"type": "ok"}, "not an object"])

    with pytest.raises(NormalizationError):
        JsonParser().parse(path, evidence_id="EV-0006")


def test_json_empty_array_returns_no_events(tmp_path):
    path = _write_json(tmp_path, "empty.json", [])

    assert JsonParser().parse(path, evidence_id="EV-0007") == []


def test_csv_rows_normalize_into_events(tmp_path):
    path = _write_csv(
        tmp_path,
        "events.csv",
        ["timestamp", "event_type", "hostname", "dst_ip", "dst_port"],
        [
            {"timestamp": "1700000000", "event_type": "network_connection", "hostname": "ws01", "dst_ip": "8.8.8.8", "dst_port": "53"},
            {"timestamp": "1700000100", "event_type": "network_connection", "hostname": "ws02", "dst_ip": "1.1.1.1", "dst_port": "443"},
        ],
    )

    events = CsvParser().parse(path, evidence_id="EV-0008")

    assert len(events) == 2
    assert events[0].hostname == "ws01"
    assert events[0].dst_port == 53
    assert events[0].source == "csv"
    assert events[0].raw_event_reference == {"row_number": 1}
    assert events[1].raw_event_reference == {"row_number": 2}


def test_csv_missing_file_raises(tmp_path):
    with pytest.raises(NormalizationError):
        CsvParser().parse(tmp_path / "does_not_exist.csv", evidence_id="EV-0009")


def test_csv_empty_returns_no_events(tmp_path):
    path = _write_csv(tmp_path, "empty.csv", ["timestamp", "event_type"], [])

    assert CsvParser().parse(path, evidence_id="EV-0010") == []


def test_field_aliasing_is_case_insensitive_with_multiple_variants(tmp_path):
    data = [
        {"SourceIP": "10.0.0.9", "DestinationIP": "10.0.0.10", "Type": "network_connection"},
        {"srcip": "10.0.0.11", "dstip": "10.0.0.12", "type": "network_connection"},
    ]
    path = _write_json(tmp_path, "aliases.json", data)

    events = JsonParser().parse(path, evidence_id="EV-0011")

    assert events[0].src_ip == "10.0.0.9"
    assert events[0].dst_ip == "10.0.0.10"
    assert events[1].src_ip == "10.0.0.11"
    assert events[1].dst_ip == "10.0.0.12"


def test_record_without_event_type_defaults_to_unknown(tmp_path):
    path = _write_json(tmp_path, "notype.json", [{"message": "no type field here"}])

    events = JsonParser().parse(path, evidence_id="EV-0012")

    assert events[0].event_type == "unknown"


def test_epoch_seconds_and_milliseconds_both_parse(tmp_path):
    data = [
        {"type": "x", "timestamp": 1700000000},
        {"type": "x", "timestamp": 1700000000000},
    ]
    path = _write_json(tmp_path, "epoch.json", data)

    events = JsonParser().parse(path, evidence_id="EV-0013")

    assert events[0].timestamp == events[1].timestamp
    assert events[0].timestamp == datetime.fromtimestamp(1700000000, tz=timezone.utc)


def test_unparseable_timestamp_leaves_field_unset(tmp_path):
    path = _write_json(tmp_path, "badtime.json", [{"type": "x", "timestamp": "not-a-date"}])

    events = JsonParser().parse(path, evidence_id="EV-0014")

    assert events[0].timestamp is None


def test_invalid_port_and_pid_values_become_none(tmp_path):
    path = _write_json(tmp_path, "badport.json", [{"type": "x", "src_port": "not-a-number", "pid": "also-not-a-number"}])

    events = JsonParser().parse(path, evidence_id="EV-0015")

    assert events[0].src_port is None
    assert events[0].process_id is None


def test_record_cannot_override_generated_identity_fields(tmp_path):
    # event_id/evidence_id/source aren't in FIELD_ALIASES, so even a record
    # that includes those exact keys can't spoof or collide with the ids
    # this parser assigns itself.
    data = [{"event_id": "SPOOFED", "evidence_id": "SPOOFED", "source": "SPOOFED", "type": "x"}]
    path = _write_json(tmp_path, "spoof.json", data)

    events = JsonParser().parse(path, evidence_id="EV-0016")

    assert events[0].evidence_id == "EV-0016"
    assert events[0].source == "json"
    assert events[0].event_id.startswith("EVT-EV-0016-")


def test_json_and_csv_parsers_registered_in_base_registry():
    from netforensicai.parsers import base

    assert isinstance(base.get_parser("json"), JsonParser)
    assert isinstance(base.get_parser("csv"), CsvParser)
