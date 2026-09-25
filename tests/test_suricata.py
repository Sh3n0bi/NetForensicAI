"""Tests for the Suricata eve.json parser and its content-based detection.

The eve.json samples here are hand-written to the documented Suricata schema
(public, non-sensitive) - one line per event, JSON Lines.
"""

import json

from netforensicai.core.evidence import infer_evidence_type
from netforensicai.parsers.suricata import SuricataParser, is_suricata_eve

ALERT = {
    "timestamp": "2026-08-27T09:00:00.100000+0000", "flow_id": 1, "event_type": "alert",
    "src_ip": "10.0.0.5", "src_port": 44100, "dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP",
    "alert": {"signature": "ET MALWARE Suspicious download", "category": "A Network Trojan", "severity": 1},
}
DNS_Q = {
    "timestamp": "2026-08-27T09:00:01+0000", "event_type": "dns",
    "src_ip": "10.0.0.5", "dest_ip": "10.0.0.1", "proto": "UDP",
    "dns": {"type": "query", "rrname": "bad.example.com", "rrtype": "A"},
}
HTTP = {
    "timestamp": "2026-08-27T09:00:02+0000", "event_type": "http",
    "src_ip": "10.0.0.5", "src_port": 44102, "dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP",
    "http": {"hostname": "example.com", "url": "/malware.exe", "http_method": "GET", "status": 200},
}
TLS = {
    "timestamp": "2026-08-27T09:00:03+0000", "event_type": "tls",
    "src_ip": "10.0.0.5", "dest_ip": "45.33.32.156", "dest_port": 443, "proto": "TCP",
    "tls": {"sni": "secure.example.net", "version": "TLS 1.3"},
}
FILEINFO = {
    "timestamp": "2026-08-27T09:00:04+0000", "event_type": "fileinfo",
    "src_ip": "93.184.216.34", "dest_ip": "10.0.0.5", "proto": "TCP",
    "fileinfo": {"filename": "/malware.exe", "sha256": "a" * 64, "size": 512},
}
FLOW = {
    "timestamp": "2026-08-27T09:00:05+0000", "event_type": "flow",
    "src_ip": "10.0.0.5", "dest_ip": "45.33.32.156", "src_port": 5000, "dest_port": 4444, "proto": "TCP",
    "flow": {"pkts_toserver": 8, "bytes_toserver": 900},
}
STATS = {"timestamp": "2026-08-27T09:00:06+0000", "event_type": "stats", "stats": {"uptime": 60}}


def _write_eve(tmp_path, records, name="eve.json"):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def test_detects_suricata_eve(tmp_path):
    assert is_suricata_eve(_write_eve(tmp_path, [ALERT, DNS_Q]))


def test_rejects_plain_json_array(tmp_path):
    # A normal JSON-array log (what JsonParser handles) is not eve.json.
    path = tmp_path / "log.json"
    path.write_text(json.dumps([{"event_type": "alert", "msg": "x"}]), encoding="utf-8")
    assert not is_suricata_eve(path)


def test_infer_evidence_type_routes_by_content(tmp_path):
    eve = _write_eve(tmp_path, [ALERT])
    assert infer_evidence_type("eve.json", path=eve) == "suricata"
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps([{"a": 1}]), encoding="utf-8")
    assert infer_evidence_type("plain.json", path=plain) == "json"
    # Without a path, extension-only (unchanged behaviour).
    assert infer_evidence_type("eve.json") == "json"


def test_maps_each_event_type(tmp_path):
    path = _write_eve(tmp_path, [ALERT, DNS_Q, HTTP, TLS, FILEINFO, FLOW, STATS])
    events = SuricataParser().parse(path, evidence_id="EV-0001")
    by_type = {e.event_type: e for e in events}

    # stats is skipped; the six security-relevant types are mapped.
    assert set(by_type) == {"alert", "dns_query", "http_request", "tls_handshake", "file_transfer", "network_connection"}

    assert by_type["alert"].message.startswith("ET MALWARE Suspicious download")
    assert by_type["alert"].severity == "High"
    assert by_type["alert"].dst_ip == "93.184.216.34" and by_type["alert"].dst_port == 80
    assert by_type["dns_query"].domain == "bad.example.com"
    assert by_type["http_request"].domain == "example.com"
    assert by_type["http_request"].url == "http://example.com/malware.exe"
    assert by_type["tls_handshake"].domain == "secure.example.net"
    assert by_type["file_transfer"].file_name == "/malware.exe"
    assert by_type["file_transfer"].file_hash == "a" * 64
    assert by_type["network_connection"].dst_port == 4444
    # Every event carries the source and a traceable line reference.
    assert all(e.source == "suricata" for e in events)
    assert all(e.raw_event_reference.get("line_number") for e in events)


def test_tolerates_blank_and_truncated_lines(tmp_path):
    path = tmp_path / "eve.json"
    # blank line, a good record, then a truncated final line (still-writing).
    path.write_text("\n" + json.dumps(ALERT) + "\n" + '{"event_type": "dns", "dns": {"rr', encoding="utf-8")
    events = SuricataParser().parse(path, evidence_id="EV-0001")
    assert len(events) == 1 and events[0].event_type == "alert"


def test_dns_v2_queries_array(tmp_path):
    rec = {
        "timestamp": "2026-08-27T09:00:00+0000", "event_type": "dns", "src_ip": "10.0.0.5", "dest_ip": "10.0.0.1",
        "dns": {"type": "query", "queries": [{"rrname": "v2.example.com", "rrtype": "A"}]},
    }
    events = SuricataParser().parse(_write_eve(tmp_path, [rec]), evidence_id="EV-0001")
    assert events[0].domain == "v2.example.com"


def test_registered_for_suricata_type():
    from netforensicai.parsers import base, load_parsers

    load_parsers()
    assert base.get_parser("suricata") is not None
