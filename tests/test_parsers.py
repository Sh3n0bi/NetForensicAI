"""Tests for the pcap parser, using synthetic pcap files built with scapy
so nothing here depends on tshark, a real capture, or sensitive data."""

import hashlib
from pathlib import Path

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

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
    assert first.raw_event_reference["first_packet_number"] == 1
    assert first.raw_event_reference["packet_count"] == 1
    assert first.raw_event_reference["byte_count"] > 0
    assert first.timestamp is not None


def test_connection_event_produced_for_tcp_handshake_with_no_payload(tmp_path):
    # Regression: a capture consisting entirely of TCP control packets
    # (SYN/ACK/FIN, no application payload) previously produced ZERO
    # network_connection events - "network_connection: one event per TCP
    # packet carrying a payload" meant a completely normal, realistic
    # capture (most TCP connections are mostly handshake/ack traffic)
    # could parse into an empty case with nothing to investigate.
    syn = IP(src="10.0.0.5", dst="8.8.8.8") / TCP(sport=51000, dport=443, flags="S")
    syn.time = 1_700_000_500.0
    synack = IP(src="8.8.8.8", dst="10.0.0.5") / TCP(sport=443, dport=51000, flags="SA")
    synack.time = 1_700_000_500.1
    pcap_path = _write_pcap(tmp_path, "handshake.pcap", [syn, synack])

    events = PcapParser().parse(pcap_path, evidence_id="EV-0008")

    connections = [e for e in events if e.event_type == "network_connection"]
    assert len(connections) == 2  # one per direction
    assert all(e.src_port is not None and e.dst_port is not None for e in connections)
    outbound = next(e for e in connections if e.src_ip == "10.0.0.5")
    assert "no application payload observed" in outbound.message


def test_multiple_packets_in_the_same_flow_aggregate_into_one_event(tmp_path):
    packets = [
        _packet("10.0.0.5", "203.0.113.9", 51000, 443, b"chunk-a", 1_700_000_600.0),
        _packet("10.0.0.5", "203.0.113.9", 51000, 443, b"chunk-b", 1_700_000_600.2),
        _packet("10.0.0.5", "203.0.113.9", 51000, 443, b"chunk-c", 1_700_000_600.4),
    ]
    pcap_path = _write_pcap(tmp_path, "same_flow.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0009")

    connections = [e for e in events if e.event_type == "network_connection"]
    assert len(connections) == 1  # not one event per packet
    assert connections[0].raw_event_reference["packet_count"] == 3
    assert connections[0].message.startswith("chunk-a")  # preview of the first packet with a payload


def test_udp_packets_produce_network_connection_events(tmp_path):
    pkt = IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=6000, dport=7000) / Raw(load=b"udp payload")
    pkt.time = 1_700_000_700.0
    pcap_path = _write_pcap(tmp_path, "udp.pcap", [pkt])

    events = PcapParser().parse(pcap_path, evidence_id="EV-0010")

    connections = [e for e in events if e.event_type == "network_connection"]
    assert len(connections) == 1
    assert connections[0].protocol == "udp"
    assert connections[0].src_port == 6000
    assert connections[0].dst_port == 7000


def test_dns_query_produces_dns_query_event_with_domain(tmp_path):
    pkt = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(qd=DNSQR(qname="evil-c2.example.com"))
    pkt.time = 1_700_000_800.0
    pcap_path = _write_pcap(tmp_path, "dns.pcap", [pkt])

    events = PcapParser().parse(pcap_path, evidence_id="EV-0011")

    dns_events = [e for e in events if e.event_type == "dns_query"]
    assert len(dns_events) == 1
    assert dns_events[0].domain == "evil-c2.example.com"
    assert dns_events[0].src_ip == "10.0.0.5"
    # DNS packets must not ALSO produce a generic network_connection event
    # (that would double-count the same packet under two event types).
    assert [e for e in events if e.event_type == "network_connection"] == []


def test_http_request_populates_domain_and_url(tmp_path):
    request = (
        b"GET /admin/login.php HTTP/1.1\r\n"
        b"Host: internal-portal.example.com\r\n"
        b"User-Agent: curl/8.0\r\n\r\n"
    )
    packets = [_packet("10.0.0.5", "203.0.113.20", 51500, 80, request, 1_700_001_100.0)]
    pcap_path = _write_pcap(tmp_path, "http_req.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0013")

    http_events = [e for e in events if e.event_type == "http_request"]
    assert len(http_events) == 1
    event = http_events[0]
    assert event.domain == "internal-portal.example.com"
    assert event.url == "http://internal-portal.example.com/admin/login.php"
    assert event.raw_event_reference["method"] == "GET"


def test_http_request_on_nonstandard_port_is_still_detected(tmp_path):
    # Matched on the request line itself, not the port - so a web service
    # on 8443 or a C2 channel on 4444 is caught the same as port 80.
    request = b"POST /upload HTTP/1.1\r\nHost: 203.0.113.99:4444\r\n\r\n"
    packets = [_packet("10.0.0.5", "203.0.113.99", 51600, 4444, request, 1_700_001_200.0)]
    pcap_path = _write_pcap(tmp_path, "http_odd_port.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0014")

    http_events = [e for e in events if e.event_type == "http_request"]
    assert len(http_events) == 1
    assert http_events[0].domain == "203.0.113.99"  # port stripped off the Host header
    assert http_events[0].raw_event_reference["method"] == "POST"


def test_non_http_payload_produces_no_http_event(tmp_path):
    packets = [_packet("10.0.0.5", "8.8.8.8", 51000, 80, b"\x00\x01binary junk", 1_700_001_300.0)]
    pcap_path = _write_pcap(tmp_path, "not_http.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0015")

    assert [e for e in events if e.event_type == "http_request"] == []


def test_tls_client_hello_sni_is_extracted(tmp_path):
    # Built with scapy's real TLS implementation rather than a hand-rolled
    # byte blob, so this exercises the offset-walking parser against bytes
    # a real TLS stack actually produces.
    from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.record import TLS

    client_hello = TLS(
        msg=[TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"malware-c2.example.net")])])]
    )
    payload = bytes(client_hello)
    packets = [_packet("10.0.0.5", "203.0.113.30", 51700, 443, payload, 1_700_001_400.0)]
    pcap_path = _write_pcap(tmp_path, "tls.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0016")

    tls_events = [e for e in events if e.event_type == "tls_handshake"]
    assert len(tls_events) == 1
    assert tls_events[0].domain == "malware-c2.example.net"
    assert tls_events[0].dst_port == 443


def test_payload_on_port_443_is_not_skipped_by_scapy_auto_dissection(tmp_path):
    # Regression: the parser used to read payloads via packet[Raw].load,
    # but scapy binds dissectors to well-known ports - a payload on 443
    # comes back as a TLS layer, so haslayer(Raw) was False and the whole
    # packet got skipped. That silently dropped ALL HTTPS traffic from
    # file-transfer extraction, and depended on which scapy submodules
    # the process happened to import. Payloads now come from TCP.payload.
    file_bytes = b"%PDF-1.7 a pdf exfiltrated over 443"
    packets = [_packet("10.0.0.5", "203.0.113.9", 51900, 443, file_bytes, 1_700_001_600.0)]
    pcap_path = _write_pcap(tmp_path, "https_pdf.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0018")

    file_events = [e for e in events if e.event_type == "file_transfer"]
    assert len(file_events) == 1
    assert file_events[0].file_name.endswith(".pdf")
    assert file_events[0].file_hash == hashlib.sha256(file_bytes).hexdigest()


def test_malformed_tls_payload_does_not_raise(tmp_path):
    # A truncated/garbage TLS record must be skipped silently, never crash
    # the whole parse - a real capture routinely contains partial records.
    packets = [_packet("10.0.0.5", "203.0.113.30", 51800, 443, b"\x16\x03\x01\x00\x05\x01\x00\x00", 1_700_001_500.0)]
    pcap_path = _write_pcap(tmp_path, "bad_tls.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0017")

    assert [e for e in events if e.event_type == "tls_handshake"] == []


def test_dns_response_does_not_produce_a_dns_query_event(tmp_path):
    query = DNSQR(qname="example.com")
    response = IP(src="8.8.8.8", dst="10.0.0.5") / UDP(sport=53, dport=5353) / DNS(qr=1, qd=query, an=None)
    response.time = 1_700_000_900.0
    pcap_path = _write_pcap(tmp_path, "dns_response.pcap", [response])

    events = PcapParser().parse(pcap_path, evidence_id="EV-0012")

    assert [e for e in events if e.event_type == "dns_query"] == []


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


def test_http_response_is_paired_back_to_its_request_url(tmp_path):
    request = b"GET /admin/secret.php HTTP/1.1\r\nHost: target.example\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"
    packets = [
        _packet("10.0.0.5", "203.0.113.7", 51000, 80, request, 1_700_002_100.0),
        _packet("203.0.113.7", "10.0.0.5", 80, 51000, response, 1_700_002_100.2),
    ]
    pcap_path = _write_pcap(tmp_path, "reqresp.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0020")

    responses = [e for e in events if e.event_type == "http_response"]
    assert len(responses) == 1
    assert responses[0].raw_event_reference["status_code"] == 200
    # The whole point: the status is tied to the URL it answered.
    assert responses[0].url == "http://target.example/admin/secret.php"
    assert responses[0].raw_event_reference["request_method"] == "GET"


def test_http_responses_pair_in_order_on_a_keepalive_flow(tmp_path):
    packets = [
        _packet("10.0.0.5", "203.0.113.7", 51000, 80, b"GET /first HTTP/1.1\r\nHost: t.example\r\n\r\n", 1_700_002_200.0),
        _packet("203.0.113.7", "10.0.0.5", 80, 51000, b"HTTP/1.1 404 Not Found\r\n\r\n", 1_700_002_200.1),
        _packet("10.0.0.5", "203.0.113.7", 51000, 80, b"GET /second HTTP/1.1\r\nHost: t.example\r\n\r\n", 1_700_002_200.2),
        _packet("203.0.113.7", "10.0.0.5", 80, 51000, b"HTTP/1.1 200 OK\r\n\r\n", 1_700_002_200.3),
    ]
    pcap_path = _write_pcap(tmp_path, "keepalive.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0021")

    responses = [e for e in events if e.event_type == "http_response"]
    paired = {r.raw_event_reference["status_code"]: r.url for r in responses}
    assert paired[404] == "http://t.example/first"
    assert paired[200] == "http://t.example/second"


def test_response_without_a_matching_request_still_records_the_status(tmp_path):
    # A capture that starts mid-conversation has responses whose requests
    # were never captured - the status is still worth recording.
    packets = [_packet("203.0.113.7", "10.0.0.5", 80, 51000, b"HTTP/1.1 500 Internal Server Error\r\n\r\n", 1_700_002_300.0)]
    pcap_path = _write_pcap(tmp_path, "orphan.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0022")

    responses = [e for e in events if e.event_type == "http_response"]
    assert len(responses) == 1
    assert responses[0].raw_event_reference["status_code"] == 500
    assert responses[0].url is None


def test_anomaly_detection_is_skipped_on_large_captures(tmp_path, monkeypatch):
    # A fixed contamination fraction reports a quantile, not an anomaly, so
    # above the threshold the detector is disabled rather than emitting a
    # guaranteed percentage of the capture as "anomalies".
    monkeypatch.setattr("netforensicai.parsers.pcap.MAX_PACKETS_FOR_ANOMALY_DETECTION", 10)
    packets = [
        _packet("10.0.0.5", "10.0.0.6", 5000, 6000, b"x" * 40, 1_700_003_000.0 + i * 0.1) for i in range(30)
    ]
    pcap_path = _write_pcap(tmp_path, "big.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0023")

    assert [e for e in events if e.event_type == "anomaly"] == []
    # Everything else must still be parsed normally.
    assert [e for e in events if e.event_type == "network_connection"]


def test_streaming_parse_does_not_hold_packets_in_memory(tmp_path):
    # Guards the property that makes multi-GB captures viable: peak memory
    # must track live flows, not capture size. Loading every scapy packet
    # was measured at ~18x the file size, so a naive parser would blow far
    # past this bound on even this small synthetic capture.
    import tracemalloc

    payload = b"A" * 1400
    packets = [
        _packet("10.0.0.5", "10.0.0.6", 5000 + (i % 50), 80, payload, 1_700_004_000.0 + i * 0.01)
        for i in range(4000)
    ]
    pcap_path = _write_pcap(tmp_path, "bulk.pcap", packets)
    file_size = pcap_path.stat().st_size

    tracemalloc.start()
    PcapParser().parse(pcap_path, evidence_id="EV-0024")
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert peak < file_size * 4, f"peak {peak} vs file {file_size} - parser is retaining packets"


def test_truncated_capture_keeps_the_packets_read_so_far(tmp_path):
    # A killed tcpdump or partial download is common in real DFIR work;
    # losing everything already parsed would be much worse than a warning.
    packets = [
        _packet("10.0.0.5", "8.8.8.8", 51000, 80, b"GET /a HTTP/1.1\r\nHost: t.example\r\n\r\n", 1_700_005_000.0),
        _packet("10.0.0.5", "8.8.8.8", 51000, 80, b"GET /b HTTP/1.1\r\nHost: t.example\r\n\r\n", 1_700_005_000.5),
    ]
    pcap_path = _write_pcap(tmp_path, "whole.pcap", packets)
    data = pcap_path.read_bytes()
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(data[: len(data) - 20])  # chop the final record

    events = PcapParser().parse(truncated, evidence_id="EV-0025")

    assert [e for e in events if e.event_type == "http_request"]


def test_ipv6_traffic_is_parsed(tmp_path):
    # Regression: scapy's `IP` class is IPv4 only, so `haslayer(IP)` silently
    # discarded every IPv6 packet - a capture of IPv6 web traffic parsed to
    # zero connection and zero HTTP events. Found by testing against a
    # corpus rather than the single IPv4 capture available.
    from scapy.all import IPv6

    packets = []
    for i in range(5):
        pkt = IPv6(src="2001:db8::5", dst="2001:db8::9") / TCP(sport=51000 + i, dport=80) / Raw(
            load=f"GET /v6-{i} HTTP/1.1\r\nHost: v6.example\r\n\r\n".encode()
        )
        pkt.time = 1_700_006_000.0 + i
        packets.append(pkt)
    pcap_path = _write_pcap(tmp_path, "ipv6.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0030")

    connections = [e for e in events if e.event_type == "network_connection"]
    requests = [e for e in events if e.event_type == "http_request"]
    assert len(connections) == 5
    assert len(requests) == 5
    assert connections[0].src_ip == "2001:db8::5"
    assert requests[0].url == "http://v6.example/v6-0"


def test_icmp_produces_a_flow_event(tmp_path):
    # A pure-ICMP capture (ping sweep, traceroute, ICMP tunnelling) used to
    # produce no events at all.
    from scapy.all import ICMP

    packets = []
    for i in range(4):
        pkt = IP(src="10.0.0.5", dst="10.0.0.9") / ICMP()
        pkt.time = 1_700_007_000.0 + i
        packets.append(pkt)
    pcap_path = _write_pcap(tmp_path, "icmp.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0031")

    connections = [e for e in events if e.event_type == "network_connection"]
    assert len(connections) == 1  # one flow, four packets
    assert connections[0].protocol == "icmp"
    assert connections[0].src_port is None and connections[0].dst_port is None
    assert connections[0].raw_event_reference["packet_count"] == 4


def test_dns_response_records_what_the_name_resolved_to(tmp_path):
    # The query alone never carries the answer; the resolved address is what
    # links a domain in one piece of evidence to an IP in another.
    from scapy.all import DNSRR

    query = DNSQR(qname="evil-c2.example.com")
    response = IP(src="8.8.8.8", dst="10.0.0.5") / UDP(sport=53, dport=40000) / DNS(
        qr=1, qd=query, an=DNSRR(rrname="evil-c2.example.com", rdata="203.0.113.99")
    )
    response.time = 1_700_008_000.0
    pcap_path = _write_pcap(tmp_path, "dnsresp.pcap", [response])

    events = PcapParser().parse(pcap_path, evidence_id="EV-0032")

    responses = [e for e in events if e.event_type == "dns_response"]
    assert len(responses) == 1
    assert responses[0].domain == "evil-c2.example.com"
    assert "203.0.113.99" in responses[0].raw_event_reference["answers"]


def test_vlan_tagged_traffic_is_parsed(tmp_path):
    from scapy.all import Dot1Q, Ether

    pkt = Ether() / Dot1Q(vlan=100) / IP(src="10.1.0.5", dst="10.1.0.9") / TCP(sport=53000, dport=80) / Raw(
        load=b"GET /vlan HTTP/1.1\r\nHost: vlan.example\r\n\r\n"
    )
    pkt.time = 1_700_009_000.0
    pcap_path = _write_pcap(tmp_path, "vlan.pcap", [pkt])

    events = PcapParser().parse(pcap_path, evidence_id="EV-0033")

    assert [e for e in events if e.event_type == "http_request"]


def test_empty_capture_parses_to_no_events(tmp_path):
    pcap_path = _write_pcap(tmp_path, "empty.pcap", [])

    assert PcapParser().parse(pcap_path, evidence_id="EV-0034") == []


def test_malformed_payloads_do_not_raise(tmp_path):
    # Truncated TLS records, bogus HTTP lines and binary noise all occur in
    # real captures; none of them may abort the parse.
    payloads = [
        b"\x16\x03\x01\x00",                      # truncated TLS record
        b"\x16\x03\x01\xff\xff\x01\x00\xff\xff",  # TLS with impossible lengths
        b"GET",                                    # truncated request line
        b"GET \x00\xff\xfe / HTTP/9.9\r\n",       # binary in the request line
        b"HTTP/1.1 abc NotANumber\r\n",           # non-numeric status code
        b"\xff" * 200,                             # pure binary
    ]
    packets = []
    for i, payload in enumerate(payloads):
        pkt = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=54000 + i, dport=443) / Raw(load=payload)
        pkt.time = 1_700_010_000.0 + i
        packets.append(pkt)
    pcap_path = _write_pcap(tmp_path, "malformed.pcap", packets)

    events = PcapParser().parse(pcap_path, evidence_id="EV-0035")

    # Every flow is still recorded even though none of the payloads parse.
    assert len([e for e in events if e.event_type == "network_connection"]) == len(payloads)


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
