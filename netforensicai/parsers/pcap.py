"""PCAP -> normalized Event parsing.

Uses scapy (pure Python) to read .pcap files instead of pyshark/tshark.
Reading and writing pcap *files* with scapy needs no external binary or
capture driver (only live sniffing does), which is what makes it possible
to build synthetic pcap fixtures for tests in this repo.

Six analyses, each producing a distinct event_type:
  - network_connection: one event per distinct flow (protocol, src
    ip:port, dst ip:port) - covers every TCP and UDP flow, not just ones
    carrying an application payload. A payload preview lands in
    `message` when any packet in the flow had one (the original DPI
    behavior); otherwise `message` just states the packet/byte count.
    This matters: a huge share of real traffic is TCP handshake/control
    packets (SYN/ACK/FIN) with no payload at all, or UDP, and a capture
    consisting mostly of that used to silently produce zero events here.
  - dns_query: one event per DNS query packet, with the queried domain
    in `domain` (a dedicated Event field, not buried in a message
    string) so it flows straight into entity extraction as a domain
    entity like any other evidence source's domain field would.
  - http_request: one event per HTTP request line found in a TCP payload,
    with the Host header in `domain` and the full URL in `url`. Matched on
    raw bytes rather than scapy's HTTP layer so it works on any port.
  - tls_handshake: one event per TLS ClientHello, with the SNI hostname in
    `domain` - usually the only identifying detail recoverable from an
    otherwise-encrypted flow.
  - file_transfer: one event per TCP stream whose reassembled data matches
    a known file signature (magic bytes), optionally saved to disk
  - anomaly: one event per packet flagged as a statistical outlier by
    IsolationForest over [size, inter_arrival, src_port, dst_port]
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from scapy.all import DNS, IP, TCP, UDP, rdpcap
from sklearn.ensemble import IsolationForest

from netforensicai.core.event import Event, EventSequence, generate_event_id
from netforensicai.parsers import base

logger = logging.getLogger(__name__)

FILE_SIGNATURES = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG",
    "jpg": b"\xFF\xD8\xFF",
    "zip": b"PK\x03\x04",
    "exe": b"MZ",
    "gif": b"GIF89a",
}

SIGNATURE_SCAN_WINDOW = 1024
DPI_PREVIEW_BYTES = 50
DEFAULT_ANOMALY_CONTAMINATION = 0.05


class PcapParseError(Exception):
    """Raised when a pcap file cannot be read."""


def _load_packets(pcap_path):
    try:
        return rdpcap(str(pcap_path))
    except Exception as e:
        raise PcapParseError(f"Failed to read pcap file '{pcap_path}': {e}") from e


def _tcp_payload(packet):
    """Raw application-layer bytes carried by a TCP packet, or b"".

    Deliberately NOT `packet[Raw].load`: scapy binds known dissectors to
    well-known ports, so a payload on 443 comes back as a `TLS` layer and
    one on 80 can come back as `HTTP` - `haslayer(Raw)` is then False and
    the payload gets skipped entirely. Whether that happens depends on
    which scapy submodules the process has imported, which makes it a
    genuinely load-order-dependent bug. Going through TCP.payload gets
    the bytes regardless of how scapy chose to dissect them.
    """
    try:
        return bytes(packet[TCP].payload)
    except Exception:
        return b""


def _tcp_payload_packets(packets):
    """Yield (packet_number, packet, payload_bytes) for IP+TCP packets
    carrying an application-layer payload."""
    for i, packet in enumerate(packets, start=1):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            continue
        payload = _tcp_payload(packet)
        if payload:
            yield i, packet, payload


def _packet_timestamp(packet):
    return datetime.fromtimestamp(float(packet.time), tz=timezone.utc)


def _connection_events(packets, evidence_id, sequence):
    """One event per distinct (protocol, src ip:port, dst ip:port) flow,
    covering every TCP and UDP packet - not just ones carrying an
    application payload. DNS packets are excluded here; they get the
    more specific dns_query event type from _dns_query_events instead."""
    flows = {}
    order = []
    for packet_number, packet in enumerate(packets, start=1):
        if not packet.haslayer(IP):
            continue
        if packet.haslayer(TCP):
            protocol, src_port, dst_port = "tcp", int(packet[TCP].sport), int(packet[TCP].dport)
        elif packet.haslayer(UDP) and not packet.haslayer(DNS):
            protocol, src_port, dst_port = "udp", int(packet[UDP].sport), int(packet[UDP].dport)
        else:
            continue

        key = (protocol, packet[IP].src, src_port, packet[IP].dst, dst_port)
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = {
                "first_timestamp": float(packet.time),
                "first_packet_number": packet_number,
                "packet_count": 0,
                "byte_count": 0,
                "payload_preview": None,
            }
            order.append(key)
        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)
        if flow["payload_preview"] is None:
            payload = _tcp_payload(packet) if protocol == "tcp" else bytes(packet[UDP].payload)
            if payload:
                flow["payload_preview"] = payload[:DPI_PREVIEW_BYTES].decode("utf-8", errors="ignore")

    events = []
    for key in order:
        protocol, src_ip, src_port, dst_ip, dst_port = key
        flow = flows[key]
        message = flow["payload_preview"]
        if message is None:
            message = f"{flow['packet_count']} packet(s), {flow['byte_count']} bytes, no application payload observed"
        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="network_connection",
                timestamp=datetime.fromtimestamp(flow["first_timestamp"], tz=timezone.utc),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                message=message,
                raw_event_reference={
                    "first_packet_number": flow["first_packet_number"],
                    "packet_count": flow["packet_count"],
                    "byte_count": flow["byte_count"],
                },
            )
        )
    return events


def _dns_qname(dns):
    """Extract the queried name from a DNS layer, tolerating scapy's
    change from `qd` being a single record to a PacketListField (newer
    scapy warns on direct attribute access, older versions have no
    indexing). Returns "" if it can't be read."""
    qd = dns.qd
    try:
        record = qd[0] if isinstance(qd, (list, tuple)) or hasattr(qd, "__getitem__") else qd
    except Exception:
        record = qd
    try:
        qname = record.qname
    except Exception:
        return ""
    if isinstance(qname, bytes):
        qname = qname.decode("utf-8", errors="ignore")
    return str(qname).rstrip(".")


def _dns_query_events(packets, evidence_id, sequence):
    """One event per DNS query packet (not responses) - the queried
    domain lands in Event.domain, a dedicated field, so it flows
    straight into entity extraction as a domain entity."""
    events = []
    for packet_number, packet in enumerate(packets, start=1):
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS)):
            continue
        dns = packet[DNS]
        if dns.qr != 0 or not dns.qd:
            continue  # qr=0 is a query; qr=1 is a response - only queries here
        qname = _dns_qname(dns)
        if not qname:
            continue
        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="dns_query",
                timestamp=_packet_timestamp(packet),
                src_ip=packet[IP].src,
                src_port=int(packet[UDP].sport),
                dst_ip=packet[IP].dst,
                dst_port=int(packet[UDP].dport),
                protocol="udp",
                domain=qname,
                message=f"DNS query for {qname}",
                raw_event_reference={"packet_number": packet_number},
            )
        )
    return events


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def _http_request_events(packets, evidence_id, sequence):
    """One event per HTTP request line seen in a TCP payload. Parsed from
    raw bytes rather than scapy's HTTP layer so it works on any port (not
    just 80) and needs no extra scapy contrib import - a request line is
    unambiguous enough to match directly.

    Populates Event.domain from the Host header and Event.url from the
    request target, so both flow into entity extraction as real entities
    rather than being buried in a message string."""
    events = []
    for packet_number, packet, payload in _tcp_payload_packets(packets):
        if not payload.startswith(HTTP_METHODS):
            continue
        head = payload[:2048]
        try:
            first_line = head.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            parts = first_line.split(" ")
            if len(parts) < 2:
                continue
            method, target = parts[0], parts[1]
        except Exception:
            continue

        host = None
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"host:"):
                host = line[5:].strip().decode("utf-8", errors="ignore")
                break

        # A request target is usually a path; combine it with Host to form
        # a real URL when we have one, otherwise keep whatever was there.
        if host and target.startswith("/"):
            url = f"http://{host}{target}"
        else:
            url = target

        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="http_request",
                timestamp=_packet_timestamp(packet),
                src_ip=packet[IP].src,
                src_port=int(packet[TCP].sport),
                dst_ip=packet[IP].dst,
                dst_port=int(packet[TCP].dport),
                protocol="tcp",
                domain=host.split(":")[0] if host else None,
                url=url,
                message=f"HTTP {method} {url}",
                raw_event_reference={"packet_number": packet_number, "method": method, "host": host},
            )
        )
    return events


def _tls_sni(payload):
    """Pull the SNI server_name out of a TLS ClientHello, walking the
    record/handshake/extension structure by offset. Returns "" if this
    isn't a ClientHello or the structure doesn't parse - deliberately
    conservative, since a malformed or truncated capture must never
    raise out of parsing."""
    try:
        # TLS record: type(1) version(2) length(2), then handshake:
        # type(1) length(3) version(2) random(32) ...
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        pos = 43  # start of session_id_length
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_suites_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cipher_suites_len
        compression_len = payload[pos]
        pos += 1 + compression_len
        if pos + 2 > len(payload):
            return ""
        extensions_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        end = min(pos + extensions_len, len(payload))
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            body = payload[pos + 4 : pos + 4 + ext_len]
            if ext_type == 0x0000 and len(body) >= 5:  # server_name
                name_len = int.from_bytes(body[3:5], "big")
                return body[5 : 5 + name_len].decode("utf-8", errors="ignore")
            pos += 4 + ext_len
    except Exception:
        return ""
    return ""


def _tls_handshake_events(packets, evidence_id, sequence):
    """One event per TLS ClientHello, with the SNI hostname in
    Event.domain. This is the single most useful thing recoverable from
    encrypted traffic: the payload is opaque, but the name the client
    asked for is not."""
    events = []
    for packet_number, packet, payload in _tcp_payload_packets(packets):
        sni = _tls_sni(payload)
        if not sni:
            continue
        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="tls_handshake",
                timestamp=_packet_timestamp(packet),
                src_ip=packet[IP].src,
                src_port=int(packet[TCP].sport),
                dst_ip=packet[IP].dst,
                dst_port=int(packet[TCP].dport),
                protocol="tcp",
                domain=sni,
                message=f"TLS ClientHello for {sni}",
                raw_event_reference={"packet_number": packet_number, "sni": sni},
            )
        )
    return events


def _file_transfer_events(packets, evidence_id, sequence, output_dir=None):
    streams = {}
    for packet_number, packet, payload in _tcp_payload_packets(packets):
        stream_key = (
            f"{packet[IP].src}:{packet[TCP].sport}->{packet[IP].dst}:{packet[TCP].dport}"
        )
        stream = streams.setdefault(
            stream_key, {"data": [], "packet_numbers": [], "first_timestamp": None}
        )
        stream["data"].append(payload)
        stream["packet_numbers"].append(packet_number)
        if stream["first_timestamp"] is None:
            stream["first_timestamp"] = float(packet.time)

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    events = []
    for stream_key, info in streams.items():
        full_data = b"".join(info["data"])
        file_type = next(
            (ext for ext, sig in FILE_SIGNATURES.items() if sig in full_data[:SIGNATURE_SCAN_WINDOW]),
            None,
        )
        if not file_type:
            continue

        src, dst = stream_key.split("->")
        src_ip, src_port = src.split(":")
        dst_ip, dst_port = dst.split(":")
        file_name = f"{stream_key.replace(':', '_').replace('->', '_to_')}.{file_type}"

        stored_path = None
        if output_dir is not None:
            stored_path = output_dir / file_name
            stored_path.write_bytes(full_data)
            logger.info(f"Saved extracted file: {stored_path} ({len(full_data)} bytes)")

        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="file_transfer",
                timestamp=datetime.fromtimestamp(info["first_timestamp"], tz=timezone.utc),
                src_ip=src_ip,
                src_port=int(src_port),
                dst_ip=dst_ip,
                dst_port=int(dst_port),
                protocol="tcp",
                file_name=file_name,
                file_path=str(stored_path) if stored_path else None,
                file_hash=hashlib.sha256(full_data).hexdigest(),
                message=f"Detected embedded {file_type} file ({len(full_data)} bytes) in TCP stream {stream_key}",
                raw_event_reference={"packet_numbers": info["packet_numbers"], "stream": stream_key},
            )
        )
    return events


def _packet_features(packets):
    """Return (feature_rows, meta) for every packet, in packet order."""
    features = []
    meta = []
    prev_time = None
    for i, packet in enumerate(packets, start=1):
        timestamp = float(packet.time)
        size = len(packet)
        src_port = int(packet[TCP].sport) if packet.haslayer(TCP) else 0
        dst_port = int(packet[TCP].dport) if packet.haslayer(TCP) else 0
        inter_arrival = timestamp - prev_time if prev_time is not None else 0.0
        prev_time = timestamp
        features.append([size, inter_arrival, src_port, dst_port])
        meta.append(
            {
                "packet_number": i,
                "timestamp": timestamp,
                "size": size,
                "inter_arrival": inter_arrival,
                "src_ip": packet[IP].src if packet.haslayer(IP) else None,
                "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
                "src_port": src_port or None,
                "dst_port": dst_port or None,
            }
        )
    return features, meta


def _anomaly_events(packets, evidence_id, sequence, contamination=DEFAULT_ANOMALY_CONTAMINATION):
    if len(packets) < 2:
        return []

    features, meta = _packet_features(packets)
    df = pd.DataFrame(features, columns=["size", "inter_arrival", "src_port", "dst_port"])
    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(df)

    events = []
    for is_anomalous, info in zip(predictions == -1, meta):
        if not is_anomalous:
            continue
        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="anomaly",
                timestamp=datetime.fromtimestamp(info["timestamp"], tz=timezone.utc),
                src_ip=info["src_ip"],
                dst_ip=info["dst_ip"],
                src_port=info["src_port"],
                dst_port=info["dst_port"],
                severity="medium",
                message="Packet flagged as a statistical outlier (size/timing/port profile) by IsolationForest.",
                raw_event_reference={
                    "packet_number": info["packet_number"],
                    "size": info["size"],
                    "inter_arrival": info["inter_arrival"],
                },
            )
        )
    return events


class PcapParser(base.BaseParser):
    evidence_types = ("pcap",)

    def parse(
        self,
        file_path,
        evidence_id,
        output_dir=None,
        anomaly_contamination=DEFAULT_ANOMALY_CONTAMINATION,
        **_ignored,
    ):
        """Parse a pcap file into normalized Events. Raises PcapParseError if unreadable.

        output_dir: if given, extracted embedded files are saved there and
        file_transfer events get a populated file_path.
        """
        packets = _load_packets(file_path)
        sequence = EventSequence()

        events = []
        events.extend(_connection_events(packets, evidence_id, sequence))
        events.extend(_dns_query_events(packets, evidence_id, sequence))
        events.extend(_http_request_events(packets, evidence_id, sequence))
        events.extend(_tls_handshake_events(packets, evidence_id, sequence))
        events.extend(_file_transfer_events(packets, evidence_id, sequence, output_dir))
        events.extend(_anomaly_events(packets, evidence_id, sequence, anomaly_contamination))
        return events


base.register(PcapParser())
