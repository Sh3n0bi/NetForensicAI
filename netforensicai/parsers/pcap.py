"""PCAP -> normalized Event parsing.

Uses scapy (pure Python) to read .pcap files instead of pyshark/tshark.
Reading and writing pcap *files* with scapy needs no external binary or
capture driver (only live sniffing does), which is what makes it possible
to build synthetic pcap fixtures for tests in this repo.

Parsing is a SINGLE STREAMING PASS (see _StreamCollector). Real DFIR
captures are routinely gigabytes, and scapy's fully-dissected packet
objects were measured at ~18x the file size in RAM - loading a 1 GB
capture up front would need ~18 GB before any analysis ran. Streaming
holds only the running state each analysis needs, so peak memory tracks
the number of live flows rather than the size of the file.

Seven analyses, each producing a distinct event_type:
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
  - http_response: one event per HTTP status line, paired back to the URL
    that was requested on the same flow. Without this you can see that an
    attacker requested 40,000 paths but not which ones actually existed -
    the status code is what separates a failed scan from a successful one.
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
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from scapy.all import DNS, ICMP, IP, IPv6, TCP, UDP, PcapReader
from sklearn.ensemble import IsolationForest

from netforensicai.core.event import Event, EventSequence, generate_event_id
from netforensicai.parsers import base, credentials

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

# Above this many packets, the fixed-fraction anomaly detector is disabled.
# IsolationForest's `contamination` is a *proportion*, so on a large capture
# it reports a fixed percentage of everything by construction - 5% of 88k
# packets is ~4,400 "anomalies" that flood the timeline and, being defined
# as a quantile rather than a property of the traffic, carry no information
# about whether anything is actually unusual. Small captures keep it, where
# a genuine outlier is a meaningful signal against a stable baseline.
MAX_PACKETS_FOR_ANOMALY_DETECTION = 20_000

# Cap on bytes buffered per TCP stream for file carving. Only streams whose
# opening bytes matched a file signature are buffered at all (see
# _StreamCollector), so this bounds the pathological case of a very large
# single transfer rather than ordinary traffic.
MAX_CARVE_BYTES_PER_STREAM = 64 * 1024 * 1024

PROGRESS_LOG_EVERY_PACKETS = 25_000


class PcapParseError(Exception):
    """Raised when a pcap file cannot be read."""


def _iter_packets(pcap_path):
    """Stream packets one at a time. PcapReader dispatches to PcapNgReader
    on the file magic, so .pcap and .pcapng both work."""
    try:
        reader = PcapReader(str(pcap_path))
    except Exception as e:
        raise PcapParseError(f"Failed to read pcap file '{pcap_path}': {e}") from e
    try:
        for packet in reader:
            yield packet
    except Exception as e:
        # A truncated capture (killed tcpdump, partial download) is common
        # enough in real DFIR work that it must not lose the packets already
        # read - the caller keeps whatever was parsed before this point.
        logger.warning(f"Stopped reading '{pcap_path}' early: {e}")
    finally:
        reader.close()


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


def _packet_timestamp(packet):
    return datetime.fromtimestamp(float(packet.time), tz=timezone.utc)


def _ip_layer(packet):
    """The packet's network layer, IPv4 or IPv6, or None.

    scapy's `IP` class is IPv4 ONLY - an IPv6 packet has no `IP` layer at
    all. Checking `haslayer(IP)` therefore silently discarded every IPv6
    packet: a capture of IPv6 web traffic parsed to zero events. Every
    address lookup goes through here so a v4-only assumption cannot creep
    back into one call site.
    """
    if packet.haslayer(IP):
        return packet[IP]
    if packet.haslayer(IPv6):
        return packet[IPv6]
    return None


def _try_parse_dns(payload):
    """Parse a UDP payload as a DNS message, or return None.

    scapy binds its DNS dissector to port 53, so `haslayer(DNS)` is False
    for DNS on any other port - and DNS tunnelling and C2 channels
    routinely use one. Same failure as trusting the port for HTTP, so the
    same answer: look at the bytes.

    Deliberately strict, because this runs against every unrecognized UDP
    payload in a capture and a false positive would invent a domain that
    was never queried. A record is only accepted when the header counts
    are sane AND a plausible name comes out the other side.
    """
    if len(payload) < 12:
        return None
    try:
        dns = DNS(payload)
        counts = (int(dns.qdcount), int(dns.ancount), int(dns.nscount), int(dns.arcount))
    except Exception:
        return None
    if counts[0] < 1 or any(count > 64 for count in counts):
        return None
    qname = _dns_qname(dns)
    # A bare label with no dot is far more likely to be a misparse of
    # arbitrary bytes than a real query.
    if not qname or "." not in qname or len(qname) > 253:
        return None
    if not all(32 < ord(c) < 127 for c in qname):
        return None
    return dns


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


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


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


HTTP_STATUS_PREFIX = b"HTTP/"


class _StreamCollector:
    """Accumulates every analysis' running state across a single pass.

    The point is that nothing here retains scapy packet objects: each
    packet is inspected, reduced to a few small values, and discarded. Peak
    memory therefore tracks live flows and carved-file buffers rather than
    capture size, which is what makes multi-gigabyte captures viable.

    feed() returns the events a single packet produced, so the caller can
    write them out and drop them; only genuinely cross-packet state (flow
    counters, carve buffers) is retained until finish(). That is what keeps
    total memory independent of how many events a capture yields, rather
    than merely independent of how many packets it holds.
    """

    def __init__(
        self,
        evidence_id,
        sequence,
        output_dir=None,
        anomaly_contamination=DEFAULT_ANOMALY_CONTAMINATION,
    ):
        self.evidence_id = evidence_id
        self.sequence = sequence
        self.output_dir = Path(output_dir) if output_dir is not None else None
        self.anomaly_contamination = anomaly_contamination

        self.packet_count = 0
        self._flows = {}
        self._flow_order = []
        self._pending = {}
        self._streams = {}
        self._emitted = []  # events produced by the packet currently being fed

        self._features = []
        self._meta = []
        self._prev_time = None
        self._anomaly_disabled = False

    # --- streaming ---

    def feed(self, packet_number, packet):
        """Process one packet and return the events it produced (usually
        none, or one). The caller is expected to persist and discard them."""
        self.packet_count = packet_number
        if packet_number % PROGRESS_LOG_EVERY_PACKETS == 0:
            logger.info(f"Parsed {packet_number:,} packets...")

        self._emitted = []
        self._collect_anomaly_features(packet_number, packet)

        ip = _ip_layer(packet)
        if ip is not None:
            if packet.haslayer(TCP):
                self._feed_tcp(packet_number, packet, ip)
            elif packet.haslayer(UDP):
                self._feed_udp(packet_number, packet, ip)
            elif packet.haslayer(ICMP):
                self._feed_icmp(packet_number, packet, ip)
        return self._emitted

    def _collect_anomaly_features(self, packet_number, packet):
        if self._anomaly_disabled:
            return
        if packet_number > MAX_PACKETS_FOR_ANOMALY_DETECTION:
            # Drop what we have: a fixed-proportion detector over a capture
            # this size reports a quantile, not an anomaly (see the constant).
            self._anomaly_disabled = True
            self._features = []
            self._meta = []
            logger.info(
                f"Capture exceeds {MAX_PACKETS_FOR_ANOMALY_DETECTION:,} packets - skipping "
                "statistical anomaly detection, which flags a fixed fraction of any input and "
                "so produces noise rather than signal at this scale."
            )
            return

        anomaly_ip = _ip_layer(packet)
        timestamp = float(packet.time)
        size = len(packet)
        has_tcp = packet.haslayer(TCP)
        src_port = int(packet[TCP].sport) if has_tcp else 0
        dst_port = int(packet[TCP].dport) if has_tcp else 0
        inter_arrival = timestamp - self._prev_time if self._prev_time is not None else 0.0
        self._prev_time = timestamp
        self._features.append([size, inter_arrival, src_port, dst_port])
        self._meta.append(
            {
                "packet_number": packet_number,
                "timestamp": timestamp,
                "size": size,
                "inter_arrival": inter_arrival,
                "src_ip": anomaly_ip.src if anomaly_ip is not None else None,
                "dst_ip": anomaly_ip.dst if anomaly_ip is not None else None,
                "src_port": src_port or None,
                "dst_port": dst_port or None,
            }
        )

    def _record_flow(self, packet, ip, protocol, src_port, dst_port, payload):
        key = (protocol, ip.src, src_port, ip.dst, dst_port)
        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows[key] = {
                "first_timestamp": float(packet.time),
                "first_packet_number": self.packet_count,
                "packet_count": 0,
                "byte_count": 0,
                "payload_preview": None,
            }
            self._flow_order.append(key)
        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)
        if flow["payload_preview"] is None and payload:
            flow["payload_preview"] = payload[:DPI_PREVIEW_BYTES].decode("utf-8", errors="ignore")

    def _feed_udp(self, packet_number, packet, ip):
        # DNS gets its own, more specific event type - recording it as a
        # generic flow as well would double-count the same packet.
        if packet.haslayer(DNS):
            self._feed_dns(packet_number, packet, ip, packet[DNS])
            return
        payload = bytes(packet[UDP].payload)
        # scapy only dissects DNS on port 53, so anything else needs the
        # payload inspected directly - see _try_parse_dns.
        dns = _try_parse_dns(payload)
        if dns is not None:
            self._feed_dns(packet_number, packet, ip, dns)
            return
        self._record_flow(packet, ip, "udp", int(packet[UDP].sport), int(packet[UDP].dport), payload)

    def _feed_icmp(self, packet_number, packet, ip):
        """ICMP recorded as a flow with no ports. Worth keeping rather than
        discarding: ping sweeps, traceroute and ICMP tunnelling are all
        ordinary findings, and a capture of pure ICMP previously produced no
        events at all."""
        self._record_flow(packet, ip, "icmp", None, None, b"")
        flow = self._flows.get(("icmp", ip.src, None, ip.dst, None))
        if flow is not None and flow["payload_preview"] is None:
            icmp = packet[ICMP]
            flow["payload_preview"] = f"ICMP type={icmp.type} code={icmp.code}"

    def _feed_dns(self, packet_number, packet, ip, dns):
        if not dns.qd:
            return
        if dns.qr != 0:
            self._feed_dns_response(packet_number, packet, ip, dns)
            return
        qname = _dns_qname(dns)
        if not qname:
            return
        self._emitted.append(
            self._event({
                "event_type": "dns_query",
                "timestamp": _packet_timestamp(packet),
                "src_ip": ip.src,
                "src_port": int(packet[UDP].sport),
                "dst_ip": ip.dst,
                "dst_port": int(packet[UDP].dport),
                "protocol": "udp",
                "domain": qname,
                "message": f"DNS query for {qname}",
                "raw_event_reference": {"packet_number": packet_number},
            })
        )

    def _feed_dns_response(self, packet_number, packet, ip, dns):
        """A DNS answer records what a name actually resolved to.

        That mapping is the thing that lets an investigator connect a
        domain seen in one piece of evidence to an IP seen in another, and
        it only exists in the response - the query alone never carries it.
        Dropping responses was the same class of gap as dropping HTTP
        status codes.
        """
        qname = _dns_qname(dns)
        if not qname:
            return
        addresses = []
        try:
            answers = dns.an if isinstance(dns.an, (list, tuple)) else ([dns.an] if dns.an else [])
            for record in answers:
                rdata = getattr(record, "rdata", None)
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")
                if rdata:
                    addresses.append(str(rdata))
        except Exception:
            addresses = []

        resolved = ", ".join(addresses) if addresses else "no answer records"
        self._emitted.append(
            self._event({
                "event_type": "dns_response",
                "timestamp": _packet_timestamp(packet),
                "src_ip": ip.src,
                "src_port": int(packet[UDP].sport),
                "dst_ip": ip.dst,
                "dst_port": int(packet[UDP].dport),
                "protocol": "udp",
                "domain": qname,
                "message": f"DNS response: {qname} -> {resolved}",
                "raw_event_reference": {
                    "packet_number": packet_number,
                    "query": qname,
                    "answers": addresses,
                    "rcode": int(getattr(dns, "rcode", 0) or 0),
                },
            })
        )

    def _feed_tcp(self, packet_number, packet, ip):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        payload = _tcp_payload(packet)
        self._record_flow(packet, ip, "tcp", src_port, dst_port, payload)
        if not payload:
            return

        self._carve(packet_number, packet, ip, src_port, dst_port, payload)

        # Line-oriented cleartext logins, which have no HTTP framing to
        # recognise them by. Guarded on the destination port so this only
        # ever reads a client-to-server payload: a server's "331 Password
        # required" is a prompt, not a credential.
        if dst_port in credentials.CLEARTEXT_PROTOCOLS and dst_port != 80:
            self._feed_credentials(packet_number, packet, ip, src_port, dst_port, payload)

        # Each branch returns: a payload that is an HTTP request or response
        # is not also a TLS ClientHello, and running the SNI parse over every
        # HTTP packet in a web capture is pure waste.
        if payload.startswith(HTTP_METHODS):
            self._feed_http_request(packet_number, packet, ip, src_port, dst_port, payload)
            return
        if payload.startswith(HTTP_STATUS_PREFIX):
            self._feed_http_response(packet_number, packet, ip, src_port, dst_port, payload)
            return
        sni = _tls_sni(payload)
        if sni:
            self._emitted.append(
                self._event({
                    "event_type": "tls_handshake",
                    "timestamp": _packet_timestamp(packet),
                    "src_ip": ip.src,
                    "src_port": src_port,
                    "dst_ip": ip.dst,
                    "dst_port": dst_port,
                    "protocol": "tcp",
                    "domain": sni,
                    "message": f"TLS ClientHello for {sni}",
                    "raw_event_reference": {"packet_number": packet_number, "sni": sni},
                })
            )

    def _feed_http_request(self, packet_number, packet, ip, src_port, dst_port, payload):
        head = payload[:2048]
        try:
            first_line = head.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            parts = first_line.split(" ")
            if len(parts) < 2:
                return
            method, target = parts[0], parts[1]
        except Exception:
            return

        host = None
        user_agent = None
        for line in head.split(b"\r\n")[1:]:
            lowered = line.lower()
            if host is None and lowered.startswith(b"host:"):
                host = line[5:].strip().decode("utf-8", errors="ignore")
            elif user_agent is None and lowered.startswith(b"user-agent:"):
                # One of the highest-signal fields in a web capture: scanners
                # and exploitation tools routinely identify themselves here
                # (see detections.py's ATTACK-TOOL-USER-AGENT rule).
                user_agent = line[11:].strip().decode("utf-8", errors="ignore")[:200]
            if host is not None and user_agent is not None:
                break

        url = f"http://{host}{target}" if host and target.startswith("/") else target

        self._emitted.append(
            self._event({
                "event_type": "http_request",
                "timestamp": _packet_timestamp(packet),
                "src_ip": ip.src,
                "src_port": src_port,
                "dst_ip": ip.dst,
                "dst_port": dst_port,
                "protocol": "tcp",
                "domain": host.split(":")[0] if host else None,
                "url": url,
                "message": f"HTTP {method} {url}",
                "raw_event_reference": {
                    "packet_number": packet_number,
                    "method": method,
                    "host": host,
                    "user_agent": user_agent,
                },
            })
        )
        self._feed_credentials(
            packet_number, packet, ip, src_port, dst_port, payload, is_http_request=True
        )

        # Queue for pairing with the response that comes back on this flow.
        self._pending.setdefault((ip.src, src_port, ip.dst, dst_port), deque()).append(
            (method, url)
        )

    def _feed_http_response(self, packet_number, packet, ip, src_port, dst_port, payload):
        first_line = payload[:512].split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
        parts = first_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return
        status_code = int(parts[1])
        reason = parts[2].strip() if len(parts) > 2 else ""

        # A response travels the reverse direction of its request's flow.
        # Pairing is FIFO per flow, which is correct for ordinary keep-alive
        # traffic; genuinely pipelined requests could mis-pair, so the URL is
        # recorded as a reference rather than treated as certain.
        queued = self._pending.get((ip.dst, dst_port, ip.src, src_port))
        method, url = queued.popleft() if queued else (None, None)

        self._emitted.append(
            self._event({
                "event_type": "http_response",
                "timestamp": _packet_timestamp(packet),
                "src_ip": ip.src,
                "src_port": src_port,
                "dst_ip": ip.dst,
                "dst_port": dst_port,
                "protocol": "tcp",
                "url": url,
                "message": f"HTTP {status_code} {reason}".strip() + (f" for {url}" if url else ""),
                "raw_event_reference": {
                    "packet_number": packet_number,
                    "status_code": status_code,
                    "reason": reason,
                    "request_method": method,
                    "request_url": url,
                },
            })
        )

    def _carve(self, packet_number, packet, ip, src_port, dst_port, payload):
        """Buffer TCP payloads only for streams whose opening bytes matched a
        file signature. Undecided streams hold at most SIGNATURE_SCAN_WINDOW
        bytes and streams that fail the check are dropped outright - without
        that, carving alone would buffer the entire capture in memory."""
        stream_key = f"{ip.src}:{src_port}->{ip.dst}:{dst_port}"
        stream = self._streams.get(stream_key)
        if stream is None:
            stream = self._streams[stream_key] = {
                "state": "undecided",
                "data": [],
                "size": 0,
                "packet_numbers": [],
                "first_timestamp": float(packet.time),
                "file_type": None,
                "truncated": False,
            }
        if stream["state"] == "skip":
            return

        stream["packet_numbers"].append(packet_number)
        if stream["size"] + len(payload) <= MAX_CARVE_BYTES_PER_STREAM:
            stream["data"].append(payload)
            stream["size"] += len(payload)
        else:
            stream["truncated"] = True

        if stream["state"] == "undecided":
            header = b"".join(stream["data"])[:SIGNATURE_SCAN_WINDOW]
            file_type = next((ext for ext, sig in FILE_SIGNATURES.items() if sig in header), None)
            if file_type:
                stream["state"] = "carving"
                stream["file_type"] = file_type
            elif len(header) >= SIGNATURE_SCAN_WINDOW:
                stream["state"] = "skip"
                stream["data"] = []
                stream["packet_numbers"] = []

    # --- materialization ---

    def _feed_credentials(
        self, packet_number, packet, ip, src_port, dst_port, payload, is_http_request=False
    ):
        """One event per credential seen crossing the network in the clear.

        THE SECRET ITSELF IS NEVER STORED - see parsers/credentials.py.
        The event carries a SHA-256 of it, which is what lets a later rule
        ask whether the same credential turned up on another protocol
        without the case database ever holding a working password.

        This engine used to emit nothing here, so CLEARTEXT-CREDENTIALS
        and CREDENTIAL-REUSE silently did not exist without Wireshark
        installed. Both engines now read the same rules from one module.
        """
        secrets, user = credentials.scan_payload(
            payload, dst_port=dst_port, is_http_request=is_http_request
        )
        if not secrets:
            return

        protocol = credentials.protocol_for(dst_port, "tcp")
        for field, value in secrets:
            self._emitted.append(
                self._event({
                    "event_type": "credential_exposure",
                    "timestamp": _packet_timestamp(packet),
                    "src_ip": ip.src,
                    "src_port": src_port,
                    "dst_ip": ip.dst,
                    "dst_port": dst_port,
                    "protocol": "tcp",
                    "user": user,
                    "severity": "high",
                    "message": credentials.message_for(field, protocol, user),
                    "raw_event_reference": credentials.reference_for(
                        packet_number, field, protocol, value, "scapy"
                    ),
                })
            )

    def _event(self, fields):
        return Event(
            event_id=generate_event_id(self.evidence_id, self.sequence.next()),
            evidence_id=self.evidence_id,
            source="pcap",
            **fields,
        )

    def _connection_events(self):
        events = []
        for key in self._flow_order:
            protocol, src_ip, src_port, dst_ip, dst_port = key
            flow = self._flows[key]
            message = flow["payload_preview"]
            if message is None:
                message = (
                    f"{flow['packet_count']} packet(s), {flow['byte_count']} bytes, "
                    "no application payload observed"
                )
            events.append(
                self._event(
                    {
                        "event_type": "network_connection",
                        "timestamp": datetime.fromtimestamp(flow["first_timestamp"], tz=timezone.utc),
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "message": message,
                        "raw_event_reference": {
                            "first_packet_number": flow["first_packet_number"],
                            "packet_count": flow["packet_count"],
                            "byte_count": flow["byte_count"],
                        },
                    }
                )
            )
        return events

    def _file_transfer_events(self):
        carving = [(k, v) for k, v in self._streams.items() if v["state"] == "carving"]
        if carving and self.output_dir is not None:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        events = []
        for stream_key, info in carving:
            full_data = b"".join(info["data"])
            file_type = info["file_type"]

            src, dst = stream_key.split("->")
            src_ip, src_port = src.rsplit(":", 1)
            dst_ip, dst_port = dst.rsplit(":", 1)
            file_name = f"{stream_key.replace(':', '_').replace('->', '_to_')}.{file_type}"

            stored_path = None
            if self.output_dir is not None:
                stored_path = self.output_dir / file_name
                stored_path.write_bytes(full_data)
                logger.info(f"Saved extracted file: {stored_path} ({len(full_data)} bytes)")

            truncated_note = " (truncated at the carve size limit)" if info["truncated"] else ""
            events.append(
                self._event(
                    {
                        "event_type": "file_transfer",
                        "timestamp": datetime.fromtimestamp(info["first_timestamp"], tz=timezone.utc),
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "dst_ip": dst_ip,
                        "dst_port": int(dst_port),
                        "protocol": "tcp",
                        "file_name": file_name,
                        "file_path": str(stored_path) if stored_path else None,
                        "file_hash": hashlib.sha256(full_data).hexdigest(),
                        "message": (
                            f"Detected embedded {file_type} file ({len(full_data)} bytes) in "
                            f"TCP stream {stream_key}{truncated_note}"
                        ),
                        "raw_event_reference": {
                            "packet_numbers": info["packet_numbers"],
                            "stream": stream_key,
                            "truncated": info["truncated"],
                        },
                    }
                )
            )
        return events

    def _anomaly_events(self):
        if self._anomaly_disabled or len(self._features) < 2:
            return []
        df = pd.DataFrame(self._features, columns=["size", "inter_arrival", "src_port", "dst_port"])
        model = IsolationForest(contamination=self.anomaly_contamination, random_state=42)
        predictions = model.fit_predict(df)

        events = []
        for is_anomalous, info in zip(predictions == -1, self._meta):
            if not is_anomalous:
                continue
            events.append(
                self._event(
                    {
                        "event_type": "anomaly",
                        "timestamp": datetime.fromtimestamp(info["timestamp"], tz=timezone.utc),
                        "src_ip": info["src_ip"],
                        "dst_ip": info["dst_ip"],
                        "src_port": info["src_port"],
                        "dst_port": info["dst_port"],
                        "severity": "medium",
                        "message": (
                            "Packet flagged as a statistical outlier (size/timing/port profile) "
                            "by IsolationForest."
                        ),
                        "raw_event_reference": {
                            "packet_number": info["packet_number"],
                            "size": info["size"],
                            "inter_arrival": info["inter_arrival"],
                        },
                    }
                )
            )
        return events

    def finish(self):
        """Events that can only be produced once the whole capture has been
        seen: per-flow summaries, carved files, and anomaly scoring."""
        return self._connection_events() + self._file_transfer_events() + self._anomaly_events()


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
        return list(
            self.iter_parse(
                file_path,
                evidence_id,
                output_dir=output_dir,
                anomaly_contamination=anomaly_contamination,
            )
        )

    def iter_parse(
        self,
        file_path,
        evidence_id,
        output_dir=None,
        anomaly_contamination=DEFAULT_ANOMALY_CONTAMINATION,
        **_ignored,
    ):
        """Yield Events as the capture is read, so a caller that writes them
        out incrementally never holds the whole set at once. This is the path
        the ingestion pipeline takes; parse() just materializes it for
        callers (and tests) that want a list."""
        collector = _StreamCollector(evidence_id, EventSequence(), output_dir, anomaly_contamination)
        emitted = 0
        for packet_number, packet in enumerate(_iter_packets(file_path), start=1):
            for event in collector.feed(packet_number, packet):
                emitted += 1
                yield event
        for event in collector.finish():
            emitted += 1
            yield event
        logger.info(f"Parsed {collector.packet_count:,} packets into {emitted:,} events")


# NOT registered here. parsers/pcap_engine.py owns the "pcap" registration
# and picks between this engine and the tshark one at parse time - see the
# module docstring there for why the choice has to live in one place. This
# module stays directly importable and directly usable (tests do exactly
# that) so the scapy engine can always be exercised on its own.
