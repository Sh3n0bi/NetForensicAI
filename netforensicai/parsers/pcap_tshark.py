"""PCAP -> normalized Event parsing, using tshark as the dissection engine.

This is the same contract as parsers/pcap.py - stream a capture file,
yield Events - with Wireshark's dissectors doing the protocol work instead
of hand-written scapy analyses. It exists because the two engines fail in
opposite directions, and a DFIR platform wants whichever one the machine
can actually offer:

  scapy (parsers/pcap.py)  Pure Python, no external binary, works from a
                           plain `pip install`, and can synthesize the pcap
                           fixtures this repo's tests are built from. But it
                           only knows the seven analyses written by hand
                           there, so an SMB file write or a Kerberos
                           pre-auth failure in the evidence is invisible.

  tshark (this module)     Wireshark's ~3000 dissectors, so protocols
                           nobody hand-wrote support for still produce
                           events, and object export recovers real
                           transferred files rather than magic-byte
                           guesses. Needs Wireshark installed.

Neither is a superset, so neither is hardcoded: PcapParser picks tshark
when it is present and falls back to scapy when it isn't, and `--engine`
pins either one when an investigation needs a specific, reproducible
dissection (see parsers/pcap.py).

STREAMING, for the same reason the scapy parser streams: real captures are
routinely gigabytes, and holding a fully dissected copy in memory is not
an option. Per-packet events are yielded as tshark emits them; only the
running per-flow state is held.

Event types produced:
  - network_connection: one per distinct flow (protocol, src, dst),
    summarizing packet and byte counts, with Wireshark's own protocol
    stack (frame.protocols) recorded so an analyst can see that a flow was
    e.g. `eth:ip:tcp:tls:http2` without re-opening the capture.
  - dns_query / dns_response: one per DNS query and per response, with the
    queried name in `domain` and any resolved addresses in the message.
    Split into two event types to match the scapy engine exactly - the
    Common Event Model must mean the same thing whichever engine produced
    it, or a timeline filter and a detection rule change behaviour
    depending on whether the analyst had Wireshark installed.
  - http_request / http_response: request line and status line, paired by
    tshark's own stream index rather than by our own reassembly.
  - tls_handshake: one per ClientHello, SNI hostname in `domain`.
  - authentication: Kerberos and NTLM authentication attempts - the class
    of evidence the scapy engine cannot see at all, and the one lateral
    movement is usually found in.
  - file_access: SMB file opens/reads/writes, naming the share path that
    was touched.
  - file_transfer: files recovered by tshark's object export (HTTP, SMB,
    FTP-DATA, TFTP, IMF), hashed and written to the case's artifact dir.
  - anomaly: statistical outliers, same IsolationForest treatment the
    scapy engine applies, when pandas/scikit-learn are installed.
"""

import hashlib
import logging
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from netforensicai.core.event import Event, EventSequence, generate_event_id
from netforensicai.integrations import wireshark

logger = logging.getLogger(__name__)


class TsharkParseError(Exception):
    """Raised when tshark cannot read a capture file."""


# Fields requested from tshark, in dotted display-filter form. Kept
# explicit rather than dumping every dissected field (-T ek with no -e):
# a full dissection of one packet can be hundreds of fields and megabytes
# of JSON, which would make the JSON decode, not the dissection, the
# bottleneck on a large capture.
FIELDS = (
    # Frame
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "_ws.col.protocol",
    "_ws.col.info",
    # Network / transport
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "icmpv6.type",
    # DNS
    "dns.qry.name",
    "dns.flags.response",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    # HTTP
    "http.request.method",
    "http.request.full_uri",
    "http.host",
    "http.user_agent",
    "http.response.code",
    "http.response.phrase",
    # TLS
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    # Authentication - Kerberos and NTLM
    "kerberos.CNameString",
    "kerberos.realm",
    "kerberos.msg_type",
    "ntlmssp.auth.username",
    "ntlmssp.auth.domain",
    "ntlmssp.auth.hostname",
    # SMB
    "smb2.filename",
    "smb.file",
    # Other identity-bearing protocols
    "dhcp.option.hostname",
    "ftp.request.command",
    "ftp.request.arg",
    "smtp.req.parameter",
)

# tshark's object-export dissectors. Each recovers complete transferred
# files from reassembled streams - which is categorically better evidence
# than the scapy engine's magic-byte carving, because the dissector knows
# where the object actually begins and ends rather than inferring it.
EXPORT_OBJECT_PROTOCOLS = ("http", "smb", "ftp-data", "tftp", "imf")

# Mirrors the scapy engine's threshold and rate, deliberately duplicated
# rather than imported: importing parsers/pcap.py would pull in scapy, and
# the entire point of this engine is that it works on a machine where
# scapy is not installed. The reasoning for the cap is the same - a
# fixed-proportion detector on a large capture reports a fixed percentage
# of everything by construction, which is noise, not signal.
DEFAULT_ANOMALY_CONTAMINATION = 0.05
MAX_PACKETS_FOR_ANOMALY_DETECTION = 20_000

PROGRESS_LOG_EVERY_PACKETS = 25_000

_TLS_CLIENT_HELLO = "1"
_DNS_RESPONSE = "True"


def _first(layers, field):
    """tshark's -T ek gives every field as a list, since a field can occur
    more than once in a packet (two DNS answers, two HTTP headers). This
    takes the first occurrence, which is the right one for the identifying
    fields; _all() is used where the rest matter."""
    values = layers.get(field.replace(".", "_"))
    if not values:
        return None
    if isinstance(values, list):
        return values[0] if values else None
    return values


def _all(layers, field):
    values = layers.get(field.replace(".", "_"))
    if values is None:
        return []
    return values if isinstance(values, list) else [values]


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _port(value):
    """Ports go into a pydantic field bounded to 0-65535, so an
    unparseable or out-of-range value has to become None rather than
    failing the whole parse - a malformed packet must not cost the
    analyst every other event in the capture."""
    port = _int(value)
    return port if port is not None and 0 <= port <= 65535 else None


def _timestamp(layers):
    raw = _first(layers, "frame.time_epoch")
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _endpoints(layers):
    """(src_ip, dst_ip, src_port, dst_port, transport) for a packet.

    IPv4 and IPv6 are checked in that order and ports are read from
    whichever of tcp/udp is present, so a v6 flow produces the same shape
    of event as a v4 one - the scapy engine had to grow IPv6 support as a
    fix, and getting it right up front here avoids the same gap.
    """
    src_ip = _first(layers, "ip.src") or _first(layers, "ipv6.src")
    dst_ip = _first(layers, "ip.dst") or _first(layers, "ipv6.dst")

    src_port = _port(_first(layers, "tcp.srcport"))
    dst_port = _port(_first(layers, "tcp.dstport"))
    transport = "tcp" if src_port is not None or dst_port is not None else None
    if transport is None:
        src_port = _port(_first(layers, "udp.srcport"))
        dst_port = _port(_first(layers, "udp.dstport"))
        transport = "udp" if src_port is not None or dst_port is not None else None

    return src_ip, dst_ip, src_port, dst_port, transport


class _TsharkCollector:
    """Per-packet event emission plus the running state needed for the
    end-of-capture summaries. One instance per parse run."""

    def __init__(self, evidence_id, sequence, anomaly_contamination):
        self.evidence_id = evidence_id
        self.sequence = sequence
        self.anomaly_contamination = anomaly_contamination

        self.packet_count = 0
        self._flows = {}
        self._pending_requests = {}
        self._features = []
        self._meta = []
        self._anomaly_disabled = False
        self._previous_timestamp = None

    def _event(self, fields):
        return Event(
            event_id=generate_event_id(self.evidence_id, self.sequence.next()),
            evidence_id=self.evidence_id,
            source="pcap",
            **fields,
        )

    def feed(self, layers):
        self.packet_count += 1
        if self.packet_count % PROGRESS_LOG_EVERY_PACKETS == 0:
            logger.info(f"tshark engine: dissected {self.packet_count:,} packets")

        packet_number = _int(_first(layers, "frame.number")) or self.packet_count
        timestamp = _timestamp(layers)
        src_ip, dst_ip, src_port, dst_port, transport = _endpoints(layers)
        length = _int(_first(layers, "frame.len")) or 0

        self._track_flow(layers, src_ip, dst_ip, src_port, dst_port, transport, timestamp, length, packet_number)
        self._track_anomaly_features(timestamp, length, src_port, dst_port, src_ip, dst_ip, packet_number)

        common = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": transport,
        }

        events = []
        events.extend(self._dns_events(layers, packet_number, common))
        events.extend(self._http_events(layers, packet_number, common))
        events.extend(self._tls_events(layers, packet_number, common))
        events.extend(self._authentication_events(layers, packet_number, common))
        events.extend(self._smb_events(layers, packet_number, common))
        return events

    # --- per-packet analyses ---

    def _dns_events(self, layers, packet_number, common):
        name = _first(layers, "dns.qry.name")
        if not name:
            return []
        is_response = _first(layers, "dns.flags.response") == _DNS_RESPONSE
        answers = _all(layers, "dns.a") + _all(layers, "dns.aaaa") + _all(layers, "dns.cname")
        if is_response:
            message = f"DNS response for {name}"
            message += f" -> {', '.join(answers)}" if answers else " with no answer records"
        else:
            message = f"DNS query for {name}"
        return [
            self._event(
                {
                    **common,
                    # Responses are their own event type, matching the scapy
                    # engine. The Common Event Model must not shift meaning
                    # with the engine: folding responses into dns_query here
                    # would make `timeline show --type dns_response` return
                    # nothing on a case parsed with tshark, and silently
                    # change what a detection rule keyed on it matches.
                    "event_type": "dns_response" if is_response else "dns_query",
                    "domain": name,
                    "message": message,
                    "raw_event_reference": {
                        "packet_number": packet_number,
                        "answers": answers or None,
                        "engine": "tshark",
                    },
                }
            )
        ]

    def _http_events(self, layers, packet_number, common):
        events = []
        method = _first(layers, "http.request.method")
        if method:
            uri = _first(layers, "http.request.full_uri")
            host = _first(layers, "http.host")
            user_agent = _first(layers, "http.user_agent")
            # Keyed on the flow rather than on a reassembled stream of our
            # own, so the status code can be attached to the request it
            # answered - the difference between "an attacker requested
            # 40,000 paths" and "which of them existed".
            self._pending_requests[self._response_key(common)] = uri
            message = f"HTTP {method} {uri or ''}".strip()
            if user_agent:
                message += f" (User-Agent: {user_agent})"
            events.append(
                self._event(
                    {
                        **common,
                        "event_type": "http_request",
                        "domain": host,
                        "url": uri,
                        "message": message,
                        "raw_event_reference": {
                            "packet_number": packet_number,
                            "method": method,
                            "user_agent": user_agent,
                            "engine": "tshark",
                        },
                    }
                )
            )

        status = _first(layers, "http.response.code")
        if status:
            # The response travels the opposite direction from the request,
            # so look it up under the reversed tuple.
            uri = self._pending_requests.pop(self._request_key(common), None)
            phrase = _first(layers, "http.response.phrase") or ""
            events.append(
                self._event(
                    {
                        **common,
                        "event_type": "http_response",
                        "url": uri,
                        "message": f"HTTP {status} {phrase}".strip() + (f" for {uri}" if uri else ""),
                        "raw_event_reference": {
                            "packet_number": packet_number,
                            "status_code": _int(status),
                            "engine": "tshark",
                        },
                    }
                )
            )
        return events

    @staticmethod
    def _response_key(common):
        return (common["src_ip"], common["src_port"], common["dst_ip"], common["dst_port"])

    @staticmethod
    def _request_key(common):
        return (common["dst_ip"], common["dst_port"], common["src_ip"], common["src_port"])

    def _tls_events(self, layers, packet_number, common):
        if _TLS_CLIENT_HELLO not in _all(layers, "tls.handshake.type"):
            return []
        sni = _first(layers, "tls.handshake.extensions_server_name")
        return [
            self._event(
                {
                    **common,
                    "event_type": "tls_handshake",
                    "domain": sni,
                    "message": (
                        f"TLS ClientHello for {sni}"
                        if sni
                        else "TLS ClientHello with no SNI extension"
                    ),
                    "raw_event_reference": {
                        "packet_number": packet_number,
                        "sni": sni,
                        "engine": "tshark",
                    },
                }
            )
        ]

    def _authentication_events(self, layers, packet_number, common):
        """Kerberos and NTLM attempts.

        This event type is the reason the tshark engine is worth having.
        Lateral movement is authentication traffic, and the scapy engine
        produces no authentication events at all - a Kerberoasting run or
        a pass-the-hash attempt shows up there only as an unremarkable TCP
        flow to port 88 or 445.
        """
        events = []

        principal = _first(layers, "kerberos.CNameString")
        if principal:
            realm = _first(layers, "kerberos.realm")
            events.append(
                self._event(
                    {
                        **common,
                        "event_type": "authentication",
                        "user": principal,
                        "domain": realm,
                        "message": (
                            f"Kerberos authentication for {principal}"
                            + (f"@{realm}" if realm else "")
                            + f": {_first(layers, '_ws.col.info') or ''}"
                        ).strip(),
                        "raw_event_reference": {
                            "packet_number": packet_number,
                            "protocol": "kerberos",
                            "message_type": _first(layers, "kerberos.msg_type"),
                            "engine": "tshark",
                        },
                    }
                )
            )

        username = _first(layers, "ntlmssp.auth.username")
        if username:
            ntlm_domain = _first(layers, "ntlmssp.auth.domain")
            hostname = _first(layers, "ntlmssp.auth.hostname")
            events.append(
                self._event(
                    {
                        **common,
                        "event_type": "authentication",
                        "user": username,
                        "hostname": hostname,
                        "message": (
                            "NTLM authentication as "
                            + (f"{ntlm_domain}\\{username}" if ntlm_domain else username)
                            + (f" from {hostname}" if hostname else "")
                        ),
                        "raw_event_reference": {
                            "packet_number": packet_number,
                            "protocol": "ntlmssp",
                            "domain": ntlm_domain,
                            "engine": "tshark",
                        },
                    }
                )
            )
        return events

    def _smb_events(self, layers, packet_number, common):
        file_name = _first(layers, "smb2.filename") or _first(layers, "smb.file")
        if not file_name:
            return []
        return [
            self._event(
                {
                    **common,
                    "event_type": "file_access",
                    "file_name": Path(str(file_name).replace("\\", "/")).name,
                    "file_path": str(file_name),
                    "message": f"SMB access to {file_name}: {_first(layers, '_ws.col.info') or ''}".strip(),
                    "raw_event_reference": {
                        "packet_number": packet_number,
                        "protocol": "smb",
                        "engine": "tshark",
                    },
                }
            )
        ]

    # --- running state for end-of-capture summaries ---

    def _track_flow(self, layers, src_ip, dst_ip, src_port, dst_port, transport, timestamp, length, packet_number):
        if not src_ip or not dst_ip:
            return
        key = (transport or "ip", src_ip, src_port, dst_ip, dst_port)
        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows[key] = {
                "packets": 0,
                "bytes": 0,
                "first_timestamp": timestamp,
                "last_timestamp": timestamp,
                "first_packet_number": packet_number,
                "protocol_stacks": Counter(),
                "application": Counter(),
            }
        flow["packets"] += 1
        flow["bytes"] += length
        flow["last_timestamp"] = timestamp or flow["last_timestamp"]
        stack = _first(layers, "frame.protocols")
        if stack:
            flow["protocol_stacks"][stack] += 1
        application = _first(layers, "_ws.col.protocol")
        if application:
            flow["application"][application] += 1

    def _track_anomaly_features(self, timestamp, length, src_port, dst_port, src_ip, dst_ip, packet_number):
        if self._anomaly_disabled:
            return
        if len(self._features) >= MAX_PACKETS_FOR_ANOMALY_DETECTION:
            self._anomaly_disabled = True
            self._features = []
            self._meta = []
            logger.info(
                "Anomaly detection disabled: capture exceeds "
                f"{MAX_PACKETS_FOR_ANOMALY_DETECTION:,} packets, where a fixed-proportion "
                "detector reports a fixed percentage of everything by construction."
            )
            return
        epoch = timestamp.timestamp() if timestamp else None
        inter_arrival = 0.0
        if epoch is not None and self._previous_timestamp is not None:
            inter_arrival = max(0.0, epoch - self._previous_timestamp)
        if epoch is not None:
            self._previous_timestamp = epoch
        self._features.append([length, inter_arrival, src_port or 0, dst_port or 0])
        self._meta.append(
            {
                "packet_number": packet_number,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "size": length,
                "inter_arrival": inter_arrival,
            }
        )

    # --- end-of-capture summaries ---

    def _connection_events(self):
        events = []
        for (transport, src_ip, src_port, dst_ip, dst_port), flow in self._flows.items():
            stack = flow["protocol_stacks"].most_common(1)
            application = flow["application"].most_common(1)
            label = application[0][0] if application else (transport or "ip").upper()
            events.append(
                self._event(
                    {
                        "event_type": "network_connection",
                        "timestamp": flow["first_timestamp"],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": transport if transport in ("tcp", "udp") else None,
                        "message": (
                            f"{label} flow {src_ip}:{src_port} -> {dst_ip}:{dst_port} - "
                            f"{flow['packets']:,} packets, {flow['bytes']:,} bytes"
                        ),
                        "raw_event_reference": {
                            "packet_number": flow["first_packet_number"],
                            "packet_count": flow["packets"],
                            "byte_count": flow["bytes"],
                            # Wireshark's own view of what this flow was,
                            # e.g. "eth:ethertype:ip:tcp:tls:http2" - the
                            # detail that makes an unfamiliar flow
                            # identifiable without reopening the capture.
                            "protocol_stack": stack[0][0] if stack else None,
                            "engine": "tshark",
                        },
                    }
                )
            )
        return events

    def _anomaly_events(self):
        if self._anomaly_disabled or len(self._features) < 2:
            return []
        try:
            import pandas as pd
            from sklearn.ensemble import IsolationForest
        except ImportError:
            # Expected whenever tshark is available but the [pcap] extra
            # is not: the analyst still gets every dissected event, just
            # without the statistical pass.
            logger.info(
                "Skipping anomaly detection: pandas/scikit-learn are not installed "
                "(install the [pcap] extra to enable it)."
            )
            return []

        frame = pd.DataFrame(self._features, columns=["size", "inter_arrival", "src_port", "dst_port"])
        model = IsolationForest(contamination=self.anomaly_contamination, random_state=42)
        predictions = model.fit_predict(frame)

        events = []
        for is_anomalous, info in zip(predictions == -1, self._meta):
            if not is_anomalous:
                continue
            events.append(
                self._event(
                    {
                        "event_type": "anomaly",
                        "timestamp": info["timestamp"],
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
                            "engine": "tshark",
                        },
                    }
                )
            )
        return events

    def finish(self):
        return self._connection_events() + self._anomaly_events()


def _export_objects(file_path, output_dir, evidence_id, sequence):
    """Recover transferred files using tshark's object-export dissectors.

    A second pass over the capture, one per protocol. That is deliberate:
    export is off the streaming path entirely, so the memory profile of
    the main parse is unaffected, and a protocol whose export fails (an
    unsupported dissector on an older tshark) costs only that protocol
    rather than the whole parse.

    Yields file_transfer Events. If output_dir is None the export is
    skipped rather than written somewhere temporary - nothing should
    materialize evidence-derived files outside the case directory.
    """
    if output_dir is None:
        return []

    output_dir = Path(output_dir)
    events = []

    for protocol in EXPORT_OBJECT_PROTOCOLS:
        # Export into a staging directory per protocol so files recovered
        # from different protocols with the same name cannot overwrite each
        # other before they have been hashed and recorded.
        with tempfile.TemporaryDirectory(prefix=f"netforensic_export_{protocol}_") as staging:
            try:
                exported_files = wireshark.export_objects(file_path, protocol, staging)
            except wireshark.WiresharkError as e:
                logger.info(f"Object export for '{protocol}' did not run: {e}")
                continue

            for exported in exported_files:
                data = exported.read_bytes()
                if not data:
                    continue
                destination = output_dir / protocol / exported.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                logger.info(f"Exported {protocol} object: {destination} ({len(data)} bytes)")
                events.append(
                    Event(
                        event_id=generate_event_id(evidence_id, sequence.next()),
                        evidence_id=evidence_id,
                        source="pcap",
                        event_type="file_transfer",
                        file_name=exported.name,
                        file_path=str(destination),
                        file_hash=hashlib.sha256(data).hexdigest(),
                        message=(
                            f"Recovered {len(data):,}-byte file '{exported.name}' from {protocol.upper()} "
                            "traffic via Wireshark object export"
                        ),
                        raw_event_reference={
                            "export_protocol": protocol,
                            "size": len(data),
                            "engine": "tshark",
                        },
                    )
                )
    return events


def iter_parse(
    file_path,
    evidence_id,
    output_dir=None,
    anomaly_contamination=DEFAULT_ANOMALY_CONTAMINATION,
    display_filter=None,
):
    """Yield Events from a capture file, dissected by tshark.

    display_filter, when given, restricts the parse to matching packets -
    which is how the display-filter workflow ingests a focused subset of a
    very large capture without first carving a slice of it.
    """
    if not wireshark.available():
        raise TsharkParseError("tshark is not installed.")

    collector = _TsharkCollector(evidence_id, EventSequence(), anomaly_contamination)
    emitted = 0
    try:
        for layers in wireshark.iter_dissected_packets(
            file_path, FIELDS, display_filter=display_filter
        ):
            for event in collector.feed(layers):
                emitted += 1
                yield event
    except wireshark.WiresharkError as e:
        raise TsharkParseError(f"Failed to read pcap file '{file_path}': {e}") from e

    for event in collector.finish():
        emitted += 1
        yield event
    for event in _export_objects(file_path, output_dir, evidence_id, collector.sequence):
        emitted += 1
        yield event

    logger.info(
        f"tshark engine parsed {collector.packet_count:,} packets into {emitted:,} events"
    )
