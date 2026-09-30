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
  - credential_exposure: one per credential crossing the network in the
    clear, carrying a HASH of the secret rather than the secret.
  - file_access: SMB file opens/reads/writes, naming the share path that
    was touched.
  - file_transfer: files recovered by tshark's object export (HTTP, SMB,
    FTP-DATA, TFTP, IMF), hashed and written to the case's artifact dir.
  - anomaly: statistical outliers, same IsolationForest treatment the
    scapy engine applies, when pandas/scikit-learn are installed.
"""

import hashlib
import logging
import ntpath
import posixpath
import re
import tempfile
from collections import Counter
from datetime import datetime, timezone
from email.header import decode_header, make_header
from pathlib import Path
from urllib.parse import unquote

from netforensicai.core.artifacts import fs_path
from netforensicai.core.event import Event, EventSequence, generate_event_id
from netforensicai.integrations import wireshark
from netforensicai.parsers import base, credentials

logger = logging.getLogger(__name__)


class TsharkParseError(base.PcapReadError):
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
    # Credential material, as DISSECTED FIELDS rather than raw payload.
    # Asking tshark for the parsed form values and FTP arguments is both
    # cheaper and more precise than pulling every packet's bytes across
    # and pattern-matching here - and it keeps the parser from handling
    # payload it has no reason to hold.
    "urlencoded-form.key",
    "urlencoded-form.value",
    "http.authorization",
)

# Form field names that carry a secret rather than an identity.
# Re-exported from parsers/credentials.py, which both engines share. They
# were duplicated here once and the copies drifted - one engine grew
# credential detection and the other silently had none.
_SECRET_FIELDS = credentials.SECRET_FIELDS
_IDENTITY_FIELDS = credentials.IDENTITY_FIELDS

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

# Ports whose protocols authenticate without encrypting. A credential
# seen on one of these is disclosed, not merely at risk.
_CLEARTEXT_PROTOCOLS = credentials.CLEARTEXT_PROTOCOLS

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
        self._cred_flow = credentials.CredentialFlowState()
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
        events.extend(self._credential_events(layers, packet_number, common))
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

    def _credential_events(self, layers, packet_number, common):
        """One event per credential seen crossing the network in the clear.

        THE SECRET ITSELF IS NEVER STORED. The event carries a SHA-256 of
        it instead, which is enough for the one question that matters
        across events - "is this the same credential that was used
        somewhere else" - without putting a working password into the case
        database, where it would then ride along in every export, report
        and backup of that case. The plaintext stays in the evidence file,
        which is already hashed, read-only and reachable through search.
        """
        events = []

        keys = _all(layers, "urlencoded-form.key")
        values = _all(layers, "urlencoded-form.value")
        pairs = list(zip(keys, values))

        command = (_first(layers, "ftp.request.command") or "").upper()
        argument = _first(layers, "ftp.request.arg")
        if command in ("PASS", "USER") and argument:
            pairs.append(("password" if command == "PASS" else "username", argument))

        authorization = _first(layers, "http.authorization")
        if authorization:
            pairs.append(("authorization", authorization))

        user = credentials.identity_of(pairs)
        # FTP/Telnet/POP3 carry USER a packet before PASS; remember the
        # username per control flow so the password event gets it too.
        flow_key = (common.get("src_ip"), common.get("src_port"), common.get("dst_ip"), common.get("dst_port"))
        self._cred_flow.remember(flow_key, user)
        user = self._cred_flow.resolve(flow_key, user)

        for lowered, value in credentials.secrets_in(pairs):
            protocol = credentials.protocol_for(common.get("dst_port"), common.get("protocol"))
            events.append(
                self._event(
                    {
                        **common,
                        "event_type": "credential_exposure",
                        "user": user,
                        "severity": "high",
                        "message": credentials.message_for(lowered, protocol, user),
                        "raw_event_reference": credentials.reference_for(
                            packet_number, lowered, protocol, value, "tshark"
                        ),
                    }
                )
            )
        return events

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
                readable = _readable_export_name(exported.name)
                name = _export_name(exported.name, protocol)
                target_dir = output_dir / protocol
                try:
                    fs_path(target_dir).mkdir(parents=True, exist_ok=True)
                    destination = _unique_path(target_dir, name)
                    fs_path(destination).write_bytes(data)
                except OSError as e:
                    # One file that cannot be written must not discard the
                    # whole capture - the pipeline is all-or-nothing, so an
                    # exception here would throw away every event with it.
                    logger.warning(f"Could not save recovered {protocol} object '{name}': {e}")
                    continue
                logger.info(f"Exported {protocol} object: {destination} ({len(data)} bytes)")
                reference = {"export_protocol": protocol, "size": len(data), "engine": "tshark"}
                if destination.name != exported.name:
                    # Both forms: exactly what Wireshark reported, and the
                    # decoded text a person can read (an email's full subject).
                    reference["original_name"] = exported.name
                    reference["original_name_readable"] = readable
                events.append(
                    Event(
                        event_id=generate_event_id(evidence_id, sequence.next()),
                        evidence_id=evidence_id,
                        source="pcap",
                        event_type="file_transfer",
                        file_name=destination.name,
                        file_path=str(destination),
                        file_hash=hashlib.sha256(data).hexdigest(),
                        message=(
                            f"Recovered {len(data):,}-byte file '{destination.name}' from {protocol.upper()} "
                            "traffic via Wireshark object export"
                        ),
                        raw_event_reference=reference,
                    )
                )
    return events


def _readable_export_name(raw_name):
    """Wireshark's export name, percent- and MIME-decoded into plain text."""
    name = unquote(raw_name or "")
    if "=?" in name:
        try:
            name = str(make_header(decode_header(name)))
        except (ValueError, LookupError, UnicodeDecodeError) as e:
            # A malformed encoded-word (or an unknown charset) keeps the
            # percent-decoded form: still usable, just not pretty.
            logger.debug(f"Could not MIME-decode export name {name!r}: {e}")
    return name


_TSHARK_COPY_SUFFIX = re.compile(r"(\(\d+\))$")
_PATH_SEPARATORS = re.compile(r"\s*[\\/]+\s*")


def _export_name(raw_name, protocol):
    """A readable, safe file name for an object Wireshark exported.

    tshark names exports after what the protocol carried: a URL's last
    segment, an SMB path, or - for email (IMF) - the message subject,
    percent-escaped and often MIME-encoded ("=?utf-8?B?SGF3a0V5ZS...?="). Seen
    on a real HawkEye keylogger capture, that name ran to ~200 characters and
    pushed the path past Windows' limit, so the write failed and the whole
    capture was discarded. Decoding first also makes the name mean something
    ("HawkEye Keylogger - Reborn v9 - Passwords Logs ...").

    What the name IS differs by protocol. For email it is a subject, so the
    whole decoded subject is kept and any slash in it is just a character.
    For HTTP and SMB it is a URL or share path, so its last segment is the
    file name (the full path is kept in the event as original_name). An HTTP
    object at the site root ("/", which tshark writes as "%5c") is the
    site's index page; tshark's "(1)", "(2)" copy suffixes are kept.
    """
    name = _readable_export_name(raw_name)
    if protocol == "imf":
        # A subject, not a path: a slash or backslash in it is punctuation.
        name = _PATH_SEPARATORS.sub(" - ", name).strip(" -")
        if not name.lower().endswith(".eml"):
            name += ".eml"
    else:
        copy = _TSHARK_COPY_SUFFIX.search(name)
        suffix = copy.group(1) if copy else ""
        last = _PATH_SEPARATORS.split(name[: len(name) - len(suffix)])[-1].strip()
        name = (last or "index") + suffix
    return _safe_file_name(name, f"{protocol}-object.bin")


# Transfer commands and which side sends the file's bytes: the client for an
# upload, the server for a download.
_FTP_UPLOAD_COMMANDS = {"STOR", "APPE", "STOU"}
_FTP_DOWNLOAD_COMMANDS = {"RETR"}
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._ ()-]")


# Short enough that cases/<id>/artifacts/<EV>/<protocol>/<name> stays well
# inside Windows' 260-character path limit from a typical case location.
MAX_RECOVERED_NAME = 64


def _safe_file_name(name, fallback):
    """A name that is safe to create on disk: no directories, no traversal,
    no characters Windows rejects, and bounded in length with its extension
    kept. Evidence controls this string."""
    base = posixpath.basename(ntpath.basename((name or "").strip()))
    base = _UNSAFE_NAME.sub("_", base).strip(" .")
    if not base:
        return fallback
    if len(base) > MAX_RECOVERED_NAME:
        suffix = Path(base).suffix
        if len(suffix) > 10 or not suffix[1:].isalnum():
            suffix = ""
        base = base[: MAX_RECOVERED_NAME - len(suffix)].rstrip(" ._") + suffix
    return base


def _unique_path(directory, name):
    candidate = directory / name
    stem, suffix = Path(name).stem, Path(name).suffix
    n = 2
    while fs_path(candidate).exists():
        candidate = directory / f"{stem}-{n}{suffix}"
        n += 1
    return candidate


def _recover_ftp_transfers(file_path, output_dir, evidence_id, sequence):
    """Recover files moved over FTP when Wireshark's own exporter cannot.

    tshark's `--export-objects ftp-data` only names a data connection it can
    tie to a PASV/PORT negotiation. When that step is missing from the
    capture - it started mid-session, or the client used the default port 20
    data channel - the exporter recovers nothing, even though the control
    channel plainly says `STOR customers-export.csv` and the bytes are sitting
    in the data stream. This pairs them itself: each FTP data connection is
    matched to the most recent unused transfer command between the same two
    hosts that preceded it, and the file is read back byte-exact from that
    stream. Every recovered file says how it was recovered.
    """
    if output_dir is None:
        return []
    from netforensicai.core import streams

    commands = []
    for layers in wireshark.iter_dissected_packets(
        file_path,
        ["frame.number", "ip.src", "ip.dst", "ftp.request.command", "ftp.request.arg"],
        display_filter="ftp.request.command",
    ):
        command = (_first(layers, "ftp.request.command") or "").upper()
        if command in _FTP_UPLOAD_COMMANDS | _FTP_DOWNLOAD_COMMANDS:
            commands.append({
                "frame": int(_first(layers, "frame.number") or 0),
                "client": _first(layers, "ip.src"),
                "server": _first(layers, "ip.dst"),
                "command": command,
                "arg": _first(layers, "ftp.request.arg"),
                "used": False,
            })
    if not commands:
        return []

    data_streams = {}
    for layers in wireshark.iter_dissected_packets(
        file_path, ["frame.number", "tcp.stream", "ip.src", "ip.dst"], display_filter="ftp-data"
    ):
        stream = _first(layers, "tcp.stream")
        if stream is None or stream in data_streams:
            continue
        data_streams[stream] = {
            "frame": int(_first(layers, "frame.number") or 0),
            "hosts": {_first(layers, "ip.src"), _first(layers, "ip.dst")},
        }

    events = []
    target_dir = Path(output_dir) / "ftp-data"
    for stream, info in sorted(data_streams.items(), key=lambda item: item[1]["frame"]):
        candidates = [
            c for c in commands
            if not c["used"] and c["frame"] < info["frame"] and {c["client"], c["server"]} == info["hosts"]
        ]
        if not candidates:
            continue
        command = max(candidates, key=lambda c: c["frame"])
        command["used"] = True
        upload = command["command"] in _FTP_UPLOAD_COMMANDS
        sender, receiver = (command["client"], command["server"]) if upload else (command["server"], command["client"])
        try:
            payload = streams.stream_bytes(file_path, "tcp", stream)
        except streams.StreamError as e:
            logger.info(f"FTP data stream {stream} could not be read: {e}")
            continue
        # The side that sent the file is the one whose address matches; fall
        # back to whichever direction carried bytes.
        node_a_ip = (payload.node_a or "").rsplit(":", 1)[0].strip("[]")
        data = payload.a_to_b if node_a_ip == sender else payload.b_to_a
        data = data or payload.a_to_b or payload.b_to_a
        if not data:
            continue

        fs_path(target_dir).mkdir(parents=True, exist_ok=True)
        destination = _unique_path(target_dir, _safe_file_name(command["arg"], f"ftp-stream-{stream}.bin"))
        fs_path(destination).write_bytes(data)
        action = "uploaded" if upload else "downloaded"
        logger.info(f"Recovered FTP file: {destination} ({len(data)} bytes)")
        events.append(
            Event(
                event_id=generate_event_id(evidence_id, sequence.next()),
                evidence_id=evidence_id,
                source="pcap",
                event_type="file_transfer",
                src_ip=sender,
                dst_ip=receiver,
                protocol="FTP-DATA",
                file_name=destination.name,
                file_path=str(destination),
                file_hash=hashlib.sha256(data).hexdigest(),
                message=(
                    f"Recovered {len(data):,}-byte file '{destination.name}' {action} over FTP from {sender} "
                    f"to {receiver} ({command['command']} paired with its data connection, TCP stream {stream})"
                ),
                raw_event_reference={
                    "export_protocol": "ftp-data",
                    "size": len(data),
                    "engine": "tshark",
                    "recovered_by": "ftp-command-pairing",
                    "ftp_command": command["command"],
                    "ftp_argument": command["arg"],
                    "control_frame": command["frame"],
                    "stream": int(stream),
                    "truncated": payload.truncated,
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
    exported = _export_objects(file_path, output_dir, evidence_id, collector.sequence)
    for event in exported:
        emitted += 1
        yield event
    # Only when Wireshark's exporter found no FTP files itself: the two would
    # otherwise recover the same transfer twice.
    if not any((e.raw_event_reference or {}).get("export_protocol") == "ftp-data" for e in exported):
        try:
            recovered = _recover_ftp_transfers(file_path, output_dir, evidence_id, collector.sequence)
        except wireshark.WiresharkError as e:
            logger.info(f"FTP file recovery did not run: {e}")
            recovered = []
        for event in recovered:
            emitted += 1
            yield event

    logger.info(
        f"tshark engine parsed {collector.packet_count:,} packets into {emitted:,} events"
    )
