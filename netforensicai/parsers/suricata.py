"""Parser for Suricata `eve.json` — the JSON event log Suricata (and many
Zeek-adjacent NSM setups) already produce.

eve.json is JSON *Lines*: one JSON object per line, each with an
`event_type` (alert / dns / http / tls / flow / fileinfo / ...) and a
nested object of the same name. That shape, and the security-relevant
fields inside it, are what the generic JSON parser cannot map - so this
maps them onto the Common Event Model (core/event.py) instead, the same
way the pcap parser maps protocol layers.

Suricata files carry a `.json` extension, so they are routed here by
content, not extension: core/evidence.py sniffs the first line and, when
it is a Suricata event, records the evidence type as "suricata" rather
than "json" (see is_suricata_eve).
"""

import json

from netforensicai.core.event import Event, EventSequence, generate_event_id, parse_timestamp
from netforensicai.parsers import base

SOURCE = "suricata"

# The event_type values Suricata emits that we map to normalized events.
# Others (stats, netflow, ikev2, ...) are skipped rather than turned into
# noise; the raw file is still preserved in evidence storage.
SUPPORTED_EVENT_TYPES = frozenset(
    {"alert", "dns", "http", "tls", "flow", "fileinfo", "anomaly", "ssh", "smtp"}
)
# Anything in this wider set marks a file as Suricata during detection,
# even when the very first line is a type we do not map.
KNOWN_EVENT_TYPES = SUPPORTED_EVENT_TYPES | frozenset(
    {"stats", "netflow", "ikev2", "krb5", "dhcp", "snmp", "rdp", "sip", "drop", "flow_start"}
)


def is_suricata_eve(path, sniff_lines=5):
    """True if `path` looks like a Suricata eve.json (JSON Lines with a
    Suricata-shaped record). Cheap: reads at most a few lines and never
    raises - a detection helper must not be the thing that fails an add."""
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            for _ in range(sniff_lines):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                # A JSON array is not eve.json (that is JSON Lines).
                if line[0] != "{":
                    return False
                try:
                    record = json.loads(line)
                except ValueError:
                    return False
                if isinstance(record, dict) and record.get("event_type") in KNOWN_EVENT_TYPES:
                    return True
                return False
    except (OSError, UnicodeDecodeError):
        return False
    return False


def _iter_records(path):
    """Yield parsed JSON objects, one per non-blank line. A malformed line is
    skipped rather than failing the whole file (a truncated final line from a
    still-writing Suricata is the common case)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _common_fields(record):
    """Network 5-tuple and timing shared by every eve event. Suricata names
    the destination `dest_ip`/`dest_port`, not `dst_*`."""
    fields = {
        "timestamp": parse_timestamp(record["timestamp"]) if record.get("timestamp") else None,
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dest_ip"),
        "src_port": _int(record.get("src_port")),
        "dst_port": _int(record.get("dest_port")),
        "protocol": (record.get("proto") or "").lower() or None,
    }
    return {k: v for k, v in fields.items() if v is not None}


def _map_alert(record, fields):
    alert = record.get("alert") or {}
    signature = alert.get("signature") or "Suricata alert"
    category = alert.get("category")
    fields["event_type"] = "alert"
    fields["message"] = f"{signature}" + (f" [{category}]" if category else "")
    sev = alert.get("severity")
    if sev is not None:
        # Suricata severity is 1 (most severe) .. 3+; map to the words used
        # elsewhere so it sorts and colours like other findings.
        fields["severity"] = {1: "High", 2: "Medium", 3: "Low"}.get(sev, "Low")
    return fields


def _map_dns(record, fields):
    dns = record.get("dns") or {}
    rrname = dns.get("rrname")
    if not rrname:
        queries = dns.get("queries") or []
        if queries and isinstance(queries[0], dict):
            rrname = queries[0].get("rrname")
    is_answer = dns.get("type") == "answer"
    fields["event_type"] = "dns_response" if is_answer else "dns_query"
    if rrname:
        fields["domain"] = rrname
        fields["message"] = f"DNS {'response for' if is_answer else 'query for'} {rrname}"
    return fields


def _map_http(record, fields):
    http = record.get("http") or {}
    host = http.get("hostname")
    url = http.get("url")
    method = http.get("http_method")
    status = http.get("status")
    fields["event_type"] = "http_request"
    if host:
        fields["domain"] = host
    if host and url:
        fields["url"] = f"http://{host}{url}"
    parts = [p for p in (method, (f"http://{host}{url}" if host and url else url)) if p]
    if status:
        parts.append(f"-> {status}")
    fields["message"] = "HTTP " + " ".join(str(p) for p in parts) if parts else "HTTP request"
    return fields


def _map_tls(record, fields):
    tls = record.get("tls") or {}
    sni = tls.get("sni")
    fields["event_type"] = "tls_handshake"
    if sni:
        fields["domain"] = sni
        fields["message"] = f"TLS ClientHello for {sni}"
    else:
        fields["message"] = "TLS handshake"
    return fields


def _map_flow(record, fields):
    fields["event_type"] = "network_connection"
    proto = fields.get("protocol", "")
    src = fields.get("src_ip", "?")
    dst = fields.get("dst_ip", "?")
    fields["message"] = f"{proto or 'flow'} {src} -> {dst}".strip()
    return fields


def _map_fileinfo(record, fields):
    info = record.get("fileinfo") or {}
    filename = info.get("filename")
    fields["event_type"] = "file_transfer"
    if filename:
        fields["file_name"] = filename
    if info.get("sha256"):
        fields["file_hash"] = info["sha256"]
    fields["message"] = f"File transfer: {filename}" if filename else "File transfer"
    return fields


def _map_anomaly(record, fields):
    anomaly = record.get("anomaly") or {}
    fields["event_type"] = "anomaly"
    fields["message"] = anomaly.get("event") or anomaly.get("type") or "Suricata anomaly"
    return fields


def _map_generic(record, fields):
    et = record.get("event_type") or "unknown"
    fields["event_type"] = et
    fields["message"] = f"Suricata {et} event"
    return fields


_MAPPERS = {
    "alert": _map_alert,
    "dns": _map_dns,
    "http": _map_http,
    "tls": _map_tls,
    "flow": _map_flow,
    "fileinfo": _map_fileinfo,
    "anomaly": _map_anomaly,
    "ssh": _map_generic,
    "smtp": _map_generic,
}


class SuricataParser(base.BaseParser):
    evidence_types = ("suricata",)

    def parse(self, file_path, evidence_id, **_ignored):
        sequence = EventSequence()
        events = []
        for line_number, record in enumerate(_iter_records(file_path), start=1):
            event_type = record.get("event_type")
            if event_type not in SUPPORTED_EVENT_TYPES:
                continue
            fields = _common_fields(record)
            fields = _MAPPERS[event_type](record, fields)
            events.append(
                Event(
                    event_id=generate_event_id(evidence_id, sequence.next()),
                    evidence_id=evidence_id,
                    source=SOURCE,
                    raw_event_reference={"line_number": line_number, "eve_event_type": event_type},
                    **fields,
                )
            )
        return events


base.register(SuricataParser())
