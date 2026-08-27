"""JSON/CSV -> normalized Event parsing.

Both formats are treated as arbitrary record evidence: each JSON array
element (or CSV row) becomes one Event. Common field-name variants (e.g.
"src_ip" / "source_ip" / "SourceIP" / "srcip") are mapped onto the Common
Event Model via case- and separator-insensitive aliasing - see
FIELD_ALIASES. A record's event_id,
evidence_id, and source are always assigned by this parser, never read
from the record itself, so evidence data can't spoof or collide with our
own traceability ids.

Fields with no matching alias in a given record are simply left unset
(see core/event.py for why that's correct rather than an error); nothing
outside the mapped fields is copied into the Event, since the immutable
stored evidence file plus each event's raw_event_reference (a record
index / row number) is enough to go back and see the full original
record when needed.
"""

import csv
import json
import logging
from pathlib import Path

from netforensicai.core.event import Event, EventSequence, generate_event_id, parse_timestamp
from netforensicai.parsers import base

logger = logging.getLogger(__name__)

FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "ts", "@timestamp", "event_time", "datetime"),
    "event_type": ("event_type", "type", "eventtype", "category"),
    "user": ("user", "username", "user_name", "account"),
    "hostname": ("hostname", "host", "computer", "computername"),
    "device": ("device", "device_id", "asset"),
    "src_ip": ("src_ip", "source_ip", "srcip", "src"),
    "src_port": ("src_port", "source_port", "srcport"),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "dstip", "dst"),
    "dst_port": ("dst_port", "dest_port", "destination_port", "dstport"),
    "protocol": ("protocol", "proto"),
    "process_name": ("process_name", "process", "image", "processname"),
    "process_id": ("process_id", "pid", "processid"),
    "parent_process": ("parent_process", "parentimage", "parent_process_name"),
    "command_line": ("command_line", "commandline", "cmd", "cmdline"),
    "file_name": ("file_name", "filename", "file"),
    "file_path": ("file_path", "filepath", "path", "targetfilename"),
    "file_hash": ("file_hash", "hash", "sha256", "md5"),
    "domain": ("domain", "domainname"),
    "url": ("url", "uri"),
    "severity": ("severity", "level", "priority"),
    "message": ("message", "msg", "description", "summary"),
}

INT_FIELDS = {"src_port", "dst_port", "process_id"}
DEFAULT_EVENT_TYPE = "unknown"
# Common wrapper keys for a JSON object containing an array of records,
# e.g. {"events": [...]} - checked in this order.
WRAPPER_KEYS = ("events", "records", "data", "logs")


class NormalizationError(Exception):
    """Raised when a JSON/CSV evidence file can't be read or isn't record-shaped."""


def _normalize_key(key):
    """Lowercase and strip separators so "src_ip", "srcip", and "SourceIP"
    style aliases ("source_ip" -> "sourceip") all compare equal."""
    return str(key).lower().replace("_", "").replace("-", "").replace(" ", "")


def _normalized_lookup(record):
    return {_normalize_key(k): k for k in record.keys()}


def _extract_field(record, lookup, canonical_field):
    for alias in FIELD_ALIASES[canonical_field]:
        original_key = lookup.get(_normalize_key(alias))
        if original_key is not None:
            value = record[original_key]
            if value not in (None, ""):
                return value
    return None


def _coerce_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_record(record, evidence_id, sequence, source, raw_event_reference):
    """Map one arbitrary record dict onto an Event via case-insensitive field aliasing."""
    lookup = _normalized_lookup(record)
    fields = {}
    for canonical_field in FIELD_ALIASES:
        value = _extract_field(record, lookup, canonical_field)
        if value is None:
            continue
        if canonical_field == "timestamp":
            fields["timestamp"] = parse_timestamp(value)
        elif canonical_field in INT_FIELDS:
            fields[canonical_field] = _coerce_int(value)
        else:
            fields[canonical_field] = str(value)

    fields.setdefault("event_type", DEFAULT_EVENT_TYPE)

    return Event(
        event_id=generate_event_id(evidence_id, sequence.next()),
        evidence_id=evidence_id,
        source=source,
        raw_event_reference=raw_event_reference,
        **fields,
    )


def _load_json_records(path):
    try:
        raw_text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise NormalizationError(f"Failed to read JSON file '{path}': {e}") from e
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise NormalizationError(f"Invalid JSON in '{path}': {e}") from e

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = next((data[k] for k in WRAPPER_KEYS if isinstance(data.get(k), list)), None)
        if records is None:
            records = [data]
    else:
        raise NormalizationError(
            f"JSON evidence must be an array of records or an object containing one "
            f"(got {type(data).__name__})"
        )

    for i, record in enumerate(records):
        if not isinstance(record, dict):
            raise NormalizationError(f"JSON record at index {i} is not an object: {record!r}")
    return records


def _load_csv_records(path):
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except OSError as e:
        raise NormalizationError(f"Failed to read CSV file '{path}': {e}") from e


class JsonParser(base.BaseParser):
    evidence_types = ("json",)

    def parse(self, file_path, evidence_id, **_ignored):
        records = _load_json_records(file_path)
        sequence = EventSequence()
        return [
            normalize_record(
                record, evidence_id, sequence, source="json", raw_event_reference={"record_index": i}
            )
            for i, record in enumerate(records)
        ]


class CsvParser(base.BaseParser):
    evidence_types = ("csv",)

    def parse(self, file_path, evidence_id, **_ignored):
        records = _load_csv_records(file_path)
        sequence = EventSequence()
        return [
            normalize_record(
                record, evidence_id, sequence, source="csv", raw_event_reference={"row_number": i + 1}
            )
            for i, record in enumerate(records)
        ]


base.register(JsonParser())
base.register(CsvParser())
