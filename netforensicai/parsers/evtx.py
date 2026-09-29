"""EVTX (Windows Event Log) -> normalized Event parsing.

Uses python-evtx (pure Python, no system dependency - reading .evtx files
needs no Windows API, so evidence collected from a Windows machine can be
parsed on any platform) to read the binary chunked .evtx file format,
then maps each record's XML into an Event.

Windows Event Log records vary hugely by provider - there is no single
schema. Three tiers of mapping:
  - Sysmon (Microsoft-Windows-Sysmon/Operational): well-known EventData
    field names per EventID (SYSMON_EVENT_TYPES below) map onto rich
    Common Event Model fields (process/network/file details). Only the
    handful of most common Sysmon event types are covered - adding more
    (registry, pipe, WMI, etc.) follows the same SYSMON_FIELD_MAP pattern.
  - Security / System / PowerShell: the event IDs incidents are worked
    from (logons, process creation, account/group changes, Kerberos/NTLM,
    service installs, log clearing, script blocks) get named event types
    and real fields - see parsers/windows_events.py.
  - Everything else (Application, and any other channel/provider or
    unmapped event ID): a generic mapping using only the universal
    <System> fields (EventID, Provider, Computer, Channel, TimeCreated).
    The raw EventData is preserved in raw_event_reference rather than
    guessed at - a security log full of provider-specific fields this
    parser doesn't recognize is exactly the "don't force every field"
    case the Common Event Model was designed around, not a parsing
    failure.
"""

import logging
import ntpath
from xml.etree import ElementTree

from netforensicai.core.event import Event, EventSequence, generate_event_id, parse_timestamp
from netforensicai.parsers import base
from netforensicai.parsers.windows_events import map_windows_event

logger = logging.getLogger(__name__)

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

# Sysmon EventID -> Common Event Model event_type.
SYSMON_EVENT_TYPES = {
    "1": "process_start",
    "3": "network_connection",
    "5": "process_stop",
    "11": "file_created",
    "22": "dns_query",
}

# event_type -> {Sysmon EventData "Name" attribute: Event field}. "Hashes"
# and "TargetFilename" are handled separately below (composite/derived
# values, not a 1:1 copy).
SYSMON_FIELD_MAP = {
    "process_start": {
        "Image": "process_name",
        "CommandLine": "command_line",
        "User": "user",
        "ParentImage": "parent_process",
    },
    "process_stop": {
        "Image": "process_name",
        "User": "user",
    },
    "network_connection": {
        "SourceIp": "src_ip",
        "SourcePort": "src_port",
        "DestinationIp": "dst_ip",
        "DestinationPort": "dst_port",
        "Protocol": "protocol",
        "Image": "process_name",
        "User": "user",
    },
    "file_created": {
        "Image": "process_name",
        "User": "user",
    },
    "dns_query": {
        "QueryName": "domain",
        "Image": "process_name",
        "User": "user",
    },
}

INT_FIELDS = {"src_port", "dst_port"}


class EvtxParseError(Exception):
    """Raised when an EVTX file can't be read."""


def _load_records(path):
    import Evtx.Evtx as evtx

    # A record python-evtx cannot RENDER is skipped, not fatal. Real logs
    # contain them: current Windows builds write substitution types the
    # library has no class for (e.g. an unsigned-byte array, type 132 - seen
    # in a stock Windows 11 System log), and one such record used to abort
    # the whole file, which the all-or-nothing pipeline then discarded
    # entirely. Failing to open or walk the file is still fatal.
    skipped = 0
    try:
        with evtx.Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_text = record.xml()
                except Exception as e:
                    skipped += 1
                    logger.debug(f"Skipping EVTX record python-evtx could not render: {e!r}")
                    continue
                yield xml_text
    except EvtxParseError:
        raise
    except Exception as e:
        raise EvtxParseError(f"Failed to read EVTX file '{path}': {e}") from e
    if skipped:
        logger.warning(f"Skipped {skipped:,} record(s) in '{path}' that python-evtx could not render.")


def _extract_sha256(hashes_value):
    """Sysmon's Hashes field is a composite string like
    "SHA1=...,SHA256=...,IMPHASH=...". Pull out SHA256 specifically since
    that's the hash type used everywhere else in this codebase (entity
    extraction, threat intel); fall back to the raw string if no SHA256
    component is present."""
    for part in hashes_value.split(","):
        if part.strip().upper().startswith("SHA256="):
            return part.split("=", 1)[1].strip()
    return hashes_value


def _parse_system(system_elem):
    provider_elem = system_elem.find(f"{_NS}Provider")
    provider = provider_elem.get("Name") if provider_elem is not None else None

    event_id_elem = system_elem.find(f"{_NS}EventID")
    event_id = event_id_elem.text if event_id_elem is not None else None

    time_elem = system_elem.find(f"{_NS}TimeCreated")
    raw_time = time_elem.get("SystemTime") if time_elem is not None else None
    # python-evtx renders SystemTime as "YYYY-MM-DD HH:MM:SS.ffffff+00:00"
    # (space-separated, not strict ISO 8601 with a "T") - normalize so
    # parse_timestamp()'s fromisoformat() call accepts it on every
    # supported Python version, not just the ones with a relaxed parser.
    timestamp = parse_timestamp(raw_time.replace(" ", "T", 1)) if raw_time else None

    computer_elem = system_elem.find(f"{_NS}Computer")
    computer = computer_elem.text if computer_elem is not None else None

    channel_elem = system_elem.find(f"{_NS}Channel")
    channel = channel_elem.text if channel_elem is not None else None

    record_id_elem = system_elem.find(f"{_NS}EventRecordID")
    record_id = record_id_elem.text if record_id_elem is not None else None

    return {
        "provider": provider,
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": computer,
        "channel": channel,
        "record_id": record_id,
    }


def _parse_event_data(event_data_elem):
    """Return {name: value} for named <Data Name="X">value</Data>
    elements, or {} if this event has no named fields - many non-Sysmon
    providers just emit unnamed <Data> text instead."""
    if event_data_elem is None:
        return {}
    fields = {}
    for data_elem in event_data_elem.findall(f"{_NS}Data"):
        name = data_elem.get("Name")
        if name:
            fields[name] = data_elem.text
    return fields


def _parse_user_data(user_data_elem):
    """{name: value} from a <UserData> block.

    Some providers (notably the Eventlog provider's 1102/104 "log cleared"
    records) put their fields under <UserData><SomeElement>...</SomeElement>
    in a provider-specific namespace instead of <EventData>. The wrapper
    element name varies, so every leaf under it is taken by local name.
    """
    if user_data_elem is None:
        return {}
    fields = {}
    for container in user_data_elem:
        for child in container:
            name = child.tag.rsplit("}", 1)[-1]
            if len(child) == 0:
                fields[name] = child.text
    return fields


def _coerce_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def record_to_event(xml_text, evidence_id, sequence):
    """Parse one EVTX record's XML into an Event. Returns None (logged,
    not raised) if the XML itself can't be parsed - one bad record
    shouldn't fail the whole file."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as e:
        logger.warning(f"Skipping unparseable EVTX record: {e}")
        return None

    system_elem = root.find(f"{_NS}System")
    system_info = _parse_system(system_elem) if system_elem is not None else {}
    event_data = _parse_event_data(root.find(f"{_NS}EventData")) or _parse_user_data(root.find(f"{_NS}UserData"))

    provider = system_info.get("provider")
    event_id = system_info.get("event_id")

    fields = {"hostname": system_info.get("computer")}
    windows_event = None if provider == SYSMON_PROVIDER else map_windows_event(provider, event_id, event_data)

    if provider == SYSMON_PROVIDER and event_id in SYSMON_EVENT_TYPES:
        event_type = SYSMON_EVENT_TYPES[event_id]
        for data_name, event_field in SYSMON_FIELD_MAP.get(event_type, {}).items():
            value = event_data.get(data_name)
            if value is None or value == "":
                continue
            fields[event_field] = _coerce_int(value) if event_field in INT_FIELDS else value

        if event_type == "file_created":
            target = event_data.get("TargetFilename")
            if target:
                fields["file_path"] = target
                # ntpath, not os.path: TargetFilename is always a Windows
                # path (it comes from a Windows EVTX record) regardless of
                # which OS is running this parser. os.path.basename() uses
                # the *host* platform's separator rules, so on Linux/macOS
                # it would silently fail to split a backslash-separated
                # path at all and return the full path as "file_name".
                fields["file_name"] = ntpath.basename(target)

        hashes = event_data.get("Hashes")
        if hashes:
            fields["file_hash"] = _extract_sha256(hashes)
    elif windows_event is not None:
        event_type, mapped_fields, fields["message"] = windows_event
        fields.update(mapped_fields)
    else:
        event_type = f"windows_event:{provider}" if provider else "windows_event"

    return Event(
        event_id=generate_event_id(evidence_id, sequence.next()),
        evidence_id=evidence_id,
        source="evtx",
        event_type=event_type,
        timestamp=system_info.get("timestamp"),
        raw_event_reference={
            "provider": provider,
            "windows_event_id": event_id,
            "record_id": system_info.get("record_id"),
            "channel": system_info.get("channel"),
            "event_data": event_data,
        },
        **fields,
    )


class EvtxParser(base.BaseParser):
    evidence_types = ("evtx",)

    def parse(self, file_path, evidence_id, **options):
        return list(self.iter_parse(file_path, evidence_id, **options))

    def iter_parse(self, file_path, evidence_id, **_ignored):
        # Streams rather than using the list-wrapping default: a busy
        # domain controller's Security.evtx is routinely hundreds of MB and
        # millions of records, which is the scale the pipeline's batching
        # exists for.
        sequence = EventSequence()
        for xml_text in _load_records(file_path):
            event = record_to_event(xml_text, evidence_id, sequence)
            if event is not None:
                yield event


base.register(EvtxParser())
