"""Unified forensic timeline: one entry per normalized event, each carrying
enough context (entity references, evidence id, original event reference)
to go straight from "what happened" back to the evidence it came from.

Every entry's confidence is "observed" - everything here comes directly
from parsing evidence, nothing is inferred. This is reserved space for a
later AI assistant layer that adds hypothesis-level entries with a lower,
explicitly-hedged confidence (see the project's AI safety model); this
engine itself never produces anything but observed fact.

build_timeline() always queries the store live - it's cheap at this data
scale and guarantees `timeline show` never displays stale results. `save`
writes a point-in-time JSON snapshot (`timeline build`) for handoff,
reporting, or archival, distinct from that live view.
"""

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CONFIDENCE_OBSERVED = "observed"


@dataclass
class TimelineEntry:
    event_id: str
    timestamp: Optional[object]  # datetime or None; see to_dict() for serialization
    event_type: str
    source: str
    evidence_id: str
    entity_references: list
    confidence: str
    raw_event_reference: Optional[dict]
    user: Optional[str] = None
    hostname: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    process_name: Optional[str] = None
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self):
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return data


def build_timeline(store):
    """Assemble one TimelineEntry per event currently in `store`, sorted by
    timestamp (events with no timestamp sort last)."""
    entities_by_event = store.entity_ids_by_event()
    events = store.all_events()

    entries = []
    for event in events:
        entity_references = [
            {"entity_id": entity_id, "entity_type": entity_type, "value": value, "field": link_field}
            for entity_id, entity_type, value, link_field in entities_by_event.get(event.event_id, [])
        ]
        entries.append(
            TimelineEntry(
                event_id=event.event_id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                source=event.source,
                evidence_id=event.evidence_id,
                entity_references=entity_references,
                confidence=CONFIDENCE_OBSERVED,
                raw_event_reference=event.raw_event_reference,
                user=event.user,
                hostname=event.hostname,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                process_name=event.process_name,
                file_name=event.file_name,
                file_path=event.file_path,
                message=event.message,
            )
        )
    return entries


def _entity_match(entry, entity_type, value):
    value_lower = value.lower()
    return any(
        ref["entity_type"] == entity_type and ref["value"].lower() == value_lower
        for ref in entry.entity_references
    )


def filter_timeline(
    entries,
    time_from=None,
    time_to=None,
    user=None,
    ip=None,
    hostname=None,
    process=None,
    file=None,
    event_type=None,
    evidence_id=None,
):
    """Filter timeline entries. time_from/time_to are datetimes; the rest
    are strings matched case-insensitively. ip/user/hostname/process/file
    also match against entity_references, so a filter still finds an entry
    even when the value lives in a field this module doesn't denormalize.
    """
    results = []
    for entry in entries:
        if time_from and (entry.timestamp is None or entry.timestamp < time_from):
            continue
        if time_to and (entry.timestamp is None or entry.timestamp > time_to):
            continue
        if user and not (
            (entry.user and entry.user.lower() == user.lower()) or _entity_match(entry, "user", user)
        ):
            continue
        if ip and not (
            (entry.src_ip and entry.src_ip.lower() == ip.lower())
            or (entry.dst_ip and entry.dst_ip.lower() == ip.lower())
            or _entity_match(entry, "ip_address", ip)
        ):
            continue
        if hostname and not (
            (entry.hostname and entry.hostname.lower() == hostname.lower())
            or _entity_match(entry, "hostname", hostname)
        ):
            continue
        if process and not (
            (entry.process_name and entry.process_name.lower() == process.lower())
            or _entity_match(entry, "process", process)
        ):
            continue
        if file and not (
            (entry.file_name and entry.file_name.lower() == file.lower())
            or (entry.file_path and file.lower() in entry.file_path.lower())
            or _entity_match(entry, "file", file)
        ):
            continue
        if event_type and entry.event_type.lower() != event_type.lower():
            continue
        if evidence_id and entry.evidence_id != evidence_id:
            continue
        results.append(entry)
    return results


def save_timeline(entries, case_dir):
    """Write a point-in-time JSON snapshot to cases/<CASE-ID>/timeline/timeline.json."""
    timeline_dir = Path(case_dir) / "timeline"
    timeline_dir.mkdir(parents=True, exist_ok=True)
    output_path = timeline_dir / "timeline.json"
    output_path.write_text(
        json.dumps([entry.to_dict() for entry in entries], indent=2),
        encoding="utf-8",
    )
    return output_path
