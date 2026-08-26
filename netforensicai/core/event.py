"""Common Event Model: the normalized representation every parser emits into.

Every evidence format (pcap, JSON, CSV, and eventually EVTX/Sysmon) maps its
own records into this shape so correlation, timeline, and investigation
commands work the same way regardless of source. Fields are optional except
the ones needed for identity and traceability (event_id, evidence_id,
source, event_type) - per-source detail that doesn't fit the common fields
belongs in raw_event_reference rather than forcing every parser to
populate every field.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Non-exhaustive, kept for consistency across parsers. Not enforced as an
# enum: parser plugins should be free to introduce new event types without
# changing this core model.
COMMON_EVENT_TYPES = (
    "network_connection",
    "file_transfer",
    "dns_query",
    "authentication",
    "process_start",
    "process_stop",
    "file_created",
    "file_modified",
    "file_deleted",
    "anomaly",
)


def generate_event_id(evidence_id, sequence):
    """Deterministic, human-traceable event id scoped to one evidence item's parse run.

    Using a sequence counter the parser already tracks (packet number, row
    index, EVTX record id) avoids needing shared/locked global state to
    generate ids for what can be a very large number of events per evidence
    item.
    """
    return f"EVT-{evidence_id}-{sequence:06d}"


class Event(BaseModel):
    """A single normalized forensic event, traceable back to one evidence item."""

    model_config = ConfigDict(extra="forbid")

    # --- Identity / traceability - required for every event ---
    event_id: str
    evidence_id: str
    source: str = Field(..., description="Originating evidence/parser type, e.g. 'pcap', 'json', 'csv'.")
    event_type: str

    # --- Timing ---
    timestamp: Optional[datetime] = None
    timestamp_precision: Optional[str] = None

    # --- Entities ---
    user: Optional[str] = None
    hostname: Optional[str] = None
    device: Optional[str] = None

    # --- Network ---
    src_ip: Optional[str] = None
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = None

    # --- Process ---
    process_name: Optional[str] = None
    process_id: Optional[int] = Field(default=None, ge=0)
    parent_process: Optional[str] = None
    command_line: Optional[str] = None

    # --- File ---
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    # --- Web / DNS ---
    domain: Optional[str] = None
    url: Optional[str] = None

    # --- Presentation ---
    severity: Optional[str] = None
    message: Optional[str] = None

    # --- Provenance pointer into the original evidence, e.g. {"packet_number": 42} ---
    raw_event_reference: Optional[dict[str, Any]] = None

    @field_validator("event_id", "evidence_id", "source", "event_type")
    @classmethod
    def _not_blank(cls, value):
        if not value or not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("timestamp")
    @classmethod
    def _assume_utc_if_naive(cls, value):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
