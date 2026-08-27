"""Investigator-controlled findings.

A Finding is the investigator's own conclusion, not the tool's: nothing in
this module infers, suggests, or auto-generates a finding's content. A
later AI assistant layer may eventually SUGGEST a finding's title/
assessment as a starting draft, but creating and confirming a finding is
always an explicit, investigator-initiated action - the investigator
remains in control of what counts as a finding.

evidence_refs deliberately pairs {"evidence_id": ..., "event_id": ...}
rather than storing either alone, matching the "Evidence Contract" shape a
future AI layer will also use: every finding should be traceable to both
which piece of evidence and which specific normalized event it came from.
"""

import dataclasses
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

FINDING_ID_PATTERN = re.compile(r"^F-(\d{4,})$")
VALID_STATUSES = ("Open", "Investigating", "Confirmed", "Rejected", "False Positive", "Resolved")
VALID_SEVERITIES = ("Low", "Medium", "High", "Critical")


class FindingError(Exception):
    """Raised for finding-management failures: not found, invalid status/severity/reference."""


@dataclasses.dataclass
class Finding:
    finding_id: str
    case_id: str
    title: str
    status: str
    severity: str
    assessment: str
    evidence_refs: list
    investigator_notes: list
    created_by: str
    created_at: str
    updated_at: str

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


class FindingManager:
    """Creates, loads, lists, and updates findings under a case's findings/ directory."""

    def __init__(self, case_dir):
        self.case_dir = Path(case_dir)
        self.findings_dir = self.case_dir / "findings"

    def _finding_path(self, finding_id):
        # finding_id is about to be reachable from web API URL/payload
        # input - validate before building a path from it, same reasoning
        # as CaseManager._case_path() (see its comment).
        if not FINDING_ID_PATTERN.match(finding_id or ""):
            raise FindingError(f"Invalid finding ID: {finding_id!r}")
        return self.findings_dir / f"{finding_id}.json"

    def _next_finding_id(self):
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        max_n = 0
        for entry in self.findings_dir.iterdir():
            if entry.is_file() and entry.suffix == ".json":
                match = FINDING_ID_PATTERN.match(entry.stem)
                if match:
                    max_n = max(max_n, int(match.group(1)))
        return f"F-{max_n + 1:04d}"

    def create(
        self,
        case_id,
        title,
        created_by,
        severity="Medium",
        status="Open",
        assessment="",
        evidence_refs=None,
        valid_event_ids=None,
    ):
        """Create a new finding. If valid_event_ids is given, every
        evidence_ref's event_id must be a member of it - this is how the
        CLI enforces that a finding can only cite events that actually
        exist in this case, not invented ones."""
        if not title or not title.strip():
            raise FindingError("Finding title must not be empty.")
        if status not in VALID_STATUSES:
            raise FindingError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}")
        if severity not in VALID_SEVERITIES:
            raise FindingError(f"Invalid severity '{severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}")

        evidence_refs = evidence_refs or []
        for ref in evidence_refs:
            if "evidence_id" not in ref or "event_id" not in ref:
                raise FindingError(f"Each evidence_ref needs evidence_id and event_id: {ref}")
            if valid_event_ids is not None and ref["event_id"] not in valid_event_ids:
                raise FindingError(f"event_id '{ref['event_id']}' was not found in this case's events.")

        finding_id = self._next_finding_id()
        finding_path = self._finding_path(finding_id)
        if finding_path.exists():
            raise FindingError(f"Finding file already exists: {finding_path}")

        now = datetime.now(timezone.utc).isoformat()
        finding = Finding(
            finding_id=finding_id,
            case_id=case_id,
            title=title,
            status=status,
            severity=severity,
            assessment=assessment,
            evidence_refs=evidence_refs,
            investigator_notes=[],
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self._save(finding)

        from netforensicai.core import audit

        audit.record(
            self.case_dir,
            audit.FINDING_CREATED,
            {
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
                "status": status,
                "cited_events": [ref.get("event_id") for ref in evidence_refs],
            },
            actor=created_by,
        )

        logger.info(f"Created finding {finding_id}: {title}")
        return finding

    def _save(self, finding):
        self._finding_path(finding.finding_id).write_text(
            json.dumps(finding.to_dict(), indent=2), encoding="utf-8"
        )

    def load(self, finding_id):
        finding_path = self._finding_path(finding_id)
        if not finding_path.exists():
            raise FindingError(f"Finding not found: {finding_id}")
        try:
            data = json.loads(finding_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise FindingError(f"Finding file for {finding_id} is corrupt: {e}") from e
        return Finding.from_dict(data)

    def list(self):
        """Return all valid findings, sorted by finding_id. Skips corrupt entries."""
        if not self.findings_dir.exists():
            return []
        findings = []
        for entry in sorted(self.findings_dir.iterdir()):
            if entry.is_file() and entry.suffix == ".json" and FINDING_ID_PATTERN.match(entry.stem):
                try:
                    findings.append(self.load(entry.stem))
                except FindingError as e:
                    logger.warning(f"Skipping unreadable finding file {entry.name}: {e}")
        return findings

    def update_status(self, finding_id, status):
        if status not in VALID_STATUSES:
            raise FindingError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}")
        finding = self.load(finding_id)
        previous_status = finding.status
        finding.status = status
        finding.updated_at = datetime.now(timezone.utc).isoformat()
        self._save(finding)

        from netforensicai.core import audit

        # Both values, not just the new one: a status history is only
        # meaningful if each change records what it changed from.
        audit.record(
            self.case_dir,
            audit.FINDING_UPDATED,
            {"finding_id": finding_id, "field": "status", "from": previous_status, "to": status},
        )
        return finding

    def add_note(self, finding_id, note_text, author):
        finding = self.load(finding_id)
        finding.investigator_notes.append(
            {"text": note_text, "author": author, "timestamp": datetime.now(timezone.utc).isoformat()}
        )
        finding.updated_at = datetime.now(timezone.utc).isoformat()
        self._save(finding)

        from netforensicai.core import audit

        audit.record(
            self.case_dir,
            audit.FINDING_UPDATED,
            {"finding_id": finding_id, "field": "note", "note": note_text},
            actor=author,
        )
        return finding
