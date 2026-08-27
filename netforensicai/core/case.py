"""Case management: create/list/load cases and their on-disk layout.

A case is the top-level unit of investigation. Evidence, normalized events,
timelines, findings, and reports are all scoped under one case directory so
an investigation stays self-contained and portable:

    cases/<CASE-ID>/
        case.json
        evidence/
        artifacts/
        timeline/
        findings/
        reports/

Timeline data is intentionally not a field on Case itself - it is derived
from normalized events (see the timeline engine, added in a later step)
rather than something callers append to directly.
"""

import dataclasses
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

CASE_ID_PATTERN = re.compile(r"^INC-(\d{4,})$")
VALID_STATUSES = ("open", "investigating", "closed")
SUBDIRS = ("evidence", "artifacts", "timeline", "findings", "reports")


class CaseError(Exception):
    """Raised for case-management failures: not found, already exists, invalid state."""


@dataclasses.dataclass
class Case:
    case_id: str
    name: str
    description: str
    investigator: str
    created_at: str
    updated_at: str
    status: str = "open"
    evidence: list = dataclasses.field(default_factory=list)
    artifacts: list = dataclasses.field(default_factory=list)
    findings: list = dataclasses.field(default_factory=list)
    notes: list = dataclasses.field(default_factory=list)

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


class CaseManager:
    """Creates, loads, and lists cases under a root cases directory."""

    def __init__(self, cases_dir="cases"):
        self.cases_dir = Path(cases_dir)

    def _case_path(self, case_id):
        # case_id reaches here directly from URL path segments in the web
        # API (and CLI --case flags) with no upstream validation - without
        # this check, a case_id like "../../../../etc" would let load()
        # walk outside cases_dir looking for a case.json (CWE-22).
        if not CASE_ID_PATTERN.match(case_id or ""):
            raise CaseError(f"Invalid case ID: {case_id!r}")
        return self.cases_dir / case_id

    def _next_case_id(self):
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        max_n = 0
        for entry in self.cases_dir.iterdir():
            if entry.is_dir():
                match = CASE_ID_PATTERN.match(entry.name)
                if match:
                    max_n = max(max_n, int(match.group(1)))
        return f"INC-{max_n + 1:04d}"

    def create(self, name, description="", investigator="unknown"):
        """Create a new case with the next available case_id and its on-disk layout."""
        if not name or not name.strip():
            raise CaseError("Case name must not be empty.")

        case_id = self._next_case_id()
        case_path = self._case_path(case_id)
        if case_path.exists():
            raise CaseError(f"Case directory already exists: {case_path}")

        now = datetime.now(timezone.utc).isoformat()
        case = Case(
            case_id=case_id,
            name=name,
            description=description,
            investigator=investigator,
            created_at=now,
            updated_at=now,
            status="open",
        )

        case_path.mkdir(parents=True)
        for sub in SUBDIRS:
            (case_path / sub).mkdir()
        self._save(case)

        from netforensicai.core import audit

        audit.record(
            case_path,
            audit.CASE_CREATED,
            {"case_id": case_id, "name": name, "description": description},
            actor=case.investigator,
        )

        logger.info(f"Created case {case_id} at {case_path}")
        return case

    def _save(self, case):
        case_file = self._case_path(case.case_id) / "case.json"
        case_file.write_text(json.dumps(case.to_dict(), indent=2), encoding="utf-8")

    def load(self, case_id):
        case_file = self._case_path(case_id) / "case.json"
        if not case_file.exists():
            raise CaseError(f"Case not found: {case_id}")
        try:
            data = json.loads(case_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise CaseError(f"Case file for {case_id} is corrupt: {e}") from e
        return Case.from_dict(data)

    def list(self):
        """Return all valid cases under cases_dir, sorted by case_id. Skips corrupt entries."""
        if not self.cases_dir.exists():
            return []
        cases = []
        for entry in sorted(self.cases_dir.iterdir()):
            if entry.is_dir() and (entry / "case.json").exists():
                try:
                    cases.append(self.load(entry.name))
                except CaseError as e:
                    logger.warning(f"Skipping unreadable case directory {entry.name}: {e}")
        return cases

    def update_status(self, case_id, status):
        if status not in VALID_STATUSES:
            raise CaseError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}")
        case = self.load(case_id)
        case.status = status
        case.updated_at = datetime.now(timezone.utc).isoformat()
        self._save(case)
        return case

    def register_evidence(self, case_id, evidence_id):
        """Record an evidence_id against the case's evidence index. Idempotent."""
        case = self.load(case_id)
        if evidence_id not in case.evidence:
            case.evidence.append(evidence_id)
            case.updated_at = datetime.now(timezone.utc).isoformat()
            self._save(case)
        return case

    def register_artifact(self, case_id, artifact_path):
        """Record a path (relative to the case directory) against the case's
        artifact index, e.g. a file extracted from evidence during parsing.
        Idempotent."""
        case = self.load(case_id)
        if artifact_path not in case.artifacts:
            case.artifacts.append(artifact_path)
            case.updated_at = datetime.now(timezone.utc).isoformat()
            self._save(case)
        return case

    def register_finding(self, case_id, finding_id):
        """Record a finding_id against the case's findings index. Idempotent."""
        case = self.load(case_id)
        if finding_id not in case.findings:
            case.findings.append(finding_id)
            case.updated_at = datetime.now(timezone.utc).isoformat()
            self._save(case)
        return case
