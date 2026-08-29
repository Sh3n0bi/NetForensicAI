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
import os
import re
import shutil
import stat
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

    def delete(self, case_id, confirm_case_id=None):
        """Delete a case and everything under it. Returns what was destroyed.

        THIS IS IRREVERSIBLE AND IT DESTROYS THE CHAIN OF CUSTODY. The
        audit log lives inside the case directory, so deleting a case
        removes the record of what was done to it along with the evidence
        copies, the store, and any carved artifacts. There is no soft
        delete and no trash: a forensics tool that pretends to delete
        evidence while keeping a copy is worse than one that deletes it,
        because the copy is then unaccounted for.

        confirm_case_id must equal case_id. A confirmation the caller has
        to type out is what separates deleting the case they meant from
        the one that happened to be selected - a boolean flag defaults to
        something, and the something is wrong at least once.

        Returns a summary of what was removed, so the caller can report it
        rather than saying "done" about work nobody can check afterwards.
        """
        case = self.load(case_id)
        if confirm_case_id != case_id:
            raise CaseError(
                f"Deleting {case_id} needs the case ID as confirmation - it is irreversible "
                "and takes the evidence and the chain of custody with it."
            )

        case_dir = self._case_path(case_id)
        # _case_path already refuses a traversing id, but this is a
        # RECURSIVE delete: re-derive the resolved path and prove it sits
        # under cases_dir before removing anything. The cost of being
        # wrong here is somebody else's data.
        resolved = case_dir.resolve()
        root = self.cases_dir.resolve()
        if resolved == root or root not in resolved.parents:
            raise CaseError(f"Refusing to delete a path outside the cases directory: {resolved}")

        evidence_dir = case_dir / "evidence"
        evidence_count = (
            sum(1 for child in evidence_dir.iterdir() if child.is_dir()) if evidence_dir.is_dir() else 0
        )
        size_bytes = sum(f.stat().st_size for f in case_dir.rglob("*") if f.is_file())

        # Evidence copies are deliberately chmod'd read-only on ingest so
        # nothing can modify them in place. On Windows that also stops
        # them being DELETED, so a plain rmtree fails with EACCES on
        # exactly the files this tool was careful about. Clear the bit
        # first rather than pass an onerror hook: that argument is
        # deprecated in 3.12 and spelled differently in 3.9, and walking
        # the tree once is simpler than branching on the version.
        for path in case_dir.rglob("*"):
            if path.is_file():
                try:
                    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                except OSError as e:
                    logger.warning(f"Could not clear the read-only bit on {path}: {e}")
        shutil.rmtree(case_dir)
        logger.info(f"Deleted case {case_id} ({evidence_count} evidence item(s), {size_bytes} bytes)")

        return {
            "case_id": case_id,
            "name": case.name,
            "evidence_count": evidence_count,
            "finding_count": len(case.findings),
            "artifact_count": len(case.artifacts),
            "size_bytes": size_bytes,
        }

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
