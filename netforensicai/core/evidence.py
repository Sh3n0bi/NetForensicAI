"""Evidence management: SHA-256 integrity, provenance, and case-scoped storage.

On ingest, the source file is copied into the case's evidence directory,
hashed, and made read-only. Every later parser/event/finding traces back to
this stored copy - the original file at its source location is never opened
for writing and never deleted, so provenance stays intact even if the
original is later moved or removed.

Layout per evidence item:
    cases/<CASE-ID>/evidence/<EV-ID>/
        manifest.json
        original/<original filename>
"""

import dataclasses
import hashlib
import json
import logging
import os
import re
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

EVIDENCE_ID_PATTERN = re.compile(r"^EV-(\d{4,})$")
HASH_CHUNK_SIZE = 1024 * 1024

EVIDENCE_TYPE_BY_EXTENSION = {
    ".pcap": "pcap",
    ".pcapng": "pcap",
    ".json": "json",
    ".csv": "csv",
    ".evtx": "evtx",
}


class EvidenceError(Exception):
    """Raised for evidence-management failures: missing source, not found, corrupt manifest."""


@dataclasses.dataclass
class Evidence:
    evidence_id: str
    case_id: str
    filename: str
    evidence_type: str
    sha256: str
    size_bytes: int
    imported_at: str
    source_path: str
    stored_path: str
    source_modified_at: str

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


def sha256_of_file(path):
    """Compute the SHA-256 of a file, streaming so large evidence files never
    need to fit in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def infer_evidence_type(filename):
    return EVIDENCE_TYPE_BY_EXTENSION.get(Path(filename).suffix.lower(), "unknown")


class EvidenceManager:
    """Manages evidence storage under a single case's evidence/ directory."""

    def __init__(self, case_dir):
        self.case_dir = Path(case_dir)
        self.evidence_dir = self.case_dir / "evidence"

    def _evidence_path(self, evidence_id):
        return self.evidence_dir / evidence_id

    def _next_evidence_id(self):
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        max_n = 0
        for entry in self.evidence_dir.iterdir():
            if entry.is_dir():
                match = EVIDENCE_ID_PATTERN.match(entry.name)
                if match:
                    max_n = max(max_n, int(match.group(1)))
        return f"EV-{max_n + 1:04d}"

    def add(self, source_path, case_id):
        """Copy source_path into evidence storage, hash it, and record a manifest.

        The original file is only ever opened for reading (via shutil.copy2);
        the returned Evidence's sha256 is computed from the stored copy, so it
        reflects exactly what was preserved.
        """
        source = Path(source_path)
        if not source.is_file():
            raise EvidenceError(f"Evidence source not found or not a regular file: {source_path}")

        filename = source.name
        if not filename or filename in (".", ".."):
            raise EvidenceError(f"Invalid evidence filename derived from: {source_path}")

        source_stat = source.stat()
        evidence_id = self._next_evidence_id()
        evidence_path = self._evidence_path(evidence_id)
        if evidence_path.exists():
            raise EvidenceError(f"Evidence directory already exists: {evidence_path}")

        original_dir = evidence_path / "original"
        original_dir.mkdir(parents=True)
        dest_file = original_dir / filename

        shutil.copy2(source, dest_file)

        sha256 = sha256_of_file(dest_file)
        os.chmod(dest_file, stat.S_IREAD)

        now = datetime.now(timezone.utc).isoformat()
        evidence = Evidence(
            evidence_id=evidence_id,
            case_id=case_id,
            filename=filename,
            evidence_type=infer_evidence_type(filename),
            sha256=sha256,
            size_bytes=source_stat.st_size,
            imported_at=now,
            source_path=str(source.resolve()),
            stored_path=str(dest_file.relative_to(self.case_dir)).replace(os.sep, "/"),
            source_modified_at=datetime.fromtimestamp(source_stat.st_mtime, tz=timezone.utc).isoformat(),
        )

        manifest_file = evidence_path / "manifest.json"
        manifest_file.write_text(json.dumps(evidence.to_dict(), indent=2), encoding="utf-8")

        from netforensicai.core import audit

        # The full hash and the original source path, not an abbreviation:
        # this line is the record of what was admitted into the case and
        # where it came from.
        audit.record(
            self.case_dir,
            audit.EVIDENCE_ADDED,
            {
                "evidence_id": evidence_id,
                "filename": filename,
                "evidence_type": evidence.evidence_type,
                "sha256": sha256,
                "size_bytes": evidence.size_bytes,
                "source_path": evidence.source_path,
            },
        )

        logger.info(f"Ingested evidence {evidence_id} ({filename}, sha256={sha256[:12]}...)")
        return evidence

    def load(self, evidence_id):
        manifest_file = self._evidence_path(evidence_id) / "manifest.json"
        if not manifest_file.exists():
            raise EvidenceError(f"Evidence not found: {evidence_id}")
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise EvidenceError(f"Evidence manifest for {evidence_id} is corrupt: {e}") from e
        return Evidence.from_dict(data)

    def list(self):
        """Return all valid evidence items, sorted by evidence_id. Skips corrupt entries."""
        if not self.evidence_dir.exists():
            return []
        items = []
        for entry in sorted(self.evidence_dir.iterdir()):
            if entry.is_dir() and (entry / "manifest.json").exists():
                try:
                    items.append(self.load(entry.name))
                except EvidenceError as e:
                    logger.warning(f"Skipping unreadable evidence directory {entry.name}: {e}")
        return items

    def stored_file_path(self, evidence_id):
        """Absolute path to the stored (read-only) copy of the evidence file."""
        evidence = self.load(evidence_id)
        return self.case_dir / evidence.stored_path

    def verify(self, evidence_id):
        """Recompute the stored copy's SHA-256 and compare against the manifest."""
        evidence = self.load(evidence_id)
        file_path = self.case_dir / evidence.stored_path
        if not file_path.exists():
            raise EvidenceError(f"Stored evidence file missing for {evidence_id}: {file_path}")
        return sha256_of_file(file_path) == evidence.sha256
