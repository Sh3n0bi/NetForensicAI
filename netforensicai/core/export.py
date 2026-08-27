"""Portable case export/import: package an entire case directory (case
metadata, evidence, the DuckDB store, timeline, findings, reports) into a
single zip archive an investigator can move, back up, or hand to another
investigator - and reconstruct it exactly on import, verifying every file
against a manifest recorded at export time so tampering or corruption in
transit is caught rather than silently imported.

Not a new storage format: the archive is just a zip of the same
cases/<ID>/ directory this tool already writes to, plus one added
manifest.json (relative path -> SHA-256) at the archive root - so a
curious investigator can also just unzip it by hand and get back exactly
what's on disk today. No file is written during import until every file
in the archive has been checked against the manifest, so a corrupt or
tampered archive is rejected outright rather than partially extracted.

The case ID always comes from the archive's own case.json - import never
renames it. Silently renaming would leave every finding and evidence
item's own embedded case_id field pointing at the old ID (Finding and
Evidence both store case_id independently of the directory name), and
patching all of those consistently is more risk than the feature is
worth. If the target case_id already exists, import refuses rather than
guessing what the investigator wants - move/rename the existing case, or
import into a different --cases-dir.
"""

import hashlib
import json
import logging
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"


class ExportError(Exception):
    """Raised for export/import failures: empty/missing case, corrupt or
    tampered archive, or a case_id collision on import."""


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def export_case(case_dir, output_path):
    """Zip every file under case_dir into output_path, with a
    manifest.json (relative path -> SHA-256) recorded at the archive
    root. Returns output_path."""
    case_dir = Path(case_dir)
    if not case_dir.is_dir():
        raise ExportError(f"Case directory not found: {case_dir}")
    if not (case_dir / "case.json").exists():
        raise ExportError(f"{case_dir} does not look like a case directory (no case.json).")

    files = sorted(p for p in case_dir.rglob("*") if p.is_file())
    if not files:
        raise ExportError(f"Case directory is empty: {case_dir}")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    manifest = {}
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in files:
            rel_path = file_path.relative_to(case_dir).as_posix()
            manifest[rel_path] = _sha256_file(file_path)
            zf.write(file_path, arcname=rel_path)
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True))

    return output_path


def import_case(archive_path, cases_dir):
    """Extract an export_case() archive into cases_dir under its
    original case_id. Verifies every manifest-listed file's hash before
    writing anything. Returns the imported case_id.

    Raises ExportError if: the archive has no manifest.json or case.json,
    any file's hash doesn't match its manifest entry, or a case with the
    same ID already exists under cases_dir.
    """
    archive_path = Path(archive_path)
    cases_dir = Path(cases_dir)

    # zipfile itself checks each entry's CRC-32 on read and raises
    # BadZipFile on a mismatch - this catches raw bit-level corruption
    # (truncated download, disk error) that never even makes it to the
    # SHA-256/manifest check below, which assumes zipfile could read the
    # bytes at all. Both failure modes should look the same to the
    # caller: a clean ExportError, not a raw zipfile traceback.
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            names = set(zf.namelist())
            if MANIFEST_NAME not in names:
                raise ExportError(f"Archive has no {MANIFEST_NAME} - not a NetForensicAI case export, or it's corrupt.")
            try:
                manifest = json.loads(zf.read(MANIFEST_NAME).decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ExportError(f"Archive's {MANIFEST_NAME} is corrupt: {e}") from e

            if "case.json" not in manifest:
                raise ExportError("Archive's manifest has no case.json entry - not a valid case export.")

            file_bytes = {}
            for rel_path, expected_hash in manifest.items():
                if rel_path not in names:
                    raise ExportError(f"Archive is missing a file listed in its manifest: {rel_path}")
                data = zf.read(rel_path)
                actual_hash = _sha256_bytes(data)
                if actual_hash != expected_hash:
                    raise ExportError(
                        f"Integrity check failed for '{rel_path}' - hash in the archive doesn't match its "
                        f"manifest entry. Refusing to import a possibly tampered or corrupted archive."
                    )
                file_bytes[rel_path] = data
    except zipfile.BadZipFile as e:
        raise ExportError(f"Archive is corrupt or not a valid zip file: {e}") from e

    try:
        case_data = json.loads(file_bytes["case.json"].decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ExportError(f"Archive's case.json is corrupt: {e}") from e
    case_id = case_data.get("case_id")
    if not case_id:
        raise ExportError("Archive's case.json has no case_id.")

    target_dir = cases_dir / case_id
    if target_dir.exists():
        raise ExportError(
            f"A case already exists at {target_dir} - move or rename it first, or import into a "
            f"different --cases-dir."
        )

    # Nothing written to disk until every check above has passed.
    for rel_path, data in file_bytes.items():
        if rel_path == MANIFEST_NAME:
            continue
        dest = target_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)

    logger.info(f"Imported case {case_id} from {archive_path} into {target_dir}")
    return case_id
