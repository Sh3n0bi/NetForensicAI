import json
import zipfile

import pytest

from netforensicai.core.case import CaseManager
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.export import MANIFEST_NAME, ExportError, export_case, import_case
from netforensicai.core.finding import FindingManager


@pytest.fixture
def populated_case(tmp_path):
    """A real case with evidence, a finding, and a DuckDB store file -
    enough to exercise export/import against real varied file types."""
    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Export test case", investigator="alice")
    case_dir = cases_dir / case.case_id

    source = tmp_path / "events.json"
    source.write_text(json.dumps([{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe"}]))
    evidence_manager = EvidenceManager(case_dir)
    evidence = evidence_manager.add(source, case_id=case.case_id)
    case_manager.register_evidence(case.case_id, evidence.evidence_id)

    finding_manager = FindingManager(case_dir)
    finding_manager.create(case_id=case.case_id, title="Test finding", created_by="alice")
    case_manager.register_finding(case.case_id, "F-0001")

    from netforensicai.core.entities import extract_and_store
    from netforensicai.core.store import CaseStore
    from netforensicai.parsers.generic import JsonParser

    events = JsonParser().parse(evidence_manager.stored_file_path(evidence.evidence_id), evidence_id=evidence.evidence_id)
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence(evidence.evidence_id, events)
        extract_and_store(store, events)

    return cases_dir, case, case_dir


def test_export_creates_archive_with_manifest(populated_case, tmp_path):
    _cases_dir, _case, case_dir = populated_case
    output_path = tmp_path / "export.zip"

    result = export_case(case_dir, output_path)

    assert result == output_path
    assert output_path.exists()
    with zipfile.ZipFile(output_path) as zf:
        names = zf.namelist()
        assert MANIFEST_NAME in names
        assert "case.json" in names
        assert any(n.startswith("evidence/") for n in names)
        assert any(n.startswith("findings/") for n in names)
        assert "case.duckdb" in names

        manifest = json.loads(zf.read(MANIFEST_NAME))
        assert set(manifest) == set(names) - {MANIFEST_NAME}


def test_export_rejects_missing_case_dir(tmp_path):
    with pytest.raises(ExportError, match="not found"):
        export_case(tmp_path / "does-not-exist", tmp_path / "out.zip")


def test_export_rejects_non_case_directory(tmp_path):
    empty_dir = tmp_path / "not-a-case"
    empty_dir.mkdir()
    (empty_dir / "random.txt").write_text("hello")

    with pytest.raises(ExportError, match="case.json"):
        export_case(empty_dir, tmp_path / "out.zip")


def test_import_round_trips_case_contents(populated_case, tmp_path):
    _cases_dir, case, case_dir = populated_case
    archive = tmp_path / "export.zip"
    export_case(case_dir, archive)

    fresh_cases_dir = tmp_path / "restored_cases"
    imported_id = import_case(archive, fresh_cases_dir)

    assert imported_id == case.case_id
    restored_dir = fresh_cases_dir / case.case_id
    assert (restored_dir / "case.json").exists()
    assert (restored_dir / "case.duckdb").exists()

    original_case = CaseManager(_cases_dir).load(case.case_id)  # re-read: `case` predates register_evidence/register_finding
    restored_case = CaseManager(fresh_cases_dir).load(case.case_id)
    assert restored_case.name == original_case.name
    assert restored_case.investigator == original_case.investigator
    assert restored_case.evidence == original_case.evidence == ["EV-0001"]

    restored_finding_manager = FindingManager(restored_dir)
    findings = restored_finding_manager.list()
    assert len(findings) == 1
    assert findings[0].title == "Test finding"

    from netforensicai.core.store import CaseStore

    with CaseStore(restored_dir) as store:
        assert store.count_events() == 1


def test_import_refuses_case_id_collision(populated_case, tmp_path):
    cases_dir, _case, case_dir = populated_case
    archive = tmp_path / "export.zip"
    export_case(case_dir, archive)

    with pytest.raises(ExportError, match="already exists"):
        import_case(archive, cases_dir)  # same cases_dir the case already lives in


def test_import_rejects_archive_without_manifest(tmp_path):
    bad_archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_archive, "w") as zf:
        zf.writestr("case.json", json.dumps({"case_id": "INC-0001"}))

    with pytest.raises(ExportError, match="manifest"):
        import_case(bad_archive, tmp_path / "cases")


def test_import_rejects_tampered_file(populated_case, tmp_path):
    _cases_dir, _case, case_dir = populated_case
    archive = tmp_path / "export.zip"
    export_case(case_dir, archive)

    # Rewrite the zip with case.json's content altered but the manifest
    # (and its recorded hash for case.json) left untouched - simulating
    # a file that was tampered with, or corrupted, after export.
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(tampered, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "case.json":
                data = data.replace(b'"status": "open"', b'"status": "closed"')
            dst.writestr(item, data)

    with pytest.raises(ExportError, match="Integrity check failed"):
        import_case(tampered, tmp_path / "cases")


def test_import_rejects_archive_with_file_missing_from_zip(populated_case, tmp_path):
    _cases_dir, _case, case_dir = populated_case
    archive = tmp_path / "export.zip"
    export_case(case_dir, archive)

    truncated = tmp_path / "truncated.zip"
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(truncated, "w") as dst:
        for item in src.infolist():
            if item.filename == "case.duckdb":
                continue  # drop a file the manifest still references
            dst.writestr(item, src.read(item.filename))

    with pytest.raises(ExportError, match="missing"):
        import_case(truncated, tmp_path / "cases")


def test_import_rejects_raw_byte_corruption(populated_case, tmp_path):
    # Regression: flipping a raw byte in the archive (simulating a
    # truncated download or disk error, as opposed to a deliberately
    # re-written entry) breaks zipfile's own CRC-32 check, which raised
    # a bare zipfile.BadZipFile that leaked past import_case() as an
    # unhandled traceback instead of a clean ExportError. Found by
    # actually corrupting a real exported archive and running `netforensic
    # case import` against it, not just by re-writing zip entries in a
    # way that keeps their CRCs internally consistent.
    _cases_dir, _case, case_dir = populated_case
    archive = tmp_path / "export.zip"
    export_case(case_dir, archive)

    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 0xFF
    corrupted = tmp_path / "corrupted.zip"
    corrupted.write_bytes(data)

    with pytest.raises(ExportError, match="corrupt"):
        import_case(corrupted, tmp_path / "cases")


def test_nothing_written_to_disk_when_import_fails(populated_case, tmp_path):
    _cases_dir, _case, case_dir = populated_case
    archive = tmp_path / "export.zip"
    export_case(case_dir, archive)

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(tampered, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "case.json":
                data = data.replace(b'"status": "open"', b'"status": "closed"')
            dst.writestr(item, data)

    target_cases_dir = tmp_path / "cases_target"
    with pytest.raises(ExportError):
        import_case(tampered, target_cases_dir)

    assert not target_cases_dir.exists()
