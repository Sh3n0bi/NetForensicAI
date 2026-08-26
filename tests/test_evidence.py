import os
import stat

import pytest

from netforensicai.core.case import CaseManager
from netforensicai.core.evidence import Evidence, EvidenceError, EvidenceManager


@pytest.fixture
def case_dir(tmp_path):
    case_manager = CaseManager(tmp_path / "cases")
    case = case_manager.create(name="Evidence test case")
    return tmp_path / "cases" / case.case_id


def _make_source(tmp_path, name="attack.pcap", content=b"fake pcap bytes"):
    source = tmp_path / name
    source.write_bytes(content)
    return source


def test_add_records_hash_size_and_type(tmp_path, case_dir):
    source = _make_source(tmp_path)
    manager = EvidenceManager(case_dir)

    evidence = manager.add(source, case_id="INC-0001")

    assert evidence.evidence_id == "EV-0001"
    assert evidence.filename == "attack.pcap"
    assert evidence.evidence_type == "pcap"
    assert evidence.size_bytes == len(b"fake pcap bytes")
    assert manager.verify(evidence.evidence_id) is True


def test_add_infers_evidence_type_from_extension(tmp_path, case_dir):
    manager = EvidenceManager(case_dir)

    json_ev = manager.add(_make_source(tmp_path, "events.json", b"{}"), case_id="INC-0001")
    csv_ev = manager.add(_make_source(tmp_path, "events.csv", b"a,b"), case_id="INC-0001")
    unknown_ev = manager.add(_make_source(tmp_path, "notes.txt", b"x"), case_id="INC-0001")

    assert json_ev.evidence_type == "json"
    assert csv_ev.evidence_type == "csv"
    assert unknown_ev.evidence_type == "unknown"


def test_evidence_ids_increment(tmp_path, case_dir):
    manager = EvidenceManager(case_dir)
    first = manager.add(_make_source(tmp_path, "a.json", b"1"), case_id="INC-0001")
    second = manager.add(_make_source(tmp_path, "b.json", b"2"), case_id="INC-0001")

    assert first.evidence_id == "EV-0001"
    assert second.evidence_id == "EV-0002"


def test_add_missing_source_raises(case_dir):
    manager = EvidenceManager(case_dir)

    with pytest.raises(EvidenceError):
        manager.add("does/not/exist.pcap", case_id="INC-0001")


def test_stored_copy_is_read_only(tmp_path, case_dir):
    source = _make_source(tmp_path)
    manager = EvidenceManager(case_dir)

    evidence = manager.add(source, case_id="INC-0001")
    stored = manager.stored_file_path(evidence.evidence_id)

    mode = stored.stat().st_mode
    assert not (mode & stat.S_IWRITE)


def test_source_file_is_never_modified(tmp_path, case_dir):
    source = _make_source(tmp_path)
    original_bytes = source.read_bytes()
    manager = EvidenceManager(case_dir)

    manager.add(source, case_id="INC-0001")

    assert source.read_bytes() == original_bytes
    assert os.access(source, os.W_OK)


def test_load_missing_evidence_raises(case_dir):
    manager = EvidenceManager(case_dir)

    with pytest.raises(EvidenceError):
        manager.load("EV-9999")


def test_list_returns_all_evidence_sorted(tmp_path, case_dir):
    manager = EvidenceManager(case_dir)
    manager.add(_make_source(tmp_path, "a.json", b"1"), case_id="INC-0001")
    manager.add(_make_source(tmp_path, "b.json", b"2"), case_id="INC-0001")

    items = manager.list()

    assert [e.evidence_id for e in items] == ["EV-0001", "EV-0002"]


def test_list_empty_returns_empty_list(case_dir):
    manager = EvidenceManager(case_dir)

    assert manager.list() == []


def test_verify_detects_tampering(tmp_path, case_dir):
    source = _make_source(tmp_path)
    manager = EvidenceManager(case_dir)
    evidence = manager.add(source, case_id="INC-0001")

    stored = manager.stored_file_path(evidence.evidence_id)
    os.chmod(stored, stat.S_IWRITE | stat.S_IREAD)
    stored.write_bytes(b"tampered")

    assert manager.verify(evidence.evidence_id) is False


def test_register_evidence_updates_case_index(tmp_path, case_dir):
    case_manager = CaseManager(tmp_path / "cases")
    evidence_manager = EvidenceManager(case_dir)
    evidence = evidence_manager.add(_make_source(tmp_path), case_id="INC-0001")

    updated_case = case_manager.register_evidence("INC-0001", evidence.evidence_id)

    assert evidence.evidence_id in updated_case.evidence
    reloaded = case_manager.load("INC-0001")
    assert evidence.evidence_id in reloaded.evidence


def test_evidence_to_dict_and_from_dict_round_trip():
    evidence = Evidence(
        evidence_id="EV-0001",
        case_id="INC-0001",
        filename="a.pcap",
        evidence_type="pcap",
        sha256="abc",
        size_bytes=10,
        imported_at="t",
        source_path="/tmp/a.pcap",
        stored_path="evidence/EV-0001/original/a.pcap",
        source_modified_at="t",
    )

    assert Evidence.from_dict(evidence.to_dict()) == evidence
