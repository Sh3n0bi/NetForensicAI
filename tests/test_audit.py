"""Tests for the chain-of-custody audit log."""

import json

from netforensicai.core import audit


def test_records_entries_in_order(tmp_path):
    audit.record(tmp_path, audit.CASE_CREATED, {"name": "Test"})
    audit.record(tmp_path, audit.EVIDENCE_ADDED, {"evidence_id": "EV-0001"})

    entries = audit.read_entries(tmp_path)

    assert [e["action"] for e in entries] == [audit.CASE_CREATED, audit.EVIDENCE_ADDED]
    assert [e["sequence"] for e in entries] == [1, 2]
    assert entries[1]["details"]["evidence_id"] == "EV-0001"


def test_entries_carry_actor_and_utc_timestamp(tmp_path):
    entry = audit.record(tmp_path, audit.CASE_CREATED, actor="alice")

    assert entry["actor"] == "alice"
    assert entry["timestamp"].endswith("+00:00")


def test_reading_an_absent_log_is_empty_not_an_error(tmp_path):
    assert audit.read_entries(tmp_path) == []
    ok, problems = audit.verify(tmp_path)
    assert ok and problems == []


def test_chain_verifies_when_untouched(tmp_path):
    for i in range(5):
        audit.record(tmp_path, audit.EVIDENCE_ADDED, {"evidence_id": f"EV-{i:04d}"})

    ok, problems = audit.verify(tmp_path)

    assert ok, problems
    assert problems == []


def test_first_entry_links_to_the_genesis_hash(tmp_path):
    audit.record(tmp_path, audit.CASE_CREATED)

    assert audit.read_entries(tmp_path)[0]["previous_hash"] == audit.GENESIS_HASH


def test_modifying_an_entry_is_detected(tmp_path):
    audit.record(tmp_path, audit.CASE_CREATED, {"name": "Real case"})
    audit.record(tmp_path, audit.FINDING_CREATED, {"finding_id": "F-0001"})

    # Rewrite the first entry's details but leave its recorded hash alone -
    # exactly what after-the-fact editing of a log looks like.
    path = audit.audit_path(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["details"]["name"] = "Something else"
    lines[0] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert any("has been modified" in p for p in problems)


def test_deleting_an_entry_is_detected(tmp_path):
    for i in range(4):
        audit.record(tmp_path, audit.EVIDENCE_ADDED, {"evidence_id": f"EV-{i:04d}"})

    path = audit.audit_path(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # remove a middle entry
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert any("inserted or removed" in p for p in problems)


def test_appending_a_forged_entry_is_detected(tmp_path):
    audit.record(tmp_path, audit.CASE_CREATED)

    path = audit.audit_path(tmp_path)
    forged = {
        "sequence": 2,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "actor": "mallory",
        "action": audit.FINDING_CREATED,
        "details": {},
        "previous_hash": audit.GENESIS_HASH,  # wrong: does not follow entry 1
        "entry_hash": "deadbeef",
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(forged, sort_keys=True) + "\n")

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert len(problems) >= 1


def test_corrupt_line_is_skipped_rather_than_raising(tmp_path):
    audit.record(tmp_path, audit.CASE_CREATED)
    with open(audit.audit_path(tmp_path), "a", encoding="utf-8") as handle:
        handle.write("{not valid json\n")
    audit.record(tmp_path, audit.FINDING_CREATED)

    entries = audit.read_entries(tmp_path)

    # The readable entries still come back; verify() is what reports damage.
    assert len(entries) == 2


def test_real_workflow_records_every_action_in_order(tmp_path):
    """End-to-end: the actions a real investigation performs must each leave
    a custody entry. Caught a genuine gap - finding.created was silently not
    being recorded, which a unit test of audit.py alone could never show."""
    import json as _json

    from netforensicai.core.case import CaseManager
    from netforensicai.core.evidence import EvidenceManager
    from netforensicai.core.finding import FindingManager

    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Workflow", investigator="alice")
    case_dir = cases_dir / case.case_id

    source = tmp_path / "e.json"
    source.write_text(
        _json.dumps([{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe"}]),
        encoding="utf-8",
    )
    EvidenceManager(case_dir).add(source, case_id=case.case_id)

    findings = FindingManager(case_dir)
    findings.create(case_id=case.case_id, title="Something", created_by="alice")
    findings.update_status("F-0001", "Confirmed")
    findings.add_note("F-0001", "checked", "alice")

    actions = [e["action"] for e in audit.read_entries(case_dir)]

    assert actions == [
        audit.CASE_CREATED,
        audit.EVIDENCE_ADDED,
        audit.FINDING_CREATED,
        audit.FINDING_UPDATED,
        audit.FINDING_UPDATED,
    ]
    ok, problems = audit.verify(case_dir)
    assert ok, problems


def test_evidence_entry_records_the_full_hash_and_source(tmp_path):
    # This entry is the record of what was admitted into the case and where
    # it came from, so it must carry the whole hash, not an abbreviation.
    import json as _json

    from netforensicai.core.case import CaseManager
    from netforensicai.core.evidence import EvidenceManager

    cases_dir = tmp_path / "cases"
    case = CaseManager(cases_dir).create(name="Hashes")
    case_dir = cases_dir / case.case_id
    source = tmp_path / "e.json"
    source.write_text(_json.dumps([{"type": "x"}]), encoding="utf-8")

    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)

    entry = next(e for e in audit.read_entries(case_dir) if e["action"] == audit.EVIDENCE_ADDED)
    assert entry["details"]["sha256"] == evidence.sha256
    assert len(entry["details"]["sha256"]) == 64
    assert entry["details"]["source_path"] == evidence.source_path


def test_status_change_records_both_old_and_new_values(tmp_path):
    from netforensicai.core.case import CaseManager
    from netforensicai.core.finding import FindingManager

    cases_dir = tmp_path / "cases"
    case = CaseManager(cases_dir).create(name="Status")
    case_dir = cases_dir / case.case_id
    findings = FindingManager(case_dir)
    findings.create(case_id=case.case_id, title="t", created_by="alice", status="Open")

    findings.update_status("F-0001", "Confirmed")

    entry = [e for e in audit.read_entries(case_dir) if e["action"] == audit.FINDING_UPDATED][-1]
    assert entry["details"]["from"] == "Open"
    assert entry["details"]["to"] == "Confirmed"


def test_export_archive_contains_its_own_export_entry(tmp_path):
    # The exported copy must say it was exported, or every archive would
    # claim the case never left the machine it came from.
    import zipfile

    from netforensicai.core.case import CaseManager
    from netforensicai.core.export import export_case

    cases_dir = tmp_path / "cases"
    case = CaseManager(cases_dir).create(name="Exported")
    case_dir = cases_dir / case.case_id
    archive = tmp_path / "out.zip"

    export_case(case_dir, archive)

    with zipfile.ZipFile(archive) as zf:
        logged = zf.read(audit.AUDIT_FILENAME).decode("utf-8")
    assert audit.CASE_EXPORTED in logged


def test_import_continues_the_chain_rather_than_restarting_it(tmp_path):
    from netforensicai.core.case import CaseManager
    from netforensicai.core.export import export_case, import_case

    cases_dir = tmp_path / "cases"
    case = CaseManager(cases_dir).create(name="Handover")
    case_dir = cases_dir / case.case_id
    archive = tmp_path / "out.zip"
    export_case(case_dir, archive)

    restored_root = tmp_path / "restored"
    import_case(archive, restored_root)
    restored_dir = restored_root / case.case_id

    actions = [e["action"] for e in audit.read_entries(restored_dir)]
    assert actions == [audit.CASE_CREATED, audit.CASE_EXPORTED, audit.CASE_IMPORTED]
    ok, problems = audit.verify(restored_dir)
    assert ok, problems


def test_recording_failure_does_not_raise(tmp_path, monkeypatch):
    # Losing an audit line is bad; losing the investigator's actual work
    # because auditing failed would be worse.
    def explode(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("builtins.open", explode)

    assert audit.record(tmp_path, audit.CASE_CREATED) is None
