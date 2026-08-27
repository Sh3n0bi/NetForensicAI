import pytest

from netforensicai.core.finding import Finding, FindingError, FindingManager, VALID_STATUSES


def test_create_finding_sets_defaults(tmp_path):
    manager = FindingManager(tmp_path)

    finding = manager.create(case_id="INC-0001", title="Suspicious PowerShell Execution", created_by="alice")

    assert finding.finding_id == "F-0001"
    assert finding.status == "Open"
    assert finding.severity == "Medium"
    assert finding.evidence_refs == []
    assert finding.investigator_notes == []
    assert finding.created_by == "alice"
    assert finding.created_at == finding.updated_at


def test_finding_ids_increment(tmp_path):
    manager = FindingManager(tmp_path)
    first = manager.create(case_id="INC-0001", title="First", created_by="alice")
    second = manager.create(case_id="INC-0001", title="Second", created_by="alice")

    assert first.finding_id == "F-0001"
    assert second.finding_id == "F-0002"


def test_create_rejects_empty_title(tmp_path):
    manager = FindingManager(tmp_path)

    with pytest.raises(FindingError):
        manager.create(case_id="INC-0001", title="   ", created_by="alice")


def test_create_rejects_invalid_status(tmp_path):
    manager = FindingManager(tmp_path)

    with pytest.raises(FindingError):
        manager.create(case_id="INC-0001", title="X", created_by="alice", status="Not A Status")


def test_create_rejects_invalid_severity(tmp_path):
    manager = FindingManager(tmp_path)

    with pytest.raises(FindingError):
        manager.create(case_id="INC-0001", title="X", created_by="alice", severity="Extreme")


def test_create_with_evidence_refs(tmp_path):
    manager = FindingManager(tmp_path)
    refs = [{"evidence_id": "EV-0001", "event_id": "EVT-EV-0001-000001"}]

    finding = manager.create(case_id="INC-0001", title="X", created_by="alice", evidence_refs=refs)

    assert finding.evidence_refs == refs


def test_create_rejects_malformed_evidence_ref(tmp_path):
    manager = FindingManager(tmp_path)

    with pytest.raises(FindingError):
        manager.create(
            case_id="INC-0001", title="X", created_by="alice", evidence_refs=[{"evidence_id": "EV-0001"}]
        )


def test_create_rejects_unknown_event_id_when_valid_set_given(tmp_path):
    manager = FindingManager(tmp_path)
    refs = [{"evidence_id": "EV-0001", "event_id": "EVT-FAKE"}]

    with pytest.raises(FindingError):
        manager.create(
            case_id="INC-0001",
            title="X",
            created_by="alice",
            evidence_refs=refs,
            valid_event_ids={"EVT-EV-0001-000001"},
        )


def test_create_accepts_known_event_id_when_valid_set_given(tmp_path):
    manager = FindingManager(tmp_path)
    refs = [{"evidence_id": "EV-0001", "event_id": "EVT-EV-0001-000001"}]

    finding = manager.create(
        case_id="INC-0001",
        title="X",
        created_by="alice",
        evidence_refs=refs,
        valid_event_ids={"EVT-EV-0001-000001"},
    )

    assert finding.evidence_refs == refs


def test_load_round_trips_saved_finding(tmp_path):
    manager = FindingManager(tmp_path)
    created = manager.create(case_id="INC-0001", title="X", created_by="alice")

    loaded = manager.load(created.finding_id)

    assert loaded == created


def test_load_missing_finding_raises(tmp_path):
    manager = FindingManager(tmp_path)

    with pytest.raises(FindingError):
        manager.load("F-9999")


def test_list_returns_all_findings_sorted(tmp_path):
    manager = FindingManager(tmp_path)
    manager.create(case_id="INC-0001", title="First", created_by="alice")
    manager.create(case_id="INC-0001", title="Second", created_by="alice")

    findings = manager.list()

    assert [f.finding_id for f in findings] == ["F-0001", "F-0002"]


def test_list_empty_returns_empty_list(tmp_path):
    manager = FindingManager(tmp_path)

    assert manager.list() == []


def test_list_skips_corrupt_finding_file(tmp_path):
    manager = FindingManager(tmp_path)
    good = manager.create(case_id="INC-0001", title="Good", created_by="alice")
    (manager.findings_dir / "F-0002.json").write_text("{not valid json", encoding="utf-8")

    findings = manager.list()

    assert [f.finding_id for f in findings] == [good.finding_id]


def test_update_status_persists(tmp_path):
    manager = FindingManager(tmp_path)
    finding = manager.create(case_id="INC-0001", title="X", created_by="alice")

    updated = manager.update_status(finding.finding_id, "Confirmed")

    assert updated.status == "Confirmed"
    reloaded = manager.load(finding.finding_id)
    assert reloaded.status == "Confirmed"


def test_update_status_rejects_invalid_value(tmp_path):
    manager = FindingManager(tmp_path)
    finding = manager.create(case_id="INC-0001", title="X", created_by="alice")

    with pytest.raises(FindingError):
        manager.update_status(finding.finding_id, "Not A Status")


def test_add_note_appends_and_persists(tmp_path):
    manager = FindingManager(tmp_path)
    finding = manager.create(case_id="INC-0001", title="X", created_by="alice")

    updated = manager.add_note(finding.finding_id, "Confirmed via process ancestry review.", "bob")

    assert len(updated.investigator_notes) == 1
    assert updated.investigator_notes[0]["text"] == "Confirmed via process ancestry review."
    assert updated.investigator_notes[0]["author"] == "bob"
    reloaded = manager.load(finding.finding_id)
    assert len(reloaded.investigator_notes) == 1


def test_all_spec_statuses_are_valid():
    assert VALID_STATUSES == ("Open", "Investigating", "Confirmed", "Rejected", "False Positive", "Resolved")


def test_finding_to_dict_and_from_dict_round_trip():
    finding = Finding(
        finding_id="F-0001",
        case_id="INC-0001",
        title="t",
        status="Open",
        severity="Medium",
        assessment="a",
        evidence_refs=[],
        investigator_notes=[],
        created_by="alice",
        created_at="t",
        updated_at="t",
    )

    assert Finding.from_dict(finding.to_dict()) == finding
