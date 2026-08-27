from netforensicai.core.case import Case, CaseError, CaseManager, SUBDIRS


def test_create_case_sets_fields_and_layout(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    case = manager.create(name="Test Incident", description="desc", investigator="alice")

    assert case.case_id == "INC-0001"
    assert case.name == "Test Incident"
    assert case.investigator == "alice"
    assert case.status == "open"
    assert case.evidence == []
    assert case.created_at == case.updated_at

    case_path = tmp_path / "cases" / "INC-0001"
    assert (case_path / "case.json").exists()
    for sub in SUBDIRS:
        assert (case_path / sub).is_dir()


def test_case_ids_increment(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    first = manager.create(name="First")
    second = manager.create(name="Second")

    assert first.case_id == "INC-0001"
    assert second.case_id == "INC-0002"


def test_create_rejects_empty_name(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    try:
        manager.create(name="   ")
        assert False, "expected CaseError"
    except CaseError:
        pass


def test_load_round_trips_saved_case(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    created = manager.create(name="Roundtrip")

    loaded = manager.load(created.case_id)

    assert loaded == created


def test_load_missing_case_raises(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    try:
        manager.load("INC-9999")
        assert False, "expected CaseError"
    except CaseError:
        pass


def test_load_rejects_path_traversal_case_id(tmp_path):
    # case_id reaches CaseManager directly from web API URL segments with
    # no upstream validation - _case_path() must refuse anything that
    # isn't a well-formed INC-#### id rather than resolving it as a path.
    manager = CaseManager(tmp_path / "cases")
    (tmp_path / "secret.json").write_text('{"leaked": true}')

    for malicious_id in ("../secret", "..\\secret", "../../etc/passwd", "INC-0001/../../secret"):
        try:
            manager.load(malicious_id)
            assert False, f"expected CaseError for {malicious_id!r}"
        except CaseError:
            pass


def test_list_returns_all_cases_sorted(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    manager.create(name="First")
    manager.create(name="Second")

    cases = manager.list()

    assert [c.case_id for c in cases] == ["INC-0001", "INC-0002"]


def test_list_empty_dir_returns_empty_list(tmp_path):
    manager = CaseManager(tmp_path / "cases")

    assert manager.list() == []


def test_list_skips_corrupt_case_json(tmp_path, caplog):
    manager = CaseManager(tmp_path / "cases")
    good = manager.create(name="Good")

    corrupt_dir = tmp_path / "cases" / "INC-0002"
    corrupt_dir.mkdir()
    (corrupt_dir / "case.json").write_text("{not valid json", encoding="utf-8")

    cases = manager.list()

    assert [c.case_id for c in cases] == [good.case_id]


def test_update_status_persists_and_bumps_updated_at(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    case = manager.create(name="Status test")

    updated = manager.update_status(case.case_id, "investigating")

    assert updated.status == "investigating"
    assert updated.updated_at >= case.created_at
    reloaded = manager.load(case.case_id)
    assert reloaded.status == "investigating"


def test_update_status_rejects_invalid_value(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    case = manager.create(name="Bad status")

    try:
        manager.update_status(case.case_id, "not-a-real-status")
        assert False, "expected CaseError"
    except CaseError:
        pass


def test_register_finding_updates_index_and_is_idempotent(tmp_path):
    manager = CaseManager(tmp_path / "cases")
    case = manager.create(name="Findings index test")

    manager.register_finding(case.case_id, "F-0001")
    updated = manager.register_finding(case.case_id, "F-0001")

    assert updated.findings == ["F-0001"]


def test_case_to_dict_and_from_dict_round_trip():
    case = Case(
        case_id="INC-0001",
        name="n",
        description="d",
        investigator="i",
        created_at="t",
        updated_at="t",
    )

    assert Case.from_dict(case.to_dict()) == case
