"""Tests for case deletion and status changes.

Deletion is the one operation here that destroys evidence, so most of
these are about what STOPS it: the confirmation, the path guard, and the
fact that it reports what it removed rather than saying "done" about work
nobody can check afterwards.
"""

import json

import pytest
from typer.testing import CliRunner

from netforensicai.cli import app as cli_app
from netforensicai.core.case import CaseError, CaseManager
from netforensicai.core.evidence import EvidenceManager
from netforensicai.web.app import create_app

runner = CliRunner()


@pytest.fixture
def seeded(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="Doomed", investigator="analyst")
    case_dir = cases_dir / case.case_id

    source = tmp_path / "events.json"
    source.write_text(json.dumps([{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication"}]), encoding="utf-8")
    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)

    return cases_dir, manager, case, case_dir


# --- the guard ----------------------------------------------------------


def test_delete_needs_the_case_id_as_confirmation(seeded):
    """A boolean flag defaults to something, and the something is wrong at
    least once. Typing the ID is what separates the case they meant from
    the one that happened to be selected."""
    cases_dir, manager, case, case_dir = seeded

    with pytest.raises(CaseError, match="confirmation"):
        manager.delete(case.case_id)
    with pytest.raises(CaseError, match="confirmation"):
        manager.delete(case.case_id, confirm_case_id="INC-9999")

    assert case_dir.exists(), "the case must survive a failed confirmation"


def test_delete_removes_everything_and_reports_what_it_removed(seeded):
    cases_dir, manager, case, case_dir = seeded

    summary = manager.delete(case.case_id, confirm_case_id=case.case_id)

    assert not case_dir.exists()
    assert summary["case_id"] == case.case_id
    assert summary["name"] == "Doomed"
    assert summary["evidence_count"] == 1
    assert summary["size_bytes"] > 0
    assert manager.list() == []


def test_deleting_a_case_that_does_not_exist_is_an_error(tmp_path):
    manager = CaseManager(tmp_path / "cases")

    with pytest.raises(CaseError, match="not found"):
        manager.delete("INC-0001", confirm_case_id="INC-0001")


def test_a_traversing_case_id_cannot_reach_outside_the_cases_directory(tmp_path):
    """This is a recursive delete; the id arrives from a URL path segment."""
    outside = tmp_path / "precious"
    outside.mkdir()
    manager = CaseManager(tmp_path / "cases")

    for bad in ("../../precious", "..", "/etc", "INC-0001/../.."):
        with pytest.raises(CaseError):
            manager.delete(bad, confirm_case_id=bad)

    assert outside.exists()


def test_deleting_one_case_leaves_the_others(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    keep = manager.create(name="Keep")
    doomed = manager.create(name="Doomed")

    manager.delete(doomed.case_id, confirm_case_id=doomed.case_id)

    assert [c.case_id for c in manager.list()] == [keep.case_id]


# --- status -------------------------------------------------------------


def test_status_moves_between_the_valid_values(seeded):
    _cases_dir, manager, case, _case_dir = seeded

    assert manager.update_status(case.case_id, "investigating").status == "investigating"
    assert manager.update_status(case.case_id, "closed").status == "closed"


def test_an_unknown_status_is_rejected(seeded):
    _cases_dir, manager, case, _case_dir = seeded

    with pytest.raises(CaseError, match="Invalid status"):
        manager.update_status(case.case_id, "done")


# --- web ----------------------------------------------------------------


@pytest.fixture
def client(seeded):
    cases_dir, _manager, case, case_dir = seeded
    c = create_app(cases_dir).test_client()
    c.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"
    return c, case, case_dir


def test_web_delete_requires_confirmation(client):
    c, case, case_dir = client

    assert c.delete(f"/api/cases/{case.case_id}", json={}).status_code == 400
    assert c.delete(f"/api/cases/{case.case_id}", json={"confirm": "INC-9999"}).status_code == 400
    assert case_dir.exists()


def test_web_delete_removes_the_case_and_returns_a_summary(client):
    c, case, case_dir = client

    response = c.delete(f"/api/cases/{case.case_id}", json={"confirm": case.case_id})

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["evidence_count"] == 1
    assert not case_dir.exists()
    assert c.get(f"/api/cases/{case.case_id}").status_code == 404


def test_web_delete_needs_the_csrf_header(seeded):
    """Deleting a case from a cross-origin fetch must not be possible."""
    cases_dir, _manager, case, case_dir = seeded
    bare = create_app(cases_dir).test_client()

    response = bare.delete(f"/api/cases/{case.case_id}", json={"confirm": case.case_id})

    assert response.status_code == 403
    assert case_dir.exists()


def test_web_status_change(client):
    c, case, _case_dir = client

    response = c.post(f"/api/cases/{case.case_id}/status", json={"status": "closed"})

    assert response.status_code == 200
    assert response.get_json()["status"] == "closed"


def test_web_status_rejects_an_unknown_value(client):
    c, case, _case_dir = client

    assert c.post(f"/api/cases/{case.case_id}/status", json={"status": "finished"}).status_code == 400


# --- CLI ----------------------------------------------------------------


def test_cli_delete_refuses_a_mistyped_confirmation(seeded):
    cases_dir, _manager, case, case_dir = seeded

    result = runner.invoke(
        cli_app, ["case", "delete", "--case", case.case_id, "--cases-dir", str(cases_dir)], input="nope\n"
    )

    assert result.exit_code == 1
    assert "Not deleted" in result.output
    assert case_dir.exists()


def test_cli_delete_accepts_the_typed_case_id(seeded):
    cases_dir, _manager, case, case_dir = seeded

    result = runner.invoke(
        cli_app,
        ["case", "delete", "--case", case.case_id, "--cases-dir", str(cases_dir)],
        input=f"{case.case_id}\n",
    )

    assert result.exit_code == 0, result.output
    assert "Deleted" in result.output
    assert not case_dir.exists()


def test_cli_delete_shows_what_will_go_before_asking(seeded):
    """The prompt has to say what is about to be destroyed - including
    that the chain of custody goes with it."""
    cases_dir, _manager, case, _case_dir = seeded

    result = runner.invoke(
        cli_app, ["case", "delete", "--case", case.case_id, "--cases-dir", str(cases_dir)], input="\n"
    )

    assert "Evidence items" in result.output
    assert "chain of custody" in result.output


def test_cli_status(seeded):
    cases_dir, manager, case, _case_dir = seeded

    result = runner.invoke(
        cli_app, ["case", "status", "--case", case.case_id, "closed", "--cases-dir", str(cases_dir)]
    )

    assert result.exit_code == 0, result.output
    assert manager.load(case.case_id).status == "closed"
