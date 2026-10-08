"""Evidence and chain-of-custody integrity.

Covers the guarantees added after the proof scorecard (proof/scorecard.py)
showed three gaps: the custody log's tail could be cut off undetected, there
was no `evidence verify` command, and `analyze` parsed evidence without
re-hashing it first.
"""

import json
import os
import stat

import pytest
from typer.testing import CliRunner

from netforensicai.cli import app as cli_app
from netforensicai.core import audit
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.export import export_case, import_case

runner = CliRunner()


# --------------------------------------------------------------------------
# Custody log: truncation, head anchor, externally noted hash
# --------------------------------------------------------------------------


def _record(case_dir, count):
    return [audit.record(case_dir, audit.EVIDENCE_ADDED, {"evidence_id": f"EV-{i:04d}"}) for i in range(count)]


def _rewrite_log(case_dir, keep):
    path = audit.audit_path(case_dir)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("".join(line + "\n" for line in lines[:keep]), encoding="utf-8")


def test_audit_tail_truncation_is_detected(tmp_path):
    _record(tmp_path, 5)
    _rewrite_log(tmp_path, keep=4)  # drop the newest entry

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert any("truncated" in p and "1 entr" in p for p in problems), problems


def test_deleting_several_newest_entries_reports_how_many(tmp_path):
    _record(tmp_path, 6)
    _rewrite_log(tmp_path, keep=2)

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert any("newest 4" in p for p in problems), problems


def test_emptying_the_log_is_detected(tmp_path):
    _record(tmp_path, 3)
    audit.audit_path(tmp_path).write_text("", encoding="utf-8")

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert any("empty" in p for p in problems), problems


def test_untouched_log_with_head_verifies(tmp_path):
    _record(tmp_path, 4)

    ok, problems = audit.verify(tmp_path)

    assert ok, problems
    assert audit.read_head(tmp_path) == {"sequence": 4, "entry_hash": audit.read_entries(tmp_path)[-1]["entry_hash"]}


def test_a_case_that_predates_the_head_file_still_verifies(tmp_path):
    _record(tmp_path, 3)
    audit.head_path(tmp_path).unlink()

    ok, problems = audit.verify(tmp_path)

    assert ok, problems


def test_head_that_lags_the_log_is_not_a_problem(tmp_path):
    """A crash between appending an entry and updating audit.head leaves the head one behind."""
    _record(tmp_path, 3)
    stale = audit.head_path(tmp_path).read_text(encoding="utf-8")
    audit.record(tmp_path, audit.FINDING_CREATED, {"finding_id": "F-0001"})
    audit.head_path(tmp_path).write_text(stale, encoding="utf-8")  # head still says 3 of 4

    ok, problems = audit.verify(tmp_path)

    assert ok, problems


def test_head_that_no_longer_matches_its_entry_is_detected(tmp_path):
    _record(tmp_path, 3)
    head = json.loads(audit.head_path(tmp_path).read_text(encoding="utf-8"))
    head["entry_hash"] = "f" * 64
    audit.head_path(tmp_path).write_text(json.dumps(head), encoding="utf-8")

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert any("rewritten" in p for p in problems), problems


@pytest.mark.parametrize("content", ["not json", "[]", '{"sequence": "3", "entry_hash": 1}'])
def test_unreadable_head_is_reported_not_ignored(tmp_path, content):
    _record(tmp_path, 2)
    audit.head_path(tmp_path).write_text(content, encoding="utf-8")

    ok, problems = audit.verify(tmp_path)

    assert not ok
    assert any("cannot be read" in p for p in problems), problems


def test_an_entry_is_still_recorded_when_the_head_cannot_be_written(tmp_path, monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(audit, "_write_head", boom)

    entry = audit.record(tmp_path, audit.CASE_CREATED, {"name": "x"})

    assert entry is not None, "the action was recorded; losing the head must not report it as lost"
    assert len(audit.read_entries(tmp_path)) == 1


def test_expected_head_still_in_chain_passes_even_after_more_entries(tmp_path):
    entries = _record(tmp_path, 3)
    noted = entries[-1]["entry_hash"]
    _record(tmp_path, 2)  # legitimate later work

    ok, problems = audit.verify(tmp_path, expected_head=noted)

    assert ok, problems


def test_expected_head_catches_truncation_even_when_the_head_file_is_rewritten(tmp_path):
    """The case a rewritten audit.head cannot hide: the investigator noted a hash elsewhere."""
    entries = _record(tmp_path, 5)
    noted = entries[-1]["entry_hash"]
    _rewrite_log(tmp_path, keep=3)
    audit.head_path(tmp_path).unlink()  # attacker also removes the on-disk anchor

    assert audit.verify(tmp_path)[0], "without the external value the cut is invisible - the documented limit"
    ok, problems = audit.verify(tmp_path, expected_head=noted)

    assert not ok
    assert any("not in the log" in p for p in problems), problems


def test_expected_head_accepts_a_prefix_of_at_least_12_characters(tmp_path):
    noted = _record(tmp_path, 2)[-1]["entry_hash"]

    assert audit.verify(tmp_path, expected_head=noted[:12])[0]
    assert audit.verify(tmp_path, expected_head=noted[:12].upper())[0]


@pytest.mark.parametrize("value", ["abc", "zzzzzzzzzzzzzzzz", "a" * 11])
def test_expected_head_rejects_values_too_short_or_not_hex(tmp_path, value):
    _record(tmp_path, 2)

    ok, problems = audit.verify(tmp_path, expected_head=value)

    assert not ok
    assert any("--expect-head" in p for p in problems), problems


def test_head_travels_with_an_exported_case_and_verifies_after_import(tmp_path):
    cases_dir = tmp_path / "cases"
    created = runner.invoke(cli_app, ["case", "create", "--name", "Handover", "--cases-dir", str(cases_dir)])
    assert created.exit_code == 0, created.output

    archive = export_case(cases_dir / "INC-0001", tmp_path / "case.zip")
    imported_dir = tmp_path / "elsewhere"
    case_id = import_case(archive, imported_dir)

    ok, problems = audit.verify(imported_dir / case_id)
    assert ok, problems
    assert audit.head_path(imported_dir / case_id).exists()


# --------------------------------------------------------------------------
# Evidence hashing: `evidence verify` and the check inside `analyze`
# --------------------------------------------------------------------------


def _make_case(tmp_path, files=1):
    cases_dir = tmp_path / "cases"
    created = runner.invoke(cli_app, ["case", "create", "--name", "Integrity", "--cases-dir", str(cases_dir)])
    assert created.exit_code == 0, created.output
    for i in range(files):
        source = tmp_path / f"events{i}.json"
        source.write_text(
            json.dumps(
                [{"timestamp": "2026-01-01T00:00:00Z", "event_type": "dns_query", "domain": f"h{i}.example.test"}]
            ),
            encoding="utf-8",
        )
        added = runner.invoke(
            cli_app, ["evidence", "add", str(source), "--case", "INC-0001", "--cases-dir", str(cases_dir)]
        )
        assert added.exit_code == 0, added.output
    return cases_dir


def _tamper(cases_dir, evidence_id):
    stored = EvidenceManager(cases_dir / "INC-0001").stored_file_path(evidence_id)
    os.chmod(stored, os.stat(stored).st_mode | stat.S_IWUSR)
    with open(stored, "ab") as handle:
        handle.write(b"\n ")
    return stored


def _cli(cases_dir, *args):
    return runner.invoke(cli_app, [*args, "--case", "INC-0001", "--cases-dir", str(cases_dir)])


def _actions(cases_dir):
    return [e["action"] for e in audit.read_entries(cases_dir / "INC-0001")]


def test_evidence_verify_passes_on_untouched_evidence_and_is_recorded(tmp_path):
    cases_dir = _make_case(tmp_path, files=2)

    result = _cli(cases_dir, "evidence", "verify")

    assert result.exit_code == 0, result.output
    assert result.output.count("verified") >= 2
    assert "match their recorded SHA-256" in result.output
    assert audit.EVIDENCE_VERIFIED in _actions(cases_dir)


def test_evidence_verify_catches_modified_evidence(tmp_path):
    cases_dir = _make_case(tmp_path, files=2)
    _tamper(cases_dir, "EV-0002")

    result = _cli(cases_dir, "evidence", "verify")

    assert result.exit_code == 1
    assert "EV-0002" in result.output and "MISMATCH" in result.output
    assert "EV-0001" in result.output  # the intact item is still listed as verified
    assert audit.EVIDENCE_INTEGRITY_FAILED in _actions(cases_dir)


def test_evidence_verify_reports_a_missing_stored_file(tmp_path):
    cases_dir = _make_case(tmp_path)
    os.remove(EvidenceManager(cases_dir / "INC-0001").stored_file_path("EV-0001"))

    result = _cli(cases_dir, "evidence", "verify")

    assert result.exit_code == 1
    assert "MISSING" in result.output


def test_evidence_verify_can_target_one_item(tmp_path):
    cases_dir = _make_case(tmp_path, files=2)
    _tamper(cases_dir, "EV-0002")

    clean = runner.invoke(
        cli_app, ["evidence", "verify", "EV-0001", "--case", "INC-0001", "--cases-dir", str(cases_dir)]
    )
    dirty = runner.invoke(
        cli_app, ["evidence", "verify", "EV-0002", "--case", "INC-0001", "--cases-dir", str(cases_dir)]
    )

    assert clean.exit_code == 0, clean.output
    assert dirty.exit_code == 1


def test_evidence_verify_rejects_an_unknown_id(tmp_path):
    cases_dir = _make_case(tmp_path)

    result = runner.invoke(
        cli_app, ["evidence", "verify", "EV-9999", "--case", "INC-0001", "--cases-dir", str(cases_dir)]
    )

    assert result.exit_code == 1


def test_analyze_refuses_modified_evidence_and_exits_nonzero(tmp_path):
    cases_dir = _make_case(tmp_path, files=2)
    _tamper(cases_dir, "EV-0002")

    result = _cli(cases_dir, "analyze")

    assert result.exit_code == 2, result.output
    assert "INTEGRITY CHECK FAILED" in result.output
    assert "EV-0002" in result.output and "NOT analysed" in result.output
    assert "EV-0001 (json): 1 events" in result.output, "intact evidence is still analysed"
    assert "EV-0002 (json): skipped" in result.output
    assert audit.EVIDENCE_INTEGRITY_FAILED in _actions(cases_dir)


def test_analyze_on_intact_evidence_is_unchanged(tmp_path):
    cases_dir = _make_case(tmp_path, files=2)

    result = _cli(cases_dir, "analyze")

    assert result.exit_code == 0, result.output
    assert "INTEGRITY" not in result.output
    assert "Analysis complete" in result.output
    assert audit.EVIDENCE_INTEGRITY_FAILED not in _actions(cases_dir)


def test_analyze_reports_a_missing_stored_file_as_an_integrity_failure(tmp_path):
    cases_dir = _make_case(tmp_path)
    os.remove(EvidenceManager(cases_dir / "INC-0001").stored_file_path("EV-0001"))

    result = _cli(cases_dir, "analyze")

    assert result.exit_code == 2, result.output
    assert "INTEGRITY CHECK FAILED" in result.output


# --------------------------------------------------------------------------
# `case audit` CLI
# --------------------------------------------------------------------------


def test_case_audit_verify_prints_a_head_hash_that_expect_head_accepts(tmp_path):
    cases_dir = _make_case(tmp_path)

    verified = _cli(cases_dir, "case", "audit", "--verify")
    assert verified.exit_code == 0, verified.output
    head_line = next(line for line in verified.output.splitlines() if line.startswith("Head:"))
    noted = head_line.rsplit("hash ", 1)[1].strip()
    assert len(noted) == 64

    _cli(cases_dir, "analyze")  # more custody entries after the hash was noted
    later = runner.invoke(
        cli_app,
        ["case", "audit", "--verify", "--expect-head", noted, "--case", "INC-0001", "--cases-dir", str(cases_dir)],
    )
    assert later.exit_code == 0, later.output


def test_case_audit_expect_head_fails_for_a_hash_that_is_not_in_the_log(tmp_path):
    cases_dir = _make_case(tmp_path)

    result = runner.invoke(
        cli_app,
        [
            "case", "audit", "--verify", "--expect-head", "ab" * 32,
            "--case", "INC-0001", "--cases-dir", str(cases_dir),
        ],
    )  # fmt: skip

    assert result.exit_code == 1
    assert "BROKEN" in result.output


def test_case_audit_verify_reports_truncation_via_the_cli(tmp_path):
    cases_dir = _make_case(tmp_path)
    _cli(cases_dir, "analyze")
    case_dir = cases_dir / "INC-0001"
    _rewrite_log(case_dir, keep=len(audit.read_entries(case_dir)) - 1)

    result = _cli(cases_dir, "case", "audit", "--verify")

    assert result.exit_code == 1
    assert "truncated" in result.output
