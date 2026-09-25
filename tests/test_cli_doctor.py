"""Tests for `netforensic doctor` and `version`, and the diagnostics service."""

import json

from typer.testing import CliRunner

from netforensicai.cli import app
from netforensicai.core import diagnostics

runner = CliRunner()


def test_version_command_prints_a_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip()  # some version string


def test_version_flag_prints_and_exits():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip()


def test_doctor_runs_and_reports_core_checks(tmp_path):
    result = runner.invoke(app, ["doctor", "--cases-dir", str(tmp_path / "cases")])
    # DuckDB and Python are always present in the test env, so no core error.
    assert result.exit_code == 0
    assert "Python" in result.output
    assert "DuckDB" in result.output


def test_doctor_json_is_valid_and_structured(tmp_path):
    result = runner.invoke(app, ["doctor", "--cases-dir", str(tmp_path / "cases"), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["overall"] in (diagnostics.OK, diagnostics.WARNING, diagnostics.MISSING, diagnostics.ERROR)
    assert isinstance(payload["checks"], list) and payload["checks"]
    for check in payload["checks"]:
        assert set(check) == {"name", "status", "detail"}


def test_run_checks_covers_the_expected_capabilities(tmp_path):
    names = [c.name for c in diagnostics.run_checks(str(tmp_path / "cases"))]
    for expected in ("Python", "DuckDB (case store)", "Cases directory", "tshark (fast pcap engine)", "dumpcap (live capture)"):
        assert expected in names


def test_run_checks_flags_an_unwritable_or_bad_cases_dir(tmp_path):
    # A path that exists as a *file* cannot be a cases directory.
    bad = tmp_path / "not-a-dir"
    bad.write_text("x")
    checks = {c.name: c for c in diagnostics.run_checks(str(bad))}
    assert checks["Cases directory"].status == diagnostics.ERROR


def test_python_check_is_ok_in_this_environment(tmp_path):
    checks = {c.name: c for c in diagnostics.run_checks(str(tmp_path))}
    assert checks["Python"].status == diagnostics.OK
    # overall is never worse than an error; here there is no core error.
    assert diagnostics.overall_status(diagnostics.run_checks(str(tmp_path))) != diagnostics.ERROR
