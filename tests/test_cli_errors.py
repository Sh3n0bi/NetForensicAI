"""CLI error-path and exit-code coverage.

The happy paths are covered in test_cli.py; these prove the commands fail
*cleanly* - a non-zero exit and a message on stderr, not a traceback - when
pointed at a missing case, a missing file, or a bad argument. That contract
is what lets these commands be scripted.
"""

from typer.testing import CliRunner

from netforensicai.cli import app

runner = CliRunner()


def _empty_cases(tmp_path):
    d = tmp_path / "cases"
    d.mkdir()
    return str(d)


def _assert_clean_failure(result):
    # Non-zero exit, and it failed by design (Exit) rather than crashing.
    assert result.exit_code != 0, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output


# --- commands against a case that does not exist ---------------------------


def test_analyze_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["analyze", "--case", "INC-9999", "--cases-dir", _empty_cases(tmp_path)])
    _assert_clean_failure(result)


def test_story_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["story", "--case", "INC-9999", "--cases-dir", _empty_cases(tmp_path)])
    _assert_clean_failure(result)


def test_detections_list_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["detections", "list", "--case", "INC-9999", "--cases-dir", _empty_cases(tmp_path)])
    _assert_clean_failure(result)


def test_report_generate_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(
        app,
        ["report", "generate", "--case", "INC-9999", "--format", "markdown", "--cases-dir", _empty_cases(tmp_path)],
    )
    _assert_clean_failure(result)


def test_timeline_show_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["timeline", "show", "--case", "INC-9999", "--cases-dir", _empty_cases(tmp_path)])
    _assert_clean_failure(result)


def test_investigate_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(
        app, ["investigate", "--case", "INC-9999", "--ip", "10.0.0.1", "--cases-dir", _empty_cases(tmp_path)]
    )
    _assert_clean_failure(result)


def test_finding_list_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["finding", "list", "--case", "INC-9999", "--cases-dir", _empty_cases(tmp_path)])
    _assert_clean_failure(result)


def test_ioc_list_missing_case_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["ioc", "list", "--case", "INC-9999", "--cases-dir", _empty_cases(tmp_path)])
    _assert_clean_failure(result)


# --- missing / bad files ---------------------------------------------------


def test_evidence_add_missing_file_fails_cleanly(tmp_path):
    cases = _empty_cases(tmp_path)
    created = runner.invoke(app, ["case", "create", "--name", "err case", "--cases-dir", cases])
    assert created.exit_code == 0, created.output
    result = runner.invoke(
        app, ["evidence", "add", str(tmp_path / "does-not-exist.pcap"), "--case", "INC-0001", "--cases-dir", cases]
    )
    _assert_clean_failure(result)


def test_evidence_add_to_missing_case_fails_cleanly(tmp_path):
    evidence = tmp_path / "e.json"
    evidence.write_text("[]", encoding="utf-8")
    result = runner.invoke(
        app, ["evidence", "add", str(evidence), "--case", "INC-9999", "--cases-dir", _empty_cases(tmp_path)]
    )
    _assert_clean_failure(result)


def test_parse_missing_file_fails_cleanly(tmp_path):
    result = runner.invoke(app, ["parse", str(tmp_path / "nope.pcap")])
    _assert_clean_failure(result)


# --- bad arguments ---------------------------------------------------------


def test_report_generate_rejects_unknown_format(tmp_path):
    cases = _empty_cases(tmp_path)
    runner.invoke(app, ["case", "create", "--name", "fmt case", "--cases-dir", cases])
    result = runner.invoke(
        app, ["report", "generate", "--case", "INC-0001", "--format", "not-a-format", "--cases-dir", cases]
    )
    _assert_clean_failure(result)


def test_unknown_command_is_a_usage_error():
    result = runner.invoke(app, ["definitely-not-a-command"])
    assert result.exit_code != 0
