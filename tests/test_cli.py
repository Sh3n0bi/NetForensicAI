"""End-to-end CLI tests, driven through the real Typer app rather than
calling internal functions directly - proves case/evidence/parse/analyze
are actually wired together correctly, not just individually correct."""

import json

from typer.testing import CliRunner

from netforensicai.cli import app
from netforensicai.core.store import CaseStore

runner = CliRunner()


def _write_json_evidence(path, records):
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def test_end_to_end_case_evidence_analyze_flow(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "events.json",
        [
            {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "alice", "src_ip": "10.0.0.5"},
            {"timestamp": "2026-08-27T09:05:00Z", "type": "network_connection", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 53},
        ],
    )

    create_result = runner.invoke(app, ["case", "create", "--name", "CLI test case", "--cases-dir", str(cases_dir)])
    assert create_result.exit_code == 0, create_result.output
    assert "INC-0001" in create_result.output

    add_result = runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert add_result.exit_code == 0, add_result.output
    assert "EV-0001" in add_result.output

    analyze_result = runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert analyze_result.exit_code == 0, analyze_result.output
    assert "2 events" in analyze_result.output

    case_dir = cases_dir / "INC-0001"
    with CaseStore(case_dir) as store:
        assert store.count_events() == 2
        entities = store.list_entities()
        assert any(e["entity_type"] == "user" and e["value"] == "alice" for e in entities)
        assert any(e["entity_type"] == "ip_address" and e["value"] == "10.0.0.5" for e in entities)


def test_parse_single_evidence_item(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(tmp_path / "single.json", [{"type": "dns_query", "domain": "example.com"}])

    runner.invoke(app, ["case", "create", "--name", "Single parse test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    parse_result = runner.invoke(
        app, ["parse", "--case", "INC-0001", "--evidence", "EV-0001", "--cases-dir", str(cases_dir)]
    )

    assert parse_result.exit_code == 0, parse_result.output
    assert "1 events" in parse_result.output


def test_reparsing_same_evidence_does_not_duplicate_events(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(tmp_path / "dup.json", [{"type": "dns_query", "domain": "example.com"}])

    runner.invoke(app, ["case", "create", "--name", "Reparse test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["parse", "--case", "INC-0001", "--evidence", "EV-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["parse", "--case", "INC-0001", "--evidence", "EV-0001", "--cases-dir", str(cases_dir)])

    with CaseStore(cases_dir / "INC-0001") as store:
        assert store.count_events() == 1


def test_analyze_reports_missing_case(tmp_path):
    result = runner.invoke(app, ["analyze", "--case", "INC-9999", "--cases-dir", str(tmp_path / "cases")])

    assert result.exit_code == 1


def test_analyze_with_no_evidence_reports_and_exits_cleanly(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Empty case", "--cases-dir", str(cases_dir)])

    result = runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    assert result.exit_code == 0
    assert "No evidence" in result.output
