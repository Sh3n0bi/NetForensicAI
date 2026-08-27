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


def test_timeline_build_and_show(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "timeline_events.json",
        [
            {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "alice"},
            {"timestamp": "2026-08-27T09:05:00Z", "type": "dns_query", "domain": "example.com"},
        ],
    )

    runner.invoke(app, ["case", "create", "--name", "Timeline test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    build_result = runner.invoke(app, ["timeline", "build", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert build_result.exit_code == 0, build_result.output
    assert "2 entries" in build_result.output
    assert (cases_dir / "INC-0001" / "timeline" / "timeline.json").exists()

    show_result = runner.invoke(app, ["timeline", "show", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert show_result.exit_code == 0, show_result.output
    assert "authentication" in show_result.output
    assert "dns_query" in show_result.output

    filtered_result = runner.invoke(
        app, ["timeline", "show", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--user", "alice"]
    )
    assert "authentication" in filtered_result.output
    assert "dns_query" not in filtered_result.output


def test_timeline_show_bad_time_filter_reports_error(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Bad filter test", "--cases-dir", str(cases_dir)])

    result = runner.invoke(
        app, ["timeline", "show", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--from", "not-a-date"]
    )

    assert result.exit_code == 1


def test_investigate_known_ip_reports_full_result(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "investigate_events.json",
        [
            {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe", "src_ip": "192.168.1.10"},
            {"timestamp": "2026-08-27T09:00:30Z", "type": "network_connection", "src_ip": "192.168.1.10", "dst_ip": "203.0.113.7"},
        ],
    )

    runner.invoke(app, ["case", "create", "--name", "Investigate test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    result = runner.invoke(app, ["investigate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--ip", "192.168.1.10"])

    assert result.exit_code == 0, result.output
    assert "Entity: ip_address '192.168.1.10'" in result.output
    assert "Related Evidence:" in result.output
    assert "EV-0001" in result.output
    assert "Timeline:" in result.output
    assert "authentication" in result.output
    assert "network_connection" in result.output
    assert "Related Entities:" in result.output
    assert "Potential Investigation Leads:" in result.output
    assert "Threat Intelligence:" in result.output
    assert "not checked" in result.output  # no --vt-api given


def test_investigate_unknown_entity_reports_not_found(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Not found test", "--cases-dir", str(cases_dir)])

    result = runner.invoke(app, ["investigate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--ip", "10.0.0.99"])

    assert result.exit_code == 0
    assert "No evidence" in result.output


def test_investigate_requires_exactly_one_entity_flag(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Flag validation test", "--cases-dir", str(cases_dir)])

    no_flags_result = runner.invoke(app, ["investigate", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert no_flags_result.exit_code == 1

    two_flags_result = runner.invoke(
        app,
        ["investigate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--ip", "10.0.0.5", "--user", "alice"],
    )
    assert two_flags_result.exit_code == 1


def test_finding_create_list_and_update(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "finding_events.json",
        [{"timestamp": "2026-08-27T09:00:00Z", "type": "process_start", "process": "powershell.exe"}],
    )

    runner.invoke(app, ["case", "create", "--name", "Finding test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    create_result = runner.invoke(
        app,
        [
            "finding", "create",
            "--case", "INC-0001",
            "--cases-dir", str(cases_dir),
            "--title", "Suspicious PowerShell Execution",
            "--severity", "High",
            "--event", "EVT-EV-0001-000001",
        ],
    )
    assert create_result.exit_code == 0, create_result.output
    assert "F-0001" in create_result.output
    assert "EVT-EV-0001-000001" in create_result.output

    list_result = runner.invoke(app, ["finding", "list", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert "F-0001" in list_result.output
    assert "Open" in list_result.output
    assert "High" in list_result.output

    update_result = runner.invoke(
        app,
        [
            "finding", "update",
            "--case", "INC-0001",
            "--cases-dir", str(cases_dir),
            "--finding", "F-0001",
            "--status", "Confirmed",
            "--note", "Verified via process ancestry.",
        ],
    )
    assert update_result.exit_code == 0, update_result.output
    assert "status=Confirmed" in update_result.output
    assert "notes=1" in update_result.output

    final_list = runner.invoke(app, ["finding", "list", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert "Confirmed" in final_list.output


def test_finding_create_rejects_unknown_event_id(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Bad event ref test", "--cases-dir", str(cases_dir)])

    result = runner.invoke(
        app,
        [
            "finding", "create",
            "--case", "INC-0001",
            "--cases-dir", str(cases_dir),
            "--title", "X",
            "--event", "EVT-DOES-NOT-EXIST",
        ],
    )

    assert result.exit_code == 1


def test_finding_update_requires_status_or_note(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Update validation test", "--cases-dir", str(cases_dir)])
    runner.invoke(
        app,
        ["finding", "create", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--title", "X"],
    )

    result = runner.invoke(
        app, ["finding", "update", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--finding", "F-0001"]
    )

    assert result.exit_code == 1
