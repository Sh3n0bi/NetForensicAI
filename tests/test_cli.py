"""End-to-end CLI tests, driven through the real Typer app rather than
calling internal functions directly - proves case/evidence/parse/analyze
are actually wired together correctly, not just individually correct."""

import json

import pytest
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


def test_analyze_reports_true_distinct_entity_count_across_evidence(tmp_path):
    # Regression: analyze's printed "distinct entities" count previously
    # summed each evidence item's own entity_count, which double-counts
    # any entity shared across evidence items (e.g. the same IP appearing
    # in two different sources) - exactly the case correlation exists to
    # find. The true count must match store.count_entities().
    cases_dir = tmp_path / "cases"
    evidence_a = _write_json_evidence(
        tmp_path / "a.json", [{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "src_ip": "10.0.0.5"}]
    )
    evidence_b = _write_json_evidence(
        tmp_path / "b.json",
        [{"timestamp": "2026-08-27T09:05:00Z", "type": "network_connection", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8"}],
    )

    runner.invoke(app, ["case", "create", "--name", "Shared entity test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_a), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_b), "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    result = runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    assert result.exit_code == 0, result.output
    # Entities: ip_address(10.0.0.5), ip_address(8.8.8.8), and the
    # network_connection synthesized from evidence_b's src_ip+dst_ip pair
    # = 3 distinct total. 10.0.0.5 is touched by both evidence items, so
    # the old buggy sum (1 entity from EV-0001 + 3 from EV-0002 = 4) would
    # have over-reported by exactly the one entity they share.
    assert "3 distinct entities" in result.output
    assert "4 distinct entities" not in result.output

    with CaseStore(cases_dir / "INC-0001") as store:
        assert store.count_entities() == 3


def test_analyze_reports_and_lists_detections(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "events.json",
        [
            {"timestamp": "2026-08-27T09:00:00Z", "type": "process_start", "process_name": "mimikatz.exe"},
            {"timestamp": "2026-08-27T09:05:00Z", "type": "network_connection", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 4444},
        ],
    )

    runner.invoke(app, ["case", "create", "--name", "Detections test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    analyze_result = runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert analyze_result.exit_code == 0, analyze_result.output
    assert "Detections: 2 rule match(es)" in analyze_result.output
    assert "netforensic detections list" in analyze_result.output

    list_result = runner.invoke(app, ["detections", "list", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    assert list_result.exit_code == 0, list_result.output
    assert "OFFENSIVE-TOOL-NAME" in list_result.output
    assert "SUSPICIOUS-PORT" in list_result.output


def test_analyze_reports_no_detections_cleanly(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "events.json", [{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "alice"}]
    )

    runner.invoke(app, ["case", "create", "--name", "No detections test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    analyze_result = runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    assert analyze_result.exit_code == 0
    assert "Detections: none." in analyze_result.output


def test_detections_list_filters_by_severity(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "events.json",
        [
            {"timestamp": "2026-08-27T09:00:00Z", "type": "process_start", "process_name": "mimikatz.exe"},  # high
            {"timestamp": "2026-08-27T09:05:00Z", "type": "network_connection", "dst_port": 4444},  # medium
        ],
    )

    runner.invoke(app, ["case", "create", "--name", "Severity filter test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    result = runner.invoke(
        app, ["detections", "list", "--case", "INC-0001", "--severity", "high", "--cases-dir", str(cases_dir)]
    )

    assert result.exit_code == 0, result.output
    assert "OFFENSIVE-TOOL-NAME" in result.output
    assert "SUSPICIOUS-PORT" not in result.output


def test_detections_list_before_analyze_reports_cleanly(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Empty detections test", "--cases-dir", str(cases_dir)])

    result = runner.invoke(app, ["detections", "list", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    assert result.exit_code == 0, result.output
    assert "No detections" in result.output


def test_case_export_import_round_trip_via_cli(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "events.json", [{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "alice"}]
    )

    runner.invoke(app, ["case", "create", "--name", "Export CLI test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    archive_path = tmp_path / "INC-0001.zip"
    export_result = runner.invoke(
        app, ["case", "export", "--case", "INC-0001", "--output", str(archive_path), "--cases-dir", str(cases_dir)]
    )
    assert export_result.exit_code == 0, export_result.output
    assert archive_path.exists()

    restored_cases_dir = tmp_path / "restored"
    import_result = runner.invoke(app, ["case", "import", str(archive_path), "--cases-dir", str(restored_cases_dir)])
    assert import_result.exit_code == 0, import_result.output
    assert "INC-0001" in import_result.output

    with CaseStore(restored_cases_dir / "INC-0001") as store:
        assert store.count_events() == 1

    list_result = runner.invoke(app, ["case", "list", "--cases-dir", str(restored_cases_dir)])
    assert "Export CLI test" in list_result.output


def test_case_export_missing_case_reports_error(tmp_path):
    result = runner.invoke(app, ["case", "export", "--case", "INC-9999", "--cases-dir", str(tmp_path / "cases")])

    assert result.exit_code == 1
    assert "not found" in result.output.lower() or "error" in result.output.lower()


def test_case_import_collision_reports_error(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Collision test", "--cases-dir", str(cases_dir)])

    archive_path = tmp_path / "INC-0001.zip"
    runner.invoke(app, ["case", "export", "--case", "INC-0001", "--output", str(archive_path), "--cases-dir", str(cases_dir)])

    result = runner.invoke(app, ["case", "import", str(archive_path), "--cases-dir", str(cases_dir)])  # same cases_dir

    assert result.exit_code == 1
    assert "already exists" in result.output


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


def test_report_generate_all_formats(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "report_events.json",
        [{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "alice", "src_ip": "10.0.0.5"}],
    )

    runner.invoke(app, ["case", "create", "--name", "Report test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(
        app,
        ["finding", "create", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--title", "Test finding"],
    )

    for fmt, ext in (("markdown", "md"), ("json", "json"), ("html", "html")):
        result = runner.invoke(
            app, ["report", "generate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--format", fmt]
        )
        assert result.exit_code == 0, result.output
        report_path = cases_dir / "INC-0001" / "reports" / f"report.{ext}"
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "INC-0001" in content
        assert "Test finding" in content


def test_report_generate_custom_output_path(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Custom output test", "--cases-dir", str(cases_dir)])

    custom_path = tmp_path / "custom_report.md"
    result = runner.invoke(
        app,
        [
            "report", "generate",
            "--case", "INC-0001",
            "--cases-dir", str(cases_dir),
            "--output", str(custom_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert custom_path.exists()


def test_report_generate_rejects_unknown_format(tmp_path):
    cases_dir = tmp_path / "cases"
    runner.invoke(app, ["case", "create", "--name", "Bad format test", "--cases-dir", str(cases_dir)])

    result = runner.invoke(
        app, ["report", "generate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--format", "pdf"]
    )

    assert result.exit_code == 1


def test_report_generate_missing_case_reports_error(tmp_path):
    result = runner.invoke(
        app, ["report", "generate", "--case", "INC-9999", "--cases-dir", str(tmp_path / "cases")]
    )

    assert result.exit_code == 1


def test_investigate_ai_flag_shows_hypothesis(tmp_path):
    # patch("anthropic.Anthropic", ...) needs anthropic importable to
    # resolve the target, even though it's only ever mocked here.
    pytest.importorskip("anthropic")
    from unittest.mock import MagicMock, patch

    from netforensicai.core.ai_assistant import EvidenceCitation, Hypothesis

    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "ai_events.json",
        [{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe", "src_ip": "192.168.1.10"}],
    )

    runner.invoke(app, ["case", "create", "--name", "AI test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    hypothesis = Hypothesis(
        evidence_sufficient=True,
        claim="This may represent a routine logon.",
        assessment="Likely benign authentication",
        observed_evidence=["User jdoe authenticated from 192.168.1.10."],
        confidence="low",
        alternative_explanation="Normal daily login activity.",
        recommended_validation="Confirm against expected work hours.",
        evidence=[EvidenceCitation(evidence_id="EV-0001", event_id="EVT-EV-0001-000001")],
    )
    mock_response = MagicMock()
    mock_response.parsed_output = hypothesis
    mock_client = MagicMock()
    mock_client.messages.parse.return_value = mock_response

    with patch("anthropic.Anthropic", return_value=mock_client):
        result = runner.invoke(
            app,
            ["investigate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--user", "jdoe", "--ai"],
        )

    assert result.exit_code == 0, result.output
    assert "AI Investigation Hypothesis" in result.output
    assert "This may represent a routine logon." in result.output
    assert "Confidence:  low" in result.output
    assert "not a conclusion" in result.output


def test_investigate_ai_flag_reports_a_rejected_credential(tmp_path):
    """The name used to say "without credentials", but the test raises an
    AuthenticationError - which is a key that was sent and REFUSED, not
    one that was missing. The two now produce different messages, and
    conflating them is what sends an investigator to set a variable they
    have already set."""
    pytest.importorskip("anthropic")
    from unittest.mock import patch

    import anthropic

    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "ai_no_creds.json", [{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe"}]
    )

    runner.invoke(app, ["case", "create", "--name", "AI no creds test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    auth_error = anthropic.AuthenticationError.__new__(anthropic.AuthenticationError)
    with patch("anthropic.Anthropic") as mock_anthropic:
        mock_anthropic.return_value.messages.parse.side_effect = auth_error
        result = runner.invoke(
            app,
            ["investigate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--user", "jdoe", "--ai"],
        )

    assert result.exit_code == 0, result.output
    assert "Not available" in result.output
    assert "rejected the credential" in result.output


def test_investigate_without_ai_flag_has_no_hypothesis_section(tmp_path):
    cases_dir = tmp_path / "cases"
    evidence_file = _write_json_evidence(
        tmp_path / "no_ai.json", [{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe"}]
    )

    runner.invoke(app, ["case", "create", "--name", "No AI test", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["evidence", "add", str(evidence_file), "--case", "INC-0001", "--cases-dir", str(cases_dir)])
    runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    result = runner.invoke(app, ["investigate", "--case", "INC-0001", "--cases-dir", str(cases_dir), "--user", "jdoe"])

    assert "AI Investigation Hypothesis" not in result.output
