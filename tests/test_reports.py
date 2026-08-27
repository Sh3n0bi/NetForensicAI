import json

import pytest

from netforensicai.core.case import CaseManager
from netforensicai.core.correlation import correlate_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.finding import FindingManager
from netforensicai.core.report import build_report, render_html, render_json, render_markdown
from netforensicai.core.store import CaseStore


@pytest.fixture
def prepared_case(tmp_path):
    """A case with one evidence item, parsed events, entities, correlation,
    and one finding - enough to exercise every report section with real
    content."""
    case_manager = CaseManager(tmp_path / "cases")
    case = case_manager.create(name="Report test case", description="desc", investigator="alice")
    case_dir = tmp_path / "cases" / case.case_id

    source = tmp_path / "events.json"
    source.write_text(
        json.dumps(
            [
                {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe", "src_ip": "192.168.1.10"},
                {"timestamp": "2026-08-27T09:00:30Z", "type": "network_connection", "src_ip": "192.168.1.10", "dst_ip": "203.0.113.7", "dst_port": 4444},
            ]
        ),
        encoding="utf-8",
    )
    evidence_manager = EvidenceManager(case_dir)
    evidence = evidence_manager.add(source, case_id=case.case_id)
    case_manager.register_evidence(case.case_id, evidence.evidence_id)

    from netforensicai.parsers.generic import JsonParser

    events = JsonParser().parse(evidence_manager.stored_file_path(evidence.evidence_id), evidence_id=evidence.evidence_id)

    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence(evidence.evidence_id, events)
        extract_and_store(store, events)
        correlate_case(store)

    finding_manager = FindingManager(case_dir)
    finding = finding_manager.create(
        case_id=case.case_id,
        title="Suspicious outbound connection",
        created_by="alice",
        severity="High",
        evidence_refs=[{"evidence_id": evidence.evidence_id, "event_id": events[1].event_id}],
    )
    finding_manager.add_note(finding.finding_id, "Reviewed and escalated.", "bob")

    return case_manager.load(case.case_id), case_dir


def test_build_report_sections_populated(prepared_case):
    case, case_dir = prepared_case

    report = build_report(case, case_dir)

    assert report["case"]["case_id"] == case.case_id
    assert len(report["evidence_sources"]) == 1
    assert report["evidence_sources"][0]["integrity_status"] == "verified"
    assert len(report["affected_entities"]) > 0
    assert len(report["timeline"]) == 2
    assert any(e["entity_type"] == "ip_address" for e in report["network_indicators"])
    assert len(report["investigation_findings"]) == 1
    assert report["investigation_findings"][0]["title"] == "Suspicious outbound connection"
    assert report["investigation_findings"][0]["investigator_notes"][0]["text"] == "Reviewed and escalated."
    assert "no potential att&ck techniques detected" in report["attack_mapping_note"].lower()
    assert report["attack_techniques"] == []
    assert len(report["limitations"]) > 0
    assert len(report["recommendations"]) > 0


def test_build_report_empty_case_has_no_crashes(tmp_path):
    case_manager = CaseManager(tmp_path / "cases")
    case = case_manager.create(name="Empty case")
    case_dir = tmp_path / "cases" / case.case_id

    report = build_report(case, case_dir)

    assert report["evidence_sources"] == []
    assert report["affected_entities"] == []
    assert report["timeline"] == []
    assert report["investigation_findings"] == []
    assert "no findings" in report["recommendations"][0].lower() or "no findings" in " ".join(report["recommendations"]).lower()


def test_build_report_detects_tampered_evidence(tmp_path):
    import os
    import stat

    case_manager = CaseManager(tmp_path / "cases")
    case = case_manager.create(name="Tamper test")
    case_dir = tmp_path / "cases" / case.case_id

    source = tmp_path / "sample.json"
    source.write_text("[]", encoding="utf-8")
    evidence_manager = EvidenceManager(case_dir)
    evidence = evidence_manager.add(source, case_id=case.case_id)

    stored = evidence_manager.stored_file_path(evidence.evidence_id)
    os.chmod(stored, stat.S_IWRITE | stat.S_IREAD)
    stored.write_bytes(b"tampered content")

    report = build_report(case, case_dir)

    assert report["evidence_sources"][0]["integrity_status"] == "MISMATCH - possible tampering"


def test_render_json_round_trips(prepared_case):
    case, case_dir = prepared_case
    report = build_report(case, case_dir)

    text = render_json(report)
    parsed = json.loads(text)

    assert parsed["case"]["case_id"] == case.case_id
    assert parsed["investigation_findings"][0]["finding_id"] == report["investigation_findings"][0]["finding_id"]


def test_render_markdown_includes_all_section_headers(prepared_case):
    case, case_dir = prepared_case
    report = build_report(case, case_dir)

    text = render_markdown(report)

    for header in [
        "Case Information", "Executive Summary", "Evidence Sources", "Evidence Integrity",
        "Affected Entities", "Timeline", "Artifacts", "Network Indicators",
        "Threat Intelligence", "Investigation Findings", "Potential ATT&CK Mapping",
        "Investigator Notes", "Limitations", "Recommendations",
    ]:
        assert f"## {header}" in text or f"# {header}" in text, header

    assert case.case_id in text
    assert "Suspicious outbound connection" in text


def test_render_html_escapes_user_supplied_content(tmp_path):
    case_manager = CaseManager(tmp_path / "cases")
    case = case_manager.create(name="<script>alert(1)</script>", description="d")
    case_dir = tmp_path / "cases" / case.case_id

    report = build_report(case, case_dir)
    text = render_html(report)

    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_render_html_includes_findings(prepared_case):
    case, case_dir = prepared_case
    report = build_report(case, case_dir)

    text = render_html(report)

    assert "Suspicious outbound connection" in text
    assert "Reviewed and escalated." in text
    assert "<html>" in text


def test_report_reflects_cached_threat_intel_results(prepared_case):
    from datetime import datetime, timezone

    case, case_dir = prepared_case
    with CaseStore(case_dir) as store:
        store.record_threat_intel(
            "ENT-ip_address-abc",
            "ip_address",
            "192.168.1.10",
            "virustotal",
            {"malicious": True, "malicious_count": 5, "total_engines": 70, "permalink": "https://x", "error": None},
            datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc),
        )

    report = build_report(case, case_dir)

    assert len(report["threat_intelligence_results"]) == 1
    result = report["threat_intelligence_results"][0]
    assert result["value"] == "192.168.1.10"
    assert result["malicious"] is True
    assert result["checked_at"] == "2026-08-27T10:00:00+00:00"
    assert "cached from those runs" in report["threat_intelligence_note"]

    markdown = render_markdown(report)
    assert "192.168.1.10" in markdown
    assert "YES (5/70)" in markdown

    html_text = render_html(report)
    assert "192.168.1.10" in html_text
    assert "YES (5/70)" in html_text


def test_report_without_threat_intel_shows_generic_note(prepared_case):
    case, case_dir = prepared_case

    report = build_report(case, case_dir)

    assert report["threat_intelligence_results"] == []
    assert "no results have been recorded" in report["threat_intelligence_note"]


def test_report_shows_no_detections_when_never_scanned(prepared_case):
    case, case_dir = prepared_case

    report = build_report(case, case_dir)

    assert report["detections"] == []
    assert "no bundled detection rules matched" in report["detections_note"].lower()


def test_report_shows_detections_table_when_present(prepared_case):
    from netforensicai.core.detections import scan_case

    case, case_dir = prepared_case
    with CaseStore(case_dir) as store:
        scan_case(store)  # the fixture's network_connection targets dst_port=4444 (SUSPICIOUS-PORT)

    report = build_report(case, case_dir)

    assert len(report["detections"]) == 1
    detection = report["detections"][0]
    assert detection["rule_id"] == "SUSPICIOUS-PORT"
    assert detection["severity"] == "medium"
    assert "deterministic pattern matches" in report["detections_note"].lower()

    markdown = render_markdown(report)
    assert "SUSPICIOUS-PORT" not in markdown  # the table shows rule_name, not rule_id
    assert "Connection to a historically suspicious port" in markdown

    html_text = render_html(report)
    assert "Connection to a historically suspicious port" in html_text


def test_report_reflects_detected_attack_techniques(prepared_case):
    from netforensicai.core.attack import scan_case

    case, case_dir = prepared_case
    with CaseStore(case_dir) as store:
        scan_case(store)  # events fixture includes a PowerShell process_start? verify below

    report = build_report(case, case_dir)

    # The prepared_case fixture's events are authentication + network_connection,
    # neither of which trigger any current rule - confirm the "none detected" path
    # still works correctly even after a real scan_case() run finds nothing.
    assert report["attack_techniques"] == []
    assert "no potential att&ck techniques detected" in report["attack_mapping_note"].lower()


def test_report_shows_technique_table_when_present(prepared_case):
    from datetime import datetime, timezone

    case, case_dir = prepared_case
    with CaseStore(case_dir) as store:
        store.upsert_technique("T1059.001", "Command and Scripting Interpreter: PowerShell", "medium", datetime.now(timezone.utc))
        store.link_technique_event("T1059.001", "EVT-FAKE-0001", "EV-0001", "test basis")

    report = build_report(case, case_dir)

    assert len(report["attack_techniques"]) == 1
    technique = report["attack_techniques"][0]
    assert technique["technique_id"] == "T1059.001"
    assert technique["status"] == "potential"
    assert technique["event_count"] == 1
    assert "deterministic rule-based suggestions" in report["attack_mapping_note"].lower()

    markdown = render_markdown(report)
    assert "T1059.001" in markdown
    assert "Command and Scripting Interpreter: PowerShell" in markdown

    html_text = render_html(report)
    assert "T1059.001" in html_text
