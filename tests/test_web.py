"""API-level tests for the web UI backend, using Flask's test client.
Seeds a case through the real core modules (same pattern as the other
integration tests), then exercises the JSON API - proves the web layer
is correctly wired to the existing core modules, not a reimplementation."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from netforensicai.core.case import CaseManager
from netforensicai.core.correlation import correlate_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.finding import FindingManager
from netforensicai.core.store import CaseStore
from netforensicai.web.app import create_app


@pytest.fixture
def prepared_case(tmp_path):
    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Web UI test case", investigator="alice")
    case_dir = cases_dir / case.case_id

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
    finding_manager.create(
        case_id=case.case_id,
        title="Suspicious outbound connection",
        created_by="alice",
        evidence_refs=[{"evidence_id": evidence.evidence_id, "event_id": events[1].event_id}],
    )

    app = create_app(cases_dir)
    client = app.test_client()
    return client, case, cases_dir


def test_index_serves_html(prepared_case):
    client, _case, _cases_dir = prepared_case

    response = client.get("/")

    assert response.status_code == 200
    assert b"<html" in response.data.lower() or b"<!doctype" in response.data.lower()


def test_list_cases(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get("/api/cases")

    assert response.status_code == 200
    data = response.get_json()
    assert any(c["case_id"] == case.case_id for c in data)


def test_get_case_includes_counts(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}")

    assert response.status_code == 200
    data = response.get_json()
    assert data["evidence_count"] == 1
    assert data["event_count"] == 2
    assert data["entity_count"] > 0
    assert data["finding_count"] == 1


def test_get_case_missing_returns_404(prepared_case):
    client, _case, _cases_dir = prepared_case

    response = client.get("/api/cases/INC-9999")

    assert response.status_code == 404
    assert "error" in response.get_json()


def test_list_evidence(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/evidence")

    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 1
    assert data[0]["evidence_type"] == "json"


def test_timeline_unfiltered(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/timeline")

    assert response.status_code == 200
    assert len(response.get_json()) == 2


def test_timeline_filtered_by_user(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/timeline?user=jdoe")

    data = response.get_json()
    assert len(data) == 1
    assert data[0]["event_type"] == "authentication"


def test_list_entities_and_search(prepared_case):
    client, case, _cases_dir = prepared_case

    all_entities = client.get(f"/api/cases/{case.case_id}/entities").get_json()
    assert len(all_entities) > 0

    filtered = client.get(f"/api/cases/{case.case_id}/entities?q=192.168").get_json()
    assert all("192.168" in e["value"] for e in filtered)
    assert len(filtered) >= 1


def test_entity_graph(prepared_case):
    client, case, _cases_dir = prepared_case

    entities = client.get(f"/api/cases/{case.case_id}/entities?type=ip_address").get_json()
    entity_id = next(e["entity_id"] for e in entities if e["value"] == "192.168.1.10")

    response = client.get(f"/api/cases/{case.case_id}/entities/{entity_id}/graph")

    assert response.status_code == 200
    data = response.get_json()
    assert data["entity"]["value"] == "192.168.1.10"
    assert isinstance(data["related"], list)


def test_entity_graph_missing_entity_returns_404(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/entities/ENT-does-not-exist/graph")

    assert response.status_code == 404


def test_investigate_endpoint(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/investigate?type=ip_address&value=192.168.1.10")

    assert response.status_code == 200
    data = response.get_json()
    assert data["entity"]["value"] == "192.168.1.10"
    assert len(data["timeline"]) >= 1
    assert isinstance(data["leads"], list)


def test_investigate_missing_params_returns_400(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/investigate?type=ip_address")

    assert response.status_code == 400


def test_investigate_unknown_entity_returns_404(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/investigate?type=ip_address&value=10.0.0.99")

    assert response.status_code == 404


def test_list_findings(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/findings")

    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 1
    assert data[0]["title"] == "Suspicious outbound connection"


def test_report_markdown(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/report/markdown")

    assert response.status_code == 200
    assert response.mimetype == "text/markdown"
    assert case.case_id in response.get_data(as_text=True)


def test_report_json(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/report/json")

    assert response.status_code == 200
    data = json.loads(response.get_data(as_text=True))
    assert data["case"]["case_id"] == case.case_id


def test_report_unsupported_format(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/report/pdf")

    assert response.status_code == 400


def test_threat_intel_endpoint_missing_fields(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.post(f"/api/cases/{case.case_id}/threat-intel", json={})

    assert response.status_code == 400


def test_threat_intel_endpoint_calls_provider(prepared_case):
    client, case, _cases_dir = prepared_case

    entities = client.get(f"/api/cases/{case.case_id}/entities?type=ip_address").get_json()
    entity = next(e for e in entities if e["value"] == "192.168.1.10")

    with patch(
        "netforensicai.intel.virustotal.check_ip",
        return_value={"malicious": True, "malicious_count": 3, "total_engines": 70, "permalink": "https://x", "error": None},
    ):
        response = client.post(
            f"/api/cases/{case.case_id}/threat-intel",
            json={
                "entity_id": entity["entity_id"],
                "entity_type": "ip_address",
                "value": "192.168.1.10",
                "api_key": "fake-key",
            },
        )

    assert response.status_code == 200
    assert response.get_json()["malicious"] is True


def test_ai_hypothesis_endpoint(prepared_case):
    client, case, _cases_dir = prepared_case
    from netforensicai.core.ai_assistant import EvidenceCitation, Hypothesis

    hypothesis = Hypothesis(
        evidence_sufficient=True,
        claim="May represent routine authentication.",
        assessment="Likely benign",
        observed_evidence=["User jdoe authenticated."],
        confidence="low",
        alternative_explanation="Normal login.",
        recommended_validation="Confirm work hours.",
        evidence=[],
    )
    mock_response = MagicMock()
    mock_response.parsed_output = hypothesis
    mock_client = MagicMock()
    mock_client.messages.parse.return_value = mock_response

    with patch("anthropic.Anthropic", return_value=mock_client):
        response = client.post(
            f"/api/cases/{case.case_id}/ai-hypothesis",
            json={"entity_type": "ip_address", "value": "192.168.1.10", "api_key": "fake-key"},
        )

    assert response.status_code == 200
    data = response.get_json()
    assert data["claim"] == "May represent routine authentication."


def test_ai_hypothesis_endpoint_reports_assistant_error(prepared_case):
    client, case, _cases_dir = prepared_case

    with patch(
        "anthropic.Anthropic",
        side_effect=TypeError("Could not resolve authentication method."),
    ):
        response = client.post(
            f"/api/cases/{case.case_id}/ai-hypothesis",
            json={"entity_type": "ip_address", "value": "192.168.1.10"},
        )

    assert response.status_code == 502
    assert "credentials" in response.get_json()["error"]


# --- evidence upload + analyze ---


def test_upload_evidence(prepared_case):
    import io

    client, case, cases_dir = prepared_case

    content = b'[{"timestamp": "2026-08-27T10:00:00Z", "type": "authentication", "user": "newuser"}]'
    response = client.post(
        f"/api/cases/{case.case_id}/evidence",
        data={"file": (io.BytesIO(content), "uploaded.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 201, response.get_json()
    data = response.get_json()
    assert data["evidence_id"] == "EV-0002"
    assert data["filename"] == "uploaded.json"
    assert data["evidence_type"] == "json"

    stored_path = cases_dir / case.case_id / "evidence" / "EV-0002" / "original" / "uploaded.json"
    assert stored_path.exists()
    assert stored_path.read_bytes() == content


def test_upload_evidence_no_file_returns_400(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.post(f"/api/cases/{case.case_id}/evidence", data={}, content_type="multipart/form-data")

    assert response.status_code == 400


def test_upload_evidence_missing_case_returns_404(prepared_case):
    import io

    client, _case, _cases_dir = prepared_case

    response = client.post(
        "/api/cases/INC-9999/evidence",
        data={"file": (io.BytesIO(b"{}"), "x.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 404


def test_analyze_endpoint_parses_new_evidence(prepared_case):
    import io

    client, case, _cases_dir = prepared_case

    client.post(
        f"/api/cases/{case.case_id}/evidence",
        data={"file": (io.BytesIO(b'[{"timestamp": "2026-08-27T10:00:00Z", "type": "x", "user": "newuser"}]'), "more.json")},
        content_type="multipart/form-data",
    )

    response = client.post(f"/api/cases/{case.case_id}/analyze")

    assert response.status_code == 200
    data = response.get_json()
    assert len(data["results"]) == 2  # original EV-0001 + the newly uploaded EV-0002
    assert data["total_events"] >= 3
    assert all(r["error"] is None for r in data["results"])

    entities = client.get(f"/api/cases/{case.case_id}/entities?q=newuser").get_json()
    assert len(entities) == 1


# --- live capture ---


def test_capture_status_when_not_running(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.get(f"/api/cases/{case.case_id}/capture/status")

    assert response.status_code == 200
    assert response.get_json() == {"running": False}


def test_capture_start_status_stop_lifecycle(prepared_case):
    client, case, _cases_dir = prepared_case

    with patch("scapy.all.AsyncSniffer") as mock_sniffer_cls:
        mock_sniffer_cls.return_value = MagicMock()

        start_response = client.post(f"/api/cases/{case.case_id}/capture/start", json={"interface": "fake0"})
        assert start_response.status_code == 200, start_response.get_json()

        status_response = client.get(f"/api/cases/{case.case_id}/capture/status")
        status = status_response.get_json()
        assert status["running"] is True
        assert status["interface"] == "fake0"

        second_start = client.post(f"/api/cases/{case.case_id}/capture/start", json={"interface": "fake0"})
        assert second_start.status_code == 409

        stop_response = client.post(f"/api/cases/{case.case_id}/capture/stop")
        assert stop_response.status_code == 200

        status_after_stop = client.get(f"/api/cases/{case.case_id}/capture/status").get_json()
        assert status_after_stop["running"] is False


def test_capture_stop_when_never_started_returns_404(prepared_case):
    client, case, _cases_dir = prepared_case

    response = client.post(f"/api/cases/{case.case_id}/capture/stop")

    assert response.status_code == 404


def test_capture_start_missing_case_returns_404(prepared_case):
    client, _case, _cases_dir = prepared_case

    response = client.post("/api/cases/INC-9999/capture/start", json={})

    assert response.status_code == 404


def test_list_interfaces_endpoint(prepared_case):
    client, _case, _cases_dir = prepared_case

    response = client.get("/api/interfaces")

    assert response.status_code == 200
    assert isinstance(response.get_json(), list)
