"""The web UI's investigation-team endpoints (web/team_runs.py + app.py).

The real agents, roles, read-only tools and citation checks run; only the
model is scripted (ai_assistant.call_model), so nothing reaches a network.
Runs happen on a background thread, so tests wait for them to finish.
"""

import json
import threading
import time

import pytest

from netforensicai.core import ai_assistant, audit, config
from netforensicai.core.finding import FindingManager
from netforensicai.web import team_runs
from netforensicai.web.app import CSRF_HEADER, CSRF_HEADER_VALUE, create_app
from tests.test_cli_team import _add_json_case, _ScriptedModel

W = {CSRF_HEADER: CSRF_HEADER_VALUE}


def _wait(case_id, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = team_runs.get_run(case_id)
        if run is not None and run.state != "running":
            return run
        time.sleep(0.05)
    raise AssertionError("team run did not finish")


@pytest.fixture
def team_case(tmp_path, monkeypatch):
    cases_dir, case_id, evidence_id, events = _add_json_case(tmp_path)
    client = create_app(cases_dir).test_client()
    return client, cases_dir, case_id, evidence_id, events


def test_status_before_any_run(team_case):
    client, _cases_dir, case_id, _ev, _events = team_case
    body = client.get(f"/api/cases/{case_id}/team").get_json()

    assert body["run"] is None
    assert body["latest"] is None
    assert [r["slug"] for r in body["available_roles"]] == ["network", "host"]
    assert body["provider"] == "anthropic"  # nothing saved in (isolated) Settings


def test_run_merges_findings_persists_and_audits(team_case, monkeypatch):
    client, cases_dir, case_id, evidence_id, events = team_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))

    resp = client.post(f"/api/cases/{case_id}/team", json={"provider": "gemini", "api_key": "sk-DO-NOT-STORE"}, headers=W)
    assert resp.status_code == 202, resp.get_json()
    assert resp.get_json()["state"] == "running"

    run = _wait(case_id)
    assert run.state == "done"
    assert run.completed_roles == ["Network Forensics", "Host & Endpoint (DFIR)"]

    body = client.get(f"/api/cases/{case_id}/team").get_json()
    latest = body["latest"]
    assert latest["provider"] == "gemini"
    assert len(latest["findings"]) == 1  # both roles cited the same event -> merged
    assert latest["findings"][0]["reported_by"] == ["network", "host"]

    # Persisted for reloads - and the API key is never written.
    stored = (cases_dir / case_id / "team" / "latest.json").read_text(encoding="utf-8")
    assert "sk-DO-NOT-STORE" not in stored

    entries = [e for e in audit.read_entries(cases_dir / case_id) if e["action"] == audit.AI_TEAM_RUN]
    assert len(entries) == 1
    assert entries[0]["details"]["provider"] == "gemini"
    assert entries[0]["details"]["outcome"] == "completed"
    assert entries[0]["details"]["roles_run"] == ["network", "host"]
    ok, problems = audit.verify(cases_dir / case_id)
    assert ok, problems


def test_accept_creates_one_open_finding(team_case, monkeypatch):
    client, cases_dir, case_id, evidence_id, events = team_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    _wait(case_id)

    resp = client.post(f"/api/cases/{case_id}/team/findings/0/accept", json={"investigator": "alice"}, headers=W)
    assert resp.status_code == 201, resp.get_json()
    finding = resp.get_json()
    assert finding["status"] == "Open"
    assert finding["severity"] == "High"
    assert finding["created_by"] == "alice"
    assert finding["evidence_refs"] == [{"evidence_id": evidence_id, "event_id": events[1].event_id}]

    again = client.post(f"/api/cases/{case_id}/team/findings/0/accept", json={}, headers=W)
    assert again.status_code == 409
    assert finding["finding_id"] in again.get_json()["error"]

    latest = client.get(f"/api/cases/{case_id}/team").get_json()["latest"]
    assert latest["accepted"] == {"0": finding["finding_id"]}
    assert len(FindingManager(cases_dir / case_id).list()) == 1


def test_accept_rejects_unknown_index_and_needs_csrf(team_case, monkeypatch):
    client, _cases_dir, case_id, evidence_id, events = team_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    _wait(case_id)

    assert client.post(f"/api/cases/{case_id}/team/findings/7/accept", json={}, headers=W).status_code == 404
    assert client.post(f"/api/cases/{case_id}/team/findings/0/accept", json={}).status_code == 403
    assert client.post(f"/api/cases/{case_id}/team", json={}).status_code == 403


def test_accept_refuses_a_citation_that_no_longer_exists(team_case, monkeypatch):
    client, cases_dir, case_id, evidence_id, events = team_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    _wait(case_id)

    latest = team_runs.load_latest(cases_dir / case_id)
    latest["findings"][0]["citations"][0]["reference"] = "EVT-EV-0001-424242"
    team_runs.save_latest(cases_dir / case_id, latest)

    resp = client.post(f"/api/cases/{case_id}/team/findings/0/accept", json={}, headers=W)
    assert resp.status_code == 409
    assert FindingManager(cases_dir / case_id).list() == []


def test_one_run_at_a_time_and_no_accepting_mid_run(team_case, monkeypatch):
    client, cases_dir, case_id, evidence_id, events = team_case
    release = threading.Event()

    def slow_model(system_prompt, user_prompt, **_kwargs):
        release.wait(10)
        return {"action": "findings", "findings": []}

    monkeypatch.setattr(ai_assistant, "call_model", slow_model)
    assert client.post(f"/api/cases/{case_id}/team", json={}, headers=W).status_code == 202

    second = client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    assert second.status_code == 409
    status = client.get(f"/api/cases/{case_id}/team").get_json()
    assert status["run"]["state"] == "running"
    assert status["run"]["current_role"] == "Network Forensics"
    assert client.post(f"/api/cases/{case_id}/team/findings/0/accept", json={}, headers=W).status_code == 409

    release.set()
    assert _wait(case_id).state == "done"


def test_provider_failure_is_reported_and_audited(team_case, monkeypatch):
    client, cases_dir, case_id, _ev, _events = team_case

    def broken(*_a, **_k):
        raise ai_assistant.AssistantError("No API key configured for anthropic")

    monkeypatch.setattr(ai_assistant, "call_model", broken)
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    run = _wait(case_id)

    assert run.state == "failed"
    assert "provider failed" in run.error
    latest = client.get(f"/api/cases/{case_id}/team").get_json()["latest"]
    assert "provider failed" in latest["error"]
    entry = [e for e in audit.read_entries(cases_dir / case_id) if e["action"] == audit.AI_TEAM_RUN][-1]
    assert entry["details"]["outcome"] == "failed"


def test_a_crash_ends_the_run_instead_of_hanging(team_case, monkeypatch):
    client, _cases_dir, case_id, _ev, _events = team_case

    def boom(*_a, **_k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("netforensicai.agents.investigate", boom)
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    run = _wait(case_id)
    assert run.state == "failed"
    assert "unexpected" in run.error


def test_bad_requests(team_case, tmp_path):
    client, cases_dir, case_id, _ev, _events = team_case
    assert client.post(f"/api/cases/{case_id}/team", json={"roles": ["wizard"]}, headers=W).status_code == 400
    assert client.post(f"/api/cases/{case_id}/team", json={"max_steps": 0}, headers=W).status_code == 400
    assert client.post(f"/api/cases/{case_id}/team", json={"max_steps": "x"}, headers=W).status_code == 400

    empty = client.post("/api/cases", json={"name": "Empty"}, headers=W).get_json()
    resp = client.post(f"/api/cases/{empty['case_id']}/team", json={}, headers=W)
    assert resp.status_code == 400
    assert "no evidence" in resp.get_json()["error"]


def test_saved_settings_provider_is_used_by_team_and_chat(team_case, monkeypatch):
    # Regression: the saved "Default AI provider" used to be ignored.
    client, _cases_dir, case_id, evidence_id, events = team_case
    config.save_settings({"ai_provider": "ollama", "ai_model": "llama3.1"})

    assert client.get(f"/api/cases/{case_id}/team").get_json()["provider"] == "ollama"

    seen = {}

    def fake_ask(question, case_dir, provider=None, model=None, **_kwargs):
        seen.update(provider=provider, model=model)
        from netforensicai.core.chat import ChatResult

        return ChatResult(answer="ok", evidence_sufficient=True, citations=[], steps=[])

    monkeypatch.setattr("netforensicai.core.chat.ask", fake_ask)
    client.post(f"/api/cases/{case_id}/chat", json={"question": "hi"}, headers=W)
    assert seen == {"provider": "ollama", "model": "llama3.1"}


def test_only_latest_result_file_is_json(team_case, monkeypatch):
    client, cases_dir, case_id, evidence_id, events = team_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: None))
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    _wait(case_id)
    files = sorted(p.name for p in (cases_dir / case_id / "team").iterdir())
    assert files == ["latest.json"]
    json.loads((cases_dir / case_id / "team" / "latest.json").read_text(encoding="utf-8"))


def test_progress_lists_only_roles_that_will_run(tmp_path, monkeypatch):
    # A Suricata/pcap-only case: the host analyst is skipped, so it must not be
    # shown as "queued" while the run is in progress.
    fake_roles = []

    def fake_investigate(case_dir, roles, evidence_types, progress, **_kwargs):
        from netforensicai.agents import TeamResult

        fake_roles.extend(r.slug for r in roles)
        return TeamResult()

    from netforensicai.agents import all_roles

    run = team_runs.start_run(
        "INC-0009", tmp_path, roles=all_roles(), evidence_types={"pcap"}, provider="ollama", api_key=None,
        model=None, base_url=None, actor="t", investigate=fake_investigate, record=lambda *a, **k: None,
    )
    assert run.snapshot()["roles"] == ["Network Forensics"]
    _wait("INC-0009")
    assert fake_roles == ["network", "host"]  # investigate still gets both, and scopes itself


def test_rerun_keeps_accepted_findings_marked(team_case, monkeypatch):
    # Accepting, then running again, must not offer "Accept" on the same
    # evidence a second time - that is one click from a duplicate finding.
    client, cases_dir, case_id, evidence_id, events = team_case
    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    _wait(case_id)
    first = client.post(f"/api/cases/{case_id}/team/findings/0/accept", json={}, headers=W).get_json()

    monkeypatch.setattr(ai_assistant, "call_model", _ScriptedModel(evidence_id, cite=lambda slug: events[1].event_id))
    client.post(f"/api/cases/{case_id}/team", json={}, headers=W)
    _wait(case_id)

    latest = client.get(f"/api/cases/{case_id}/team").get_json()["latest"]
    assert latest["accepted"] == {"0": first["finding_id"]}
    assert client.post(f"/api/cases/{case_id}/team/findings/0/accept", json={}, headers=W).status_code == 409
    assert len(FindingManager(cases_dir / case_id).list()) == 1


def test_carry_over_matches_on_evidence_not_wording():
    cite = {"kind": "event", "evidence_id": "EV-0001", "reference": "E1"}
    previous = {"findings": [{"title": "Old wording", "citations": [cite]}], "accepted": {"0": "F-0003"}}
    new = [
        {"title": "Unrelated", "citations": [{"kind": "event", "evidence_id": "EV-0001", "reference": "E2"}]},
        {"title": "New wording, same evidence", "citations": [cite]},
    ]
    assert team_runs.carry_over_accepted(previous, new) == {"1": "F-0003"}
    assert team_runs.carry_over_accepted(None, new) == {}
