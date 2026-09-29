"""Every path that sends case content to an AI provider leaves a custody entry.

`investigate --ai` and team runs always did; `chat` (CLI and web) and the web
AI-hypothesis route did not. These pin that each records its request and its
outcome - including refusals and failures, which show an attempt was made -
that the chain still verifies, and that no API key is ever written.
"""

import pytest
from typer.testing import CliRunner

from netforensicai.cli import app
from netforensicai.core import ai_assistant, audit, chat
from netforensicai.core.chat import ChatError, ChatResult, Citation, ToolCall
from netforensicai.web.app import CSRF_HEADER, CSRF_HEADER_VALUE, create_app
from tests.test_cli_team import _add_json_case

W = {CSRF_HEADER: CSRF_HEADER_VALUE}
SECRET = "sk-NEVER-IN-AUDIT"


def _entries(case_dir, action):
    return [e for e in audit.read_entries(case_dir) if e["action"] == action]


def _answer(question, *_a, **_k):
    return ChatResult(
        question=question,
        answer="An executable was fetched from 203.0.113.7.",
        evidence_sufficient=True,
        citations=[Citation(kind="event", evidence_id="EV-0001", reference="EVT-EV-0001-000002")],
        steps=[ToolCall(tool="search_events", arguments={}, summary="2 rows", rows=2)],
    )


@pytest.fixture
def json_case(tmp_path):
    return _add_json_case(tmp_path)


# --- chat: CLI ---


def test_cli_chat_answer_is_recorded(json_case, monkeypatch):
    cases_dir, case_id, _ev, _events = json_case
    monkeypatch.setattr(chat, "ask", _answer)

    result = CliRunner().invoke(
        app, ["chat", "--case", case_id, "--cases-dir", str(cases_dir), "--ai-provider", "gemini",
              "--api-key", SECRET, "was anything downloaded?"],
    )

    assert result.exit_code == 0, result.output
    [entry] = _entries(cases_dir / case_id, audit.AI_CHAT_REQUESTED)
    details = entry["details"]
    assert details["provider"] == "gemini"
    assert details["model"] == "(provider default)"
    assert details["question"] == "was anything downloaded?"
    assert details["outcome"] == "answered"
    assert details["evidence_sufficient"] is True
    assert details["tool_calls"] == ["search_events"]
    assert details["cited"] == ["event:EV-0001/EVT-EV-0001-000002"]
    assert SECRET not in (cases_dir / case_id / audit.AUDIT_FILENAME).read_text(encoding="utf-8")
    ok, problems = audit.verify(cases_dir / case_id)
    assert ok, problems


@pytest.mark.parametrize(
    "message, outcome",
    [
        ("Answer refused: it cited evidence no tool returned (event EV-0001/X).", "refused"),
        ("AI provider failed: 401 Unauthorized", "failed"),
    ],
)
def test_cli_chat_refusal_and_failure_are_recorded(json_case, monkeypatch, message, outcome):
    cases_dir, case_id, _ev, _events = json_case

    def refuse(*_a, **_k):
        raise ChatError(message)

    monkeypatch.setattr(chat, "ask", refuse)
    result = CliRunner().invoke(app, ["chat", "--case", case_id, "--cases-dir", str(cases_dir), "anything?"])

    assert result.exit_code == 1
    [entry] = _entries(cases_dir / case_id, audit.AI_CHAT_REQUESTED)
    assert entry["details"]["outcome"] == outcome
    assert entry["details"]["error"] == message
    assert "tool_calls" not in entry["details"]


def test_long_question_is_truncated_in_the_record(json_case):
    cases_dir, case_id, _ev, _events = json_case
    question = "x" * (chat.AUDIT_QUESTION_CHARS + 100)
    chat.record_chat_request(cases_dir / case_id, question, "ollama", None, error=ChatError("AI provider failed: x"))
    [entry] = _entries(cases_dir / case_id, audit.AI_CHAT_REQUESTED)
    assert len(entry["details"]["question"]) == chat.AUDIT_QUESTION_CHARS + 1
    assert entry["details"]["question"].endswith("…")


# --- chat: web ---


def test_web_chat_answer_and_refusal_are_recorded(json_case, monkeypatch):
    cases_dir, case_id, _ev, _events = json_case
    client = create_app(cases_dir).test_client()

    monkeypatch.setattr(chat, "ask", _answer)
    ok = client.post(f"/api/cases/{case_id}/chat", json={"question": "q1", "provider": "ollama", "api_key": SECRET}, headers=W)
    assert ok.status_code == 200

    def refuse(*_a, **_k):
        raise ChatError("Answer refused: it cited evidence no tool returned.")

    monkeypatch.setattr(chat, "ask", refuse)
    refused = client.post(f"/api/cases/{case_id}/chat", json={"question": "q2"}, headers=W)
    assert refused.status_code == 502

    entries = _entries(cases_dir / case_id, audit.AI_CHAT_REQUESTED)
    assert [(e["details"]["question"], e["details"]["outcome"]) for e in entries] == [("q1", "answered"), ("q2", "refused")]
    assert entries[0]["details"]["provider"] == "ollama"
    assert entries[1]["details"]["provider"] == "anthropic"  # nothing saved in (isolated) Settings
    assert SECRET not in (cases_dir / case_id / audit.AUDIT_FILENAME).read_text(encoding="utf-8")
    assert audit.verify(cases_dir / case_id)[0]


def test_web_chat_empty_question_sends_nothing_and_records_nothing(json_case):
    cases_dir, case_id, _ev, _events = json_case
    client = create_app(cases_dir).test_client()
    assert client.post(f"/api/cases/{case_id}/chat", json={"question": "  "}, headers=W).status_code == 400
    assert _entries(cases_dir / case_id, audit.AI_CHAT_REQUESTED) == []


# --- AI hypothesis: web ---


def _hypothesis(events, **_kwargs):
    return ai_assistant.Hypothesis(
        evidence_sufficient=True,
        claim="jdoe's host connected to a Metasploit-style port.",
        assessment="may indicate a reverse shell",
        observed_evidence=["connection to 203.0.113.7:4444"],
        confidence="medium",
        alternative_explanation="a legitimate service on that port",
        recommended_validation="check the process that opened it",
        evidence=[ai_assistant.EvidenceCitation(evidence_id=events[0].evidence_id, event_id=events[0].event_id)],
    )


def test_web_hypothesis_is_recorded_like_the_cli(json_case, monkeypatch):
    cases_dir, case_id, _ev, events = json_case
    client = create_app(cases_dir).test_client()
    monkeypatch.setattr(ai_assistant, "generate_hypothesis", _hypothesis)

    resp = client.post(
        f"/api/cases/{case_id}/ai-hypothesis",
        json={"entity_type": "user", "value": "jdoe", "provider": "gemini", "api_key": SECRET},
        headers=W,
    )

    assert resp.status_code == 200, resp.get_json()
    [entry] = _entries(cases_dir / case_id, audit.AI_HYPOTHESIS_REQUESTED)
    details = entry["details"]
    assert details["provider"] == "gemini"
    assert (details["entity_type"], details["value"]) == ("user", "jdoe")
    assert details["events_sent"] >= 1
    assert details["outcome"] == "returned"
    assert details["confidence"] == "medium"
    assert details["cited_events"] == [events[0].event_id]
    assert SECRET not in (cases_dir / case_id / audit.AUDIT_FILENAME).read_text(encoding="utf-8")


def test_web_hypothesis_failure_is_recorded(json_case, monkeypatch):
    cases_dir, case_id, _ev, _events = json_case
    client = create_app(cases_dir).test_client()

    def broken(*_a, **_k):
        raise ai_assistant.AssistantError("No API key configured for anthropic")

    monkeypatch.setattr(ai_assistant, "generate_hypothesis", broken)
    resp = client.post(f"/api/cases/{case_id}/ai-hypothesis", json={"entity_type": "user", "value": "jdoe"}, headers=W)

    assert resp.status_code == 502
    [entry] = _entries(cases_dir / case_id, audit.AI_HYPOTHESIS_REQUESTED)
    assert entry["details"]["outcome"] == "failed"
    assert "No API key" in entry["details"]["error"]


def test_hypothesis_for_unknown_entity_sends_nothing_and_records_nothing(json_case, monkeypatch):
    cases_dir, case_id, _ev, _events = json_case
    client = create_app(cases_dir).test_client()
    called = []
    monkeypatch.setattr(ai_assistant, "generate_hypothesis", lambda *a, **k: called.append(1))

    resp = client.post(f"/api/cases/{case_id}/ai-hypothesis", json={"entity_type": "user", "value": "nobody"}, headers=W)

    assert resp.status_code == 404
    assert called == []
    assert _entries(cases_dir / case_id, audit.AI_HYPOTHESIS_REQUESTED) == []
