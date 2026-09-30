"""Chat and the investigation team through the REAL provider layer.

Regression: every provider call was forced into the Hypothesis schema, so a
real model could only ever answer with a hypothesis - never the tool calls and
answers the chat loop and the team read ({"action": ...}). Chat always ended
"No answer after N tool calls"; every team role ended "no findings within the
step budget". The existing tests never saw it: they replace call_model()
itself. These go through call_model() and each provider's request code, and
fake only what leaves the process (the HTTP call or SDK client).
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from netforensicai.core import ai_assistant, chat
from netforensicai.core.ai_assistant import AssistantError, _json_from_text
from tests.test_cli_team import _add_json_case


@pytest.fixture
def json_case(tmp_path):
    return _add_json_case(tmp_path)


# --- the JSON extraction every schema-less reply goes through ------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"action": "tool", "tool": "search_events", "arguments": {}}',
        '```json\n{"action": "tool", "tool": "search_events", "arguments": {}}\n```',
        'Sure - here is my call:\n{"action": "tool", "tool": "search_events", "arguments": {}}\nThanks.',
    ],
)
def test_json_is_extracted_from_common_reply_shapes(text):
    assert _json_from_text(text) == {"action": "tool", "tool": "search_events", "arguments": {}}


@pytest.mark.parametrize("text", ["", "no json here", "[1, 2, 3]", '{"broken": '])
def test_non_object_replies_are_format_errors(text):
    with pytest.raises(AssistantError):
        _json_from_text(text)


# --- Ollama (local AI): chat end to end ----------------------------------------


class _FakeOllama:
    """Stands in for `requests.post` to Ollama's /api/chat."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, url, json=None, timeout=None):
        self.requests.append({"url": url, "body": json})
        reply = self.replies.pop(0)
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"message": {"content": reply}}
        return response


def test_chat_works_end_to_end_on_ollama(json_case, monkeypatch):
    cases_dir, case_id, evidence_id, events = json_case
    target = events[1].event_id
    fake = _FakeOllama([
        json.dumps({"action": "tool", "tool": "search_events", "arguments": {"event_type": "network_connection"}}),
        json.dumps({"action": "answer", "evidence_sufficient": True,
                    "answer": "10.0.0.x connected to 203.0.113.7 on port 4444.",
                    "citations": [{"kind": "event", "evidence_id": evidence_id, "reference": target}]}),
    ])
    requests = pytest.importorskip("requests")
    monkeypatch.setattr(requests, "post", fake)

    result = chat.ask("Was there a suspicious connection?", cases_dir / case_id, provider="ollama")

    assert result.evidence_sufficient is True
    assert [c.reference for c in result.citations] == [target]
    # Plain JSON mode, not the hypothesis schema: that was the bug.
    assert all(r["body"]["format"] == "json" for r in fake.requests)


def test_team_role_works_end_to_end_on_ollama(json_case, monkeypatch):
    from netforensicai.agents import run_role
    from netforensicai.agents.roles import NETWORK

    cases_dir, case_id, evidence_id, events = json_case
    fake = _FakeOllama([
        json.dumps({"action": "tool", "tool": "search_events", "arguments": {}}),
        json.dumps({"action": "findings", "findings": [{
            "title": "Outbound to a Metasploit-style port", "severity": "High", "confidence": "medium",
            "assessment": "A connection to port 4444 may indicate a reverse shell.",
            "citations": [{"kind": "event", "evidence_id": evidence_id, "reference": events[1].event_id}]}]}),
    ])
    requests = pytest.importorskip("requests")
    monkeypatch.setattr(requests, "post", fake)

    result = run_role(NETWORK, cases_dir / case_id, provider="ollama")

    assert [f.title for f in result.findings] == ["Outbound to a Metasploit-style port"]
    assert result.note is None


def test_hypothesis_still_uses_its_schema_on_ollama(monkeypatch):
    fake = _FakeOllama([json.dumps({"x": 1})])
    requests = pytest.importorskip("requests")
    monkeypatch.setattr(requests, "post", fake)
    ai_assistant.call_model("s", "u", provider="ollama", schema=ai_assistant.Hypothesis)
    assert fake.requests[0]["body"]["format"] == ai_assistant.Hypothesis.model_json_schema()


# --- the cloud SDKs: schema-less calls use JSON mode, schema calls unchanged ----


def test_anthropic_without_schema_parses_the_text_reply():
    pytest.importorskip("anthropic")
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        content=[SimpleNamespace(type="text", text='{"action": "answer", "answer": "hi"}')]
    )
    with patch("anthropic.Anthropic", return_value=client):
        raw = ai_assistant.call_model("s", "u", provider="anthropic", api_key="k")
    assert raw == {"action": "answer", "answer": "hi"}
    client.messages.parse.assert_not_called()


def test_openai_without_schema_uses_json_object_mode():
    pytest.importorskip("openai")
    client = MagicMock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"action": "answer", "answer": "hi"}'))]
    )
    with patch("openai.OpenAI", return_value=client):
        raw = ai_assistant.call_model("s", "Reply with JSON.", provider="openai", api_key="k")
    assert raw["action"] == "answer"
    assert client.chat.completions.create.call_args.kwargs["response_format"] == {"type": "json_object"}
    client.beta.chat.completions.parse.assert_not_called()


def test_gemini_without_schema_sends_no_response_schema():
    pytest.importorskip("google.genai")
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(text='{"action": "answer", "answer": "hi"}', parsed=None)
    with patch("google.genai.Client", return_value=client):
        raw = ai_assistant.call_model("s", "u", provider="gemini", api_key="k")
    assert raw["action"] == "answer"
    config = client.models.generate_content.call_args.kwargs["config"]
    assert config.response_schema is None
    assert config.response_mime_type == "application/json"
