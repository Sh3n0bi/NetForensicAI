"""Tests for the AI investigation assistant. The Anthropic client is
always mocked - these tests must never touch the real network or require
a real API key."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# unittest.mock.patch("anthropic.Anthropic", ...) needs to *import*
# anthropic to resolve that target string, even though every call in this
# file mocks it rather than using it for real - so these tests need the
# package installed to run at all, not just to pass. anthropic's 1.x line
# requires Python >=3.10, so this also naturally skips on older Pythons
# rather than failing with an import error.
pytest.importorskip("anthropic")

from netforensicai.core.ai_assistant import (
    MAX_EVENTS,
    AssistantError,
    EvidenceCitation,
    Hypothesis,
    generate_hypothesis,
)
from netforensicai.core.event import Event


def _event(event_id, evidence_id="EV-0001", **overrides):
    fields = dict(
        event_id=event_id,
        evidence_id=evidence_id,
        source="json",
        event_type="process_start",
        timestamp=datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc),
    )
    fields.update(overrides)
    return Event(**fields)


def _mock_client(hypothesis):
    mock_response = MagicMock()
    mock_response.parsed_output = hypothesis
    mock_client = MagicMock()
    mock_client.messages.parse.return_value = mock_response
    return mock_client


def _valid_hypothesis(evidence_refs):
    return Hypothesis(
        evidence_sufficient=True,
        claim="This may represent suspicious activity.",
        assessment="Possible suspicious PowerShell execution",
        observed_evidence=["A PowerShell process started shortly after logon."],
        confidence="medium",
        alternative_explanation="Could be legitimate administrative automation.",
        recommended_validation="Review process ancestry and command line.",
        evidence=[EvidenceCitation(evidence_id=e, event_id=ev) for e, ev in evidence_refs],
    )


def test_no_events_raises():
    with pytest.raises(AssistantError):
        generate_hypothesis([])


def test_returns_hypothesis_when_citations_valid():
    events = [_event("EVT-0001"), _event("EVT-0002")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-0001")])

    with patch("anthropic.Anthropic", return_value=_mock_client(hyp)):
        result = generate_hypothesis(events, api_key="fake-key")

    assert result.claim == hyp.claim
    assert result.confidence == "medium"


def test_rejects_hypothesis_citing_unknown_event():
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-9999")])  # not in the given events

    with patch("anthropic.Anthropic", return_value=_mock_client(hyp)):
        with pytest.raises(AssistantError, match="not present"):
            generate_hypothesis(events, api_key="fake-key")


def test_rejects_hypothesis_citing_unknown_evidence_id():
    events = [_event("EVT-0001", evidence_id="EV-0001")]
    hyp = _valid_hypothesis([("EV-9999", "EVT-0001")])  # right event, wrong evidence_id

    with patch("anthropic.Anthropic", return_value=_mock_client(hyp)):
        with pytest.raises(AssistantError, match="not present"):
            generate_hypothesis(events, api_key="fake-key")


def test_accepts_hypothesis_with_no_citations_when_insufficient():
    events = [_event("EVT-0001")]
    hyp = Hypothesis(
        evidence_sufficient=False,
        claim="Insufficient evidence",
        assessment="Insufficient evidence",
        observed_evidence=[],
        confidence="low",
        alternative_explanation="N/A",
        recommended_validation="Gather more events before forming a hypothesis.",
        evidence=[],
    )

    with patch("anthropic.Anthropic", return_value=_mock_client(hyp)):
        result = generate_hypothesis(events, api_key="fake-key")

    assert result.evidence_sufficient is False
    assert result.evidence == []


def test_none_parsed_output_raises():
    mock_response = MagicMock()
    mock_response.parsed_output = None
    mock_client = MagicMock()
    mock_client.messages.parse.return_value = mock_response

    with patch("anthropic.Anthropic", return_value=mock_client):
        with pytest.raises(AssistantError, match="could not be parsed"):
            generate_hypothesis([_event("EVT-0001")], api_key="fake-key")


def test_authentication_error_raises_assistant_error():
    import anthropic

    mock_client = MagicMock()
    # Bypass __init__ - we only need an instance of the right exception
    # type for the except clause to catch; constructor args aren't
    # documented and this test doesn't need real response internals.
    auth_error = anthropic.AuthenticationError.__new__(anthropic.AuthenticationError)
    mock_client.messages.parse.side_effect = auth_error

    with patch("anthropic.Anthropic", return_value=mock_client):
        with pytest.raises(AssistantError, match="rejected the credential"):
            generate_hypothesis([_event("EVT-0001")], api_key="bad-key")


def test_no_credentials_at_all_raises_assistant_error_not_typeerror():
    # Regression: when no credential source can be resolved at all (no
    # api_key, no env var, no ant auth profile), the SDK raises TypeError
    # at client *construction* - before any request, and before the
    # try/except around messages.parse() even starts. Confirmed against
    # the real SDK's actual error message text.
    with patch(
        "anthropic.Anthropic",
        side_effect=TypeError(
            "Could not resolve authentication method. Expected one of api_key, auth_token, or "
            "credentials to be set."
        ),
    ):
        with pytest.raises(AssistantError, match="credentials"):
            generate_hypothesis([_event("EVT-0001")], api_key=None)


def test_unrelated_type_error_at_construction_is_not_swallowed():
    with patch("anthropic.Anthropic", side_effect=TypeError("unrelated bug in client setup")):
        with pytest.raises(TypeError, match="unrelated bug"):
            generate_hypothesis([_event("EVT-0001")], api_key="fake-key")


def test_events_are_capped_at_max_events():
    events = [_event(f"EVT-{i:04d}") for i in range(MAX_EVENTS + 10)]
    hyp = _valid_hypothesis([])

    mock_client = _mock_client(hyp)
    with patch("anthropic.Anthropic", return_value=mock_client):
        generate_hypothesis(events, api_key="fake-key")

    call_kwargs = mock_client.messages.parse.call_args.kwargs
    prompt_text = call_kwargs["messages"][0]["content"]
    assert prompt_text.count("[EV-0001/EVT-") == MAX_EVENTS


def test_prompt_includes_normalized_fields_and_request_uses_expected_model():
    event = _event("EVT-0001", message="normal message", command_line="cmd /c whoami")
    hyp = _valid_hypothesis([])

    mock_client = _mock_client(hyp)
    with patch("anthropic.Anthropic", return_value=mock_client):
        generate_hypothesis([event], api_key="fake-key")

    call_kwargs = mock_client.messages.parse.call_args.kwargs
    prompt_text = call_kwargs["messages"][0]["content"]
    assert "cmd /c whoami" in prompt_text
    assert call_kwargs["output_format"] is Hypothesis
    assert call_kwargs["model"] == "claude-opus-5"


def test_model_override_is_passed_through():
    hyp = _valid_hypothesis([])
    mock_client = _mock_client(hyp)
    with patch("anthropic.Anthropic", return_value=mock_client):
        generate_hypothesis([_event("EVT-0001")], api_key="fake-key", model="claude-haiku-4-5-20251001")

    assert mock_client.messages.parse.call_args.kwargs["model"] == "claude-haiku-4-5-20251001"


def test_transient_capacity_failure_is_retried_then_succeeds():
    # Observed live: Gemini returned "currently experiencing high demand"
    # while a sibling model answered fine. Overload is an ordinary
    # condition, not a failed investigation.
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-0001")])
    calls = {"n": 0}

    def flaky(*_args, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise AssistantError("AI request failed: This model is currently experiencing high demand.")
        return _mock_client(hyp)

    with patch("netforensicai.core.ai_assistant.RETRY_BACKOFF_SECONDS", 0):
        with patch("anthropic.Anthropic", side_effect=flaky):
            result = generate_hypothesis(events, api_key="fake-key")

    assert calls["n"] == 2
    assert result.claim == hyp.claim


def test_transient_failure_gives_up_after_the_retry_limit():
    from netforensicai.core.ai_assistant import MAX_TRANSIENT_RETRIES

    calls = {"n": 0}

    def always_overloaded(*_args, **_kwargs):
        calls["n"] += 1
        raise AssistantError("AI request failed: server overloaded, try again later")

    with patch("netforensicai.core.ai_assistant.RETRY_BACKOFF_SECONDS", 0):
        with patch("anthropic.Anthropic", side_effect=always_overloaded):
            with pytest.raises(AssistantError, match="overloaded"):
                generate_hypothesis([_event("EVT-0001")], api_key="fake-key")

    assert calls["n"] == MAX_TRANSIENT_RETRIES + 1


def test_credential_failure_is_not_retried():
    # Retrying a bad key fails identically every time and only delays a
    # clear message - the opposite of the overload case.
    calls = {"n": 0}

    def bad_credentials(*_args, **_kwargs):
        calls["n"] += 1
        raise TypeError("Could not resolve authentication method.")

    with patch("netforensicai.core.ai_assistant.RETRY_BACKOFF_SECONDS", 0):
        with patch("anthropic.Anthropic", side_effect=bad_credentials):
            with pytest.raises(AssistantError, match="credentials"):
                generate_hypothesis([_event("EVT-0001")], api_key=None)

    assert calls["n"] == 1


def test_retired_model_error_is_not_retried():
    # A retired model 404s identically forever; the API's message names the
    # replacement, so surfacing it immediately is the useful behavior.
    calls = {"n": 0}

    def retired(*_args, **_kwargs):
        calls["n"] += 1
        raise AssistantError(
            "AI request failed: This model models/gemini-2.0-flash is no longer available."
        )

    with patch("netforensicai.core.ai_assistant.RETRY_BACKOFF_SECONDS", 0):
        with patch("anthropic.Anthropic", side_effect=retired):
            with pytest.raises(AssistantError, match="no longer available"):
                generate_hypothesis([_event("EVT-0001")], api_key="fake-key")

    assert calls["n"] == 1


def test_unknown_provider_raises_assistant_error():
    with pytest.raises(AssistantError, match="Unknown AI provider"):
        generate_hypothesis([_event("EVT-0001")], provider="chatgpt-3000")


# --- OpenAI provider ---


def _mock_openai_client(hypothesis, refusal=None):
    mock_message = MagicMock()
    mock_message.parsed = hypothesis
    mock_message.refusal = refusal
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=mock_message)]
    mock_client = MagicMock()
    mock_client.beta.chat.completions.parse.return_value = mock_response
    return mock_client


def test_openai_provider_returns_hypothesis_when_citations_valid():
    pytest.importorskip("openai")
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-0001")])

    with patch("openai.OpenAI", return_value=_mock_openai_client(hyp)):
        result = generate_hypothesis(events, provider="openai", api_key="fake-key")

    assert result.claim == hyp.claim


def test_openai_provider_rejects_unknown_citation():
    pytest.importorskip("openai")
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-9999")])

    with patch("openai.OpenAI", return_value=_mock_openai_client(hyp)):
        with pytest.raises(AssistantError, match="not present"):
            generate_hypothesis(events, provider="openai", api_key="fake-key")


def test_openai_provider_uses_default_model_and_schema():
    pytest.importorskip("openai")
    hyp = _valid_hypothesis([])
    mock_client = _mock_openai_client(hyp)
    with patch("openai.OpenAI", return_value=mock_client):
        generate_hypothesis([_event("EVT-0001")], provider="openai", api_key="fake-key")

    call_kwargs = mock_client.beta.chat.completions.parse.call_args.kwargs
    assert call_kwargs["model"] == "gpt-4o-mini"
    assert call_kwargs["response_format"] is Hypothesis


def test_openai_provider_no_parsed_output_raises():
    pytest.importorskip("openai")
    with patch("openai.OpenAI", return_value=_mock_openai_client(None, refusal="policy violation")):
        with pytest.raises(AssistantError, match="policy violation"):
            generate_hypothesis([_event("EVT-0001")], provider="openai", api_key="fake-key")


def test_openai_provider_authentication_error_raises_assistant_error():
    pytest.importorskip("openai")
    import openai

    mock_client = MagicMock()
    auth_error = openai.AuthenticationError.__new__(openai.AuthenticationError)
    mock_client.beta.chat.completions.parse.side_effect = auth_error

    with patch("openai.OpenAI", return_value=mock_client):
        with pytest.raises(AssistantError, match="rejected the credential"):
            generate_hypothesis([_event("EVT-0001")], provider="openai", api_key="bad-key")


def test_openai_provider_no_credentials_at_construction_raises_assistant_error():
    pytest.importorskip("openai")
    import openai

    with patch(
        "openai.OpenAI",
        side_effect=openai.OpenAIError("Missing credentials. Please pass an `api_key` ... or set OPENAI_API_KEY"),
    ):
        with pytest.raises(AssistantError, match="credentials"):
            generate_hypothesis([_event("EVT-0001")], provider="openai", api_key=None)


# --- Gemini provider ---


def test_gemini_provider_returns_hypothesis_when_citations_valid():
    pytest.importorskip("google.genai")
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-0001")])

    mock_response = MagicMock()
    mock_response.parsed = hyp
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client):
        result = generate_hypothesis(events, provider="gemini", api_key="fake-key")

    assert result.claim == hyp.claim


def test_gemini_provider_rejects_unknown_citation():
    pytest.importorskip("google.genai")
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-9999")])

    mock_response = MagicMock()
    mock_response.parsed = hyp
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client):
        with pytest.raises(AssistantError, match="not present"):
            generate_hypothesis(events, provider="gemini", api_key="fake-key")


def test_gemini_provider_no_parsed_output_raises():
    pytest.importorskip("google.genai")
    mock_response = MagicMock()
    mock_response.parsed = None
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client):
        with pytest.raises(AssistantError, match="could not be parsed"):
            generate_hypothesis([_event("EVT-0001")], provider="gemini", api_key="fake-key")


def test_gemini_provider_no_credentials_raises_assistant_error():
    pytest.importorskip("google.genai")
    with patch("google.genai.Client", side_effect=ValueError("No API key was provided. Please pass a valid API key.")):
        with pytest.raises(AssistantError, match="credentials"):
            generate_hypothesis([_event("EVT-0001")], provider="gemini", api_key=None)


def test_gemini_provider_client_error_with_401_raises_assistant_error():
    pytest.importorskip("google.genai")
    from google.genai import errors as genai_errors

    mock_client = MagicMock()
    client_error = genai_errors.ClientError.__new__(genai_errors.ClientError)
    client_error.code = 401
    client_error.message = "unauthorized"
    mock_client.models.generate_content.side_effect = client_error

    with patch("google.genai.Client", return_value=mock_client):
        with pytest.raises(AssistantError, match="rejected the credential"):
            generate_hypothesis([_event("EVT-0001")], provider="gemini", api_key="bad-key")


# --- Ollama provider (local, no SDK - mocks `requests`) ---


def test_ollama_provider_returns_hypothesis_when_citations_valid():
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-0001")])

    mock_response = MagicMock()
    mock_response.json.return_value = {"message": {"content": hyp.model_dump_json()}}
    mock_response.raise_for_status.return_value = None

    with patch("requests.post", return_value=mock_response) as mock_post:
        result = generate_hypothesis(events, provider="ollama", api_key=None)

    assert result.claim == hyp.claim
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["json"]["model"] == "llama3.1"
    assert "properties" in call_kwargs["json"]["format"]  # a JSON schema, not the bare string "json"


def test_ollama_provider_rejects_unknown_citation():
    events = [_event("EVT-0001")]
    hyp = _valid_hypothesis([("EV-0001", "EVT-9999")])
    mock_response = MagicMock()
    mock_response.json.return_value = {"message": {"content": hyp.model_dump_json()}}
    mock_response.raise_for_status.return_value = None

    with patch("requests.post", return_value=mock_response):
        with pytest.raises(AssistantError, match="not present"):
            generate_hypothesis(events, provider="ollama", api_key=None)


def test_ollama_provider_connection_error_raises_assistant_error():
    import requests

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("refused")):
        with pytest.raises(AssistantError, match="is `ollama serve` running"):
            generate_hypothesis([_event("EVT-0001")], provider="ollama")


def test_ollama_provider_uses_custom_base_url():
    hyp = _valid_hypothesis([])
    mock_response = MagicMock()
    mock_response.json.return_value = {"message": {"content": hyp.model_dump_json()}}
    mock_response.raise_for_status.return_value = None

    with patch("requests.post", return_value=mock_response) as mock_post:
        generate_hypothesis([_event("EVT-0001")], provider="ollama", base_url="http://192.168.1.50:11434")

    assert mock_post.call_args.args[0] == "http://192.168.1.50:11434/api/chat"


def test_a_rejected_key_is_not_reported_as_a_missing_key():
    """A 401 means a key WAS resolved, sent, and refused - expired,
    revoked, or not authorised for the model.

    All three providers used to report that as "No credentials found",
    which sends the investigator to set an environment variable they have
    already set, get the identical error, and conclude the tool is broken.
    Found while trying to verify the assistant against a live provider,
    where it cost exactly that debugging cycle.
    """
    pytest.importorskip("google.genai")
    from google.genai import errors as genai_errors

    rejected = genai_errors.ClientError(401, {"error": {"message": "API key not valid"}})
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = rejected

    with patch("netforensicai.core.ai_assistant.RETRY_BACKOFF_SECONDS", 0):
        with patch("google.genai.Client", return_value=mock_client):
            with pytest.raises(AssistantError) as caught:
                generate_hypothesis([_event("EVT-0001")], provider="gemini", api_key="stale-key")

    message = str(caught.value)
    assert "A key WAS found" in message
    assert "No Gemini credentials found" not in message, "the misleading message came back"
