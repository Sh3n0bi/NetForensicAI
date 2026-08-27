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
        with pytest.raises(AssistantError, match="credentials"):
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
