"""SDK-free tests for ai_assistant: the validation, provider-selection and
retry logic that must hold regardless of which provider SDKs are installed.

test_ai_assistant.py skips wholesale when `anthropic` is absent; these do
not, so the SSRF guard, the unknown-provider guard and the retry policy are
covered in every environment.
"""

import pytest

from netforensicai.core import ai_assistant as ai
from netforensicai.core.ai_assistant import AssistantError

# --- Ollama base-URL SSRF guard -------------------------------------------


@pytest.mark.parametrize("url", ["http://localhost:11434", "http://127.0.0.1:11434", "https://[::1]:11434", "http://127.5.5.5:11434"])
def test_ollama_loopback_is_allowed(url):
    # Loopback is the normal, safe target and must never raise.
    ai._validate_ollama_base_url(url)


@pytest.mark.parametrize("url", ["ftp://localhost", "file:///etc/passwd", "localhost:11434", ""])
def test_ollama_non_http_scheme_is_refused(url):
    with pytest.raises(AssistantError, match=r"http or https|no host"):
        ai._validate_ollama_base_url(url)


def test_ollama_missing_host_is_refused():
    with pytest.raises(AssistantError, match="no host"):
        ai._validate_ollama_base_url("http://")


def test_ollama_remote_host_is_refused_by_default(monkeypatch):
    monkeypatch.delenv(ai.OLLAMA_ALLOW_REMOTE_ENV, raising=False)
    with pytest.raises(AssistantError, match="non-local Ollama host"):
        ai._validate_ollama_base_url("http://10.0.0.5:11434")


def test_ollama_remote_host_allowed_with_optin(monkeypatch):
    monkeypatch.setenv(ai.OLLAMA_ALLOW_REMOTE_ENV, "1")
    # Must not raise once the operator has explicitly opted in.
    ai._validate_ollama_base_url("http://10.0.0.5:11434")


# --- provider selection ----------------------------------------------------


def test_call_model_unknown_provider_raises():
    with pytest.raises(AssistantError, match="Unknown AI provider"):
        ai.call_model("sys", "user", provider="not-a-provider")


def test_generate_hypothesis_with_no_events_raises():
    with pytest.raises(AssistantError, match="No events provided"):
        ai.generate_hypothesis([], provider="anthropic")


def test_call_model_ollama_rejects_remote_base_url(monkeypatch):
    # provider selection reaches the SSRF guard before any SDK is needed.
    monkeypatch.delenv(ai.OLLAMA_ALLOW_REMOTE_ENV, raising=False)
    with pytest.raises(AssistantError, match="non-local Ollama host"):
        ai.call_model("sys", "user", provider="ollama", base_url="http://192.168.1.50:11434")


# --- transient-retry policy ------------------------------------------------


def test_is_transient_matches_capacity_language():
    assert ai._is_transient(AssistantError("The model is overloaded, try again"))
    assert not ai._is_transient(AssistantError("invalid api key"))


def test_with_transient_retry_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 2:
            raise AssistantError("temporarily overloaded, please retry")
        return {"ok": True}

    # time.sleep is imported inside the function; patch the module-level name.
    import time as _t

    monkeypatch.setattr(_t, "sleep", lambda *_: None)
    assert ai._with_transient_retry(flaky, "anthropic") == {"ok": True}
    assert calls["n"] == 2


def test_with_transient_retry_gives_up_after_limit(monkeypatch):
    import time as _t

    monkeypatch.setattr(_t, "sleep", lambda *_: None)
    attempts = {"n": 0}

    def always_busy():
        attempts["n"] += 1
        raise AssistantError("service overloaded")

    with pytest.raises(AssistantError, match="overloaded"):
        ai._with_transient_retry(always_busy, "gemini")
    assert attempts["n"] == ai.MAX_TRANSIENT_RETRIES + 1


def test_credential_failure_is_not_retried(monkeypatch):
    import time as _t

    monkeypatch.setattr(_t, "sleep", lambda *_: None)
    attempts = {"n": 0}

    def bad_key():
        attempts["n"] += 1
        raise AssistantError("HTTP 401 - key rejected")

    with pytest.raises(AssistantError, match="key rejected"):
        ai._with_transient_retry(bad_key, "openai")
    # A non-transient error must fail on the first attempt, no retries.
    assert attempts["n"] == 1


def test_rejected_message_distinguishes_from_missing_credentials():
    msg = ai._rejected_message("OpenAI", "--api-key or OPENAI_API_KEY")
    assert "rejected the credential" in msg
    assert "OPENAI_API_KEY" in msg
