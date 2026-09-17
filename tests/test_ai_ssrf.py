"""The Ollama base_url guard (SSRF hardening).

base_url can reach the AI path from an unauthenticated web request, so the
resolver must refuse to treat an arbitrary internal host as an Ollama server.
Loopback is allowed (Ollama is a local service); a remote host needs an
explicit env opt-in. These tests exercise the validator directly, with no
network involved.
"""

import pytest

from netforensicai.core.ai_assistant import (
    OLLAMA_ALLOW_REMOTE_ENV,
    AssistantError,
    _validate_ollama_base_url,
)


@pytest.mark.parametrize(
    "url",
    ["http://localhost:11434", "http://127.0.0.1:11434", "http://127.0.0.1", "https://localhost:11434"],
)
def test_loopback_is_allowed(url):
    _validate_ollama_base_url(url)  # must not raise


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data",  # cloud metadata endpoint
        "http://10.0.0.5:11434",
        "http://internal.example.com/api",
    ],
)
def test_remote_host_is_refused_by_default(url):
    with pytest.raises(AssistantError):
        _validate_ollama_base_url(url)


def test_remote_host_allowed_with_optin(monkeypatch):
    monkeypatch.setenv(OLLAMA_ALLOW_REMOTE_ENV, "1")
    _validate_ollama_base_url("http://10.0.0.5:11434")  # must not raise


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "gopher://host", "", "not-a-url"])
def test_non_http_schemes_are_refused(url):
    with pytest.raises(AssistantError):
        _validate_ollama_base_url(url)
