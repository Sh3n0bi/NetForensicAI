"""Choosing how the AI assistant runs (core/ai_setup.py, /api/ai/status).

Ollama is faked at the HTTP boundary (requests.get), so detection, the
readiness rules, the cache and the SSRF guard all run for real. The config
directory is isolated per test by conftest.
"""

from unittest.mock import MagicMock

import pytest

from netforensicai.core import ai_assistant, ai_setup, config

TAGS = {"models": [
    {"name": "llama3.1:8b", "size": 4_920_753_328, "details": {"parameter_size": "8.0B", "family": "llama"}},
    {"name": "qwen2.5:latest", "size": 4_683_087_332, "details": {"parameter_size": "7.6B", "family": "qwen2"}},
]}


@pytest.fixture(autouse=True)
def _clear_cache():
    ai_setup._local_cache.clear()
    yield
    ai_setup._local_cache.clear()


@pytest.fixture
def ollama(monkeypatch):
    """A fake Ollama: records calls; `.down = True` makes it unreachable."""
    requests = pytest.importorskip("requests")

    class Fake:
        def __init__(self):
            self.down = False
            self.calls = []

        def __call__(self, url, timeout=None):
            self.calls.append(url)
            if self.down:
                raise requests.exceptions.ConnectionError("refused")
            response = MagicMock()
            response.raise_for_status.return_value = None
            response.json.return_value = TAGS
            return response

    fake = Fake()
    monkeypatch.setattr(requests, "get", fake)
    return fake


def test_default_ollama_address_is_ipv4_loopback():
    # "localhost" costs ~2 s per request on Windows (IPv6 tried first).
    assert ai_assistant.DEFAULT_OLLAMA_BASE_URL == "http://127.0.0.1:11434"


def test_local_detection_lists_models(ollama):
    s = ai_setup.local_status()
    assert s["reachable"] is True and s["error"] is None
    assert [m["name"] for m in s["models"]] == ["llama3.1:8b", "qwen2.5:latest"]
    assert s["models"][0]["size_gb"] == 4.9 and s["models"][0]["parameters"] == "8.0B"
    assert ollama.calls == ["http://127.0.0.1:11434/api/tags"]


def test_local_not_running_is_explained(ollama):
    ollama.down = True
    s = ai_setup.local_status()
    assert s["reachable"] is False
    assert "not answering" in s["error"] and "installed and running" in s["error"]
    assert "ConnectionError" not in s["error"]  # no exception detail in what the user sees


def test_saved_remote_ollama_address_is_refused_without_a_request(ollama):
    config.save_settings({"ollama_base_url": "http://10.0.0.5:11434"})
    s = ai_setup.local_status()
    assert s["reachable"] is False
    assert "not on this computer" in s["error"]
    assert ollama.calls == []  # the SSRF guard stops it before any request


def test_probe_is_cached_and_refresh_bypasses_it(ollama):
    ai_setup.local_status()
    ai_setup.local_status()
    assert len(ollama.calls) == 1
    ai_setup.local_status(refresh=True)
    assert len(ollama.calls) == 2


def test_local_choice_ready_only_with_the_model_installed(ollama):
    config.save_settings({"ai_provider": "ollama", "ai_model": "llama3.1:8b"})
    s = ai_setup.status()
    assert (s["mode"], s["ready"], s["not_ready_reason"]) == ("local", True, None)

    config.save_settings({"ai_model": "qwen2.5"})  # a bare name matches its :latest
    assert ai_setup.status(refresh=True)["ready"] is True

    config.save_settings({"ai_model": "mistral-nemo"})
    s = ai_setup.status(refresh=True)
    assert s["ready"] is False
    assert "ollama pull mistral-nemo" in s["not_ready_reason"]


def test_local_choice_not_ready_when_ollama_is_down(ollama):
    ollama.down = True
    config.save_settings({"ai_provider": "ollama", "ai_model": "llama3.1:8b"})
    s = ai_setup.status()
    assert s["ready"] is False and "not answering" in s["not_ready_reason"]


def test_cloud_readiness_follows_the_saved_key_and_never_returns_it(ollama):
    s = ai_setup.status()
    assert (s["provider"], s["mode"], s["ready"]) == ("anthropic", "cloud", False)
    assert "No API key is set" in s["not_ready_reason"]

    config.save_settings({"ai_provider": "gemini", "gemini_api_key": "AIza-SECRET-KEY-1234"})
    s = ai_setup.status()
    assert s["ready"] is True
    assert s["cloud"]["gemini"]["key_set"] is True
    assert s["cloud"]["gemini"]["key_hint"] == "...1234"
    assert "SECRET" not in str(s)


def test_status_route(ollama):
    from netforensicai.web.app import create_app

    client = create_app("unused-cases").test_client()
    body = client.get("/api/ai/status").get_json()
    assert body["local"]["reachable"] is True
    assert body["recommended_local_models"][0]["name"] == "llama3.1:8b"
    # An address in the request is ignored: only the saved setting is probed.
    body = client.get("/api/ai/status?base_url=http://192.168.1.9:11434").get_json()
    assert body["local"]["base_url"] == "http://127.0.0.1:11434"
    client.get("/api/ai/status?refresh=1")
    assert all(call.startswith("http://127.0.0.1:11434") for call in ollama.calls)
    assert len(ollama.calls) == 2  # first status + the refresh (the second one was cached)
