"""Tests for the VirusTotal client. requests is always mocked - these
tests must never touch the real network or require a real API key."""

import os
from unittest.mock import MagicMock, patch

from netforensicai.intel import virustotal


def _mock_response(status_code=200, stats=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = {"data": {"attributes": {"last_analysis_stats": stats or {}}}}
    return response


def test_get_api_key_prefers_cli_value(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env-key")

    assert virustotal.get_api_key("cli-key") == "cli-key"


def test_get_api_key_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env-key")

    assert virustotal.get_api_key(None) == "env-key"


def test_get_api_key_none_when_neither_set(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    assert virustotal.get_api_key(None) is None


def test_check_ip_without_api_key_returns_no_api_key_error():
    result = virustotal.check_ip("1.2.3.4", None)

    assert result["error"] == "no API key"
    assert result["malicious"] is False


def test_check_ip_malicious():
    stats = {"malicious": 5, "harmless": 60, "undetected": 5}
    with patch("requests.get", return_value=_mock_response(stats=stats)):
        result = virustotal.check_ip("1.2.3.4", "fake-key")

    assert result["malicious"] is True
    assert result["malicious_count"] == 5
    assert result["total_engines"] == 70
    assert result["permalink"] is not None
    assert result["error"] is None


def test_check_ip_clean():
    stats = {"malicious": 0, "harmless": 70}
    with patch("requests.get", return_value=_mock_response(stats=stats)):
        result = virustotal.check_ip("8.8.8.8", "fake-key")

    assert result["malicious"] is False
    assert result["malicious_count"] == 0


def test_check_hash_malicious():
    stats = {"malicious": 40, "harmless": 20}
    sha256_hash = "deadbeef" * 8  # 64 hex chars - a valid SHA-256-shaped hash
    with patch("requests.get", return_value=_mock_response(stats=stats)):
        result = virustotal.check_hash(sha256_hash, "fake-key")

    assert result["malicious"] is True
    assert result["malicious_count"] == 40


def test_check_hash_rejects_malformed_input():
    result = virustotal.check_hash("not-a-hash", "fake-key")

    assert result["error"] == "'not-a-hash' is not a valid MD5/SHA-1/SHA-256 hash"
    assert result["malicious"] is False


def test_check_ip_rejects_malformed_input():
    result = virustotal.check_ip("not-an-ip; rm -rf /", "fake-key")

    assert "not a valid IP address" in result["error"]
    assert result["malicious"] is False


def test_check_non_200_status_returns_error():
    with patch("requests.get", return_value=_mock_response(status_code=404)):
        result = virustotal.check_ip("1.2.3.4", "fake-key")

    assert result["error"] == "HTTP 404"
    assert result["malicious"] is False


def test_check_network_exception_returns_error_not_raise():
    with patch("requests.get", side_effect=ConnectionError("boom")):
        result = virustotal.check_ip("1.2.3.4", "fake-key")

    assert result["malicious"] is False
    assert "boom" in result["error"]


def test_check_uses_timeout():
    stats = {"malicious": 0}
    with patch("requests.get", return_value=_mock_response(stats=stats)) as mock_get:
        virustotal.check_ip("1.2.3.4", "fake-key")

    _, kwargs = mock_get.call_args
    assert kwargs["timeout"] == virustotal.REQUEST_TIMEOUT_SECONDS
