"""Tests for local settings storage. Every test points
NETFORENSIC_CONFIG_DIR at tmp_path so nothing here ever reads or writes
the developer's real ~/.netforensicai/config.json."""

import json

import pytest

from netforensicai.core import config


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv(config.CONFIG_DIR_ENV, str(tmp_path / "cfg"))
    # Clear provider env vars so tests exercise the config-file layer
    # rather than accidentally picking up the developer's real keys.
    for env_var in config.SECRET_KEYS.values():
        monkeypatch.delenv(env_var, raising=False)
    return tmp_path / "cfg"


def test_load_returns_empty_when_nothing_saved():
    assert config.load_settings() == {}


def test_save_and_load_round_trip():
    config.save_settings({"virustotal_api_key": "vt-key-1234"})

    assert config.load_settings()["virustotal_api_key"] == "vt-key-1234"


def test_save_merges_rather_than_replacing():
    config.save_settings({"virustotal_api_key": "vt-key"})
    config.save_settings({"openai_api_key": "oai-key"})

    saved = config.load_settings()
    assert saved["virustotal_api_key"] == "vt-key"
    assert saved["openai_api_key"] == "oai-key"


def test_empty_string_clears_a_setting_but_omission_leaves_it():
    config.save_settings({"virustotal_api_key": "vt-key", "openai_api_key": "oai-key"})

    config.save_settings({"virustotal_api_key": ""})  # explicit clear
    saved = config.load_settings()

    assert "virustotal_api_key" not in saved
    assert saved["openai_api_key"] == "oai-key"  # untouched, not wiped


def test_unknown_keys_are_ignored():
    config.save_settings({"totally_made_up": "value", "virustotal_api_key": "vt"})

    saved = config.load_settings()
    assert "totally_made_up" not in saved
    assert saved["virustotal_api_key"] == "vt"


def test_explicit_value_beats_env_and_config(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "from-env")
    config.save_settings({"virustotal_api_key": "from-config"})

    assert config.get_secret("virustotal_api_key", "explicit") == "explicit"


def test_env_beats_config(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "from-env")
    config.save_settings({"virustotal_api_key": "from-config"})

    assert config.get_secret("virustotal_api_key") == "from-env"


def test_config_used_when_no_explicit_or_env():
    config.save_settings({"virustotal_api_key": "from-config"})

    assert config.get_secret("virustotal_api_key") == "from-config"


def test_get_secret_returns_none_when_nothing_set():
    assert config.get_secret("virustotal_api_key") is None


def test_corrupt_config_is_ignored_not_fatal(isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    (isolated_config / config.CONFIG_FILENAME).write_text("{not valid json", encoding="utf-8")

    assert config.load_settings() == {}
    assert config.get_secret("virustotal_api_key") is None


def test_masked_settings_never_returns_the_raw_key():
    config.save_settings({"virustotal_api_key": "supersecretvalue9999"})

    masked = config.masked_settings()
    serialized = json.dumps(masked)

    assert "supersecretvalue9999" not in serialized
    assert masked["secrets"]["virustotal_api_key"]["set"] is True
    assert masked["secrets"]["virustotal_api_key"]["hint"] == "...9999"
    assert masked["secrets"]["virustotal_api_key"]["source"] == "config"


def test_masked_settings_flags_env_override(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env-value-abcd")
    config.save_settings({"virustotal_api_key": "config-value-wxyz"})

    entry = config.masked_settings()["secrets"]["virustotal_api_key"]

    assert entry["source"] == "environment"
    assert entry["overridden_by_env"] is True
    assert entry["hint"] == "...abcd"  # reflects the value that will actually be used


def test_masked_settings_reports_unset_keys():
    entry = config.masked_settings()["secrets"]["anthropic_api_key"]

    assert entry["set"] is False
    assert entry["source"] is None
    assert entry["hint"] is None


def test_plain_preferences_fall_back_to_documented_defaults():
    assert config.get_plain("ai_provider") == "anthropic"

    config.save_settings({"ai_provider": "ollama"})
    assert config.get_plain("ai_provider") == "ollama"


def test_virustotal_get_api_key_reads_saved_config():
    # Proves the resolution actually reaches the real caller, not just
    # config.get_secret() in isolation.
    from netforensicai.intel import virustotal

    config.save_settings({"virustotal_api_key": "vt-from-settings"})

    assert virustotal.get_api_key() == "vt-from-settings"
    assert virustotal.get_api_key("explicit-wins") == "explicit-wins"
