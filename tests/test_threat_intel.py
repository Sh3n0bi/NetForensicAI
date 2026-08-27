from datetime import timedelta
from unittest.mock import patch

from netforensicai.core.store import CaseStore
from netforensicai.core.threat_intel import DEFAULT_CACHE_TTL, check_entity, supported_entity_types


def _mock_vt_result(malicious=False):
    return {
        "malicious": malicious,
        "malicious_count": 5 if malicious else 0,
        "total_engines": 70,
        "permalink": "https://www.virustotal.com/gui/search/x",
        "error": None,
    }


def test_supported_entity_types():
    assert set(supported_entity_types()) == {"ip_address", "hash"}


def test_unsupported_entity_type_returns_none(tmp_path):
    with CaseStore(tmp_path) as store:
        result = check_entity(store, "ENT-1", "user", "alice", api_key="fake-key")

    assert result is None


def test_no_api_key_returns_no_api_key_error_without_calling_provider(tmp_path):
    with patch("netforensicai.intel.virustotal.check_ip") as mock_check:
        with CaseStore(tmp_path) as store:
            result = check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key=None)

    mock_check.assert_not_called()
    assert result["error"] == "no API key"
    assert result["cached"] is False


def test_first_check_calls_provider_and_caches(tmp_path):
    with patch("netforensicai.intel.virustotal.check_ip", return_value=_mock_vt_result(malicious=True)) as mock_check:
        with CaseStore(tmp_path) as store:
            result = check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key="fake-key")

            mock_check.assert_called_once_with("1.2.3.4", "fake-key")
            assert result["malicious"] is True
            assert result["cached"] is False
            assert result["checked_at"] is not None

            cached_row = store.get_threat_intel("ENT-1", "virustotal")
            assert cached_row is not None
            assert cached_row["malicious"] is True


def test_second_check_uses_cache_not_provider(tmp_path):
    with CaseStore(tmp_path) as store:
        with patch("netforensicai.intel.virustotal.check_ip", return_value=_mock_vt_result(malicious=False)) as mock_check:
            check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key="fake-key")
            assert mock_check.call_count == 1

            result = check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key="fake-key")
            assert mock_check.call_count == 1  # not called again
            assert result["cached"] is True
            assert result["malicious"] is False


def test_expired_cache_triggers_new_provider_call(tmp_path):
    with CaseStore(tmp_path) as store:
        with patch("netforensicai.intel.virustotal.check_ip", return_value=_mock_vt_result()) as mock_check:
            check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key="fake-key", ttl=timedelta(seconds=-1))
            check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key="fake-key", ttl=timedelta(seconds=-1))

    assert mock_check.call_count == 2


def test_force_bypasses_cache(tmp_path):
    with CaseStore(tmp_path) as store:
        with patch("netforensicai.intel.virustotal.check_ip", return_value=_mock_vt_result()) as mock_check:
            check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key="fake-key")
            check_entity(store, "ENT-1", "ip_address", "1.2.3.4", api_key="fake-key", force=True)

    assert mock_check.call_count == 2


def test_hash_entity_uses_check_hash(tmp_path):
    with patch("netforensicai.intel.virustotal.check_hash", return_value=_mock_vt_result(malicious=True)) as mock_check:
        with CaseStore(tmp_path) as store:
            result = check_entity(store, "ENT-2", "hash", "deadbeef", api_key="fake-key")

    mock_check.assert_called_once_with("deadbeef", "fake-key")
    assert result["malicious"] is True


def test_default_ttl_is_24_hours():
    assert DEFAULT_CACHE_TTL == timedelta(hours=24)
