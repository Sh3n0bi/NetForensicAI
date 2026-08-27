"""Optional VirusTotal IP and file-hash reputation lookups.

Opt-in, explicit enrichment only: never called unless the caller supplies
an API key, and never wired up to run automatically against evidence.
Results are meant to be cached by the caller (see core/threat_intel.py)
rather than re-queried on every command - VT rate-limits free API keys
aggressively, and there's no reason to re-ask a question a case has
already recorded the answer to.

`requests` (the [intel] extra) is only imported inside _check(), so
callers can import this module just to resolve an API key (get_api_key)
without requests being installed.
"""

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{value}"
HASH_URL = "https://www.virustotal.com/api/v3/files/{value}"
REQUEST_TIMEOUT_SECONDS = 10

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def get_api_key(cli_value=None):
    """Resolve the VT API key: explicit CLI value, then VT_API_KEY env
    var, then whatever was saved via the web UI's Settings tab (see
    core/config.py for why that order)."""
    from netforensicai.core import config

    return config.get_secret("virustotal_api_key", cli_value)


def _empty_result(error):
    return {
        "malicious": False,
        "malicious_count": None,
        "total_engines": None,
        "permalink": None,
        "error": error,
    }


def _check(url_template, value, api_key):
    """Shared GET + response parsing for both IP and hash lookups - the
    VirusTotal v3 API returns the same last_analysis_stats shape for both
    object types."""
    if not api_key:
        logger.warning("VirusTotal API key not provided. Skipping threat intel.")
        return _empty_result("no API key")

    import requests

    logger.info(f"Checking threat intel for: {value}")
    try:
        response = requests.get(
            url_template.format(value=value),
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            return _empty_result(f"HTTP {response.status_code}")

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)
        total_engines = sum(stats.values())
        return {
            "malicious": malicious_count > 0,
            "malicious_count": malicious_count,
            "total_engines": total_engines,
            "permalink": f"https://www.virustotal.com/gui/search/{value}",
            "error": None,
        }
    except Exception as e:
        logger.error(f"Error checking threat intel for '{value}': {e}")
        return _empty_result(str(e))


def check_ip(ip, api_key):
    """Look up an IP address. Returns a result dict - see _check()."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _empty_result(f"'{ip}' is not a valid IP address")
    return _check(IP_URL, ip, api_key)


def check_hash(file_hash, api_key):
    """Look up a file hash (MD5/SHA-1/SHA-256). Returns a result dict - see _check()."""
    # Validated (rather than passed straight into the URL) both to reject
    # garbage before spending a rate-limited API call on it, and because
    # `value` may originate from evidence content or a web API payload -
    # an unvalidated value formatted directly into a URL path is worth
    # constraining to a known-safe shape on principle.
    if not _HASH_RE.match(file_hash or ""):
        return _empty_result(f"'{file_hash}' is not a valid MD5/SHA-1/SHA-256 hash")
    return _check(HASH_URL, file_hash, api_key)
