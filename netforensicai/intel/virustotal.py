"""Optional VirusTotal IP reputation lookups.

This is opt-in, explicit enrichment only: it is never called unless the
caller supplies an API key, and it must never be wired up to run
automatically against evidence.
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
REQUEST_TIMEOUT_SECONDS = 10


def get_api_key(cli_value=None):
    """Resolve the VT API key: explicit CLI value first, then VT_API_KEY env var."""
    return cli_value or os.environ.get("VT_API_KEY")


def check_ip(ip, api_key):
    """Return True if VirusTotal flags `ip` as malicious. False on any failure."""
    if not api_key:
        logger.warning("VirusTotal API key not provided. Skipping threat intel.")
        return False
    logger.info(f"Checking threat intel for IP: {ip}")
    try:
        response = requests.get(
            VT_API_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == 200:
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            return malicious > 0
        return False
    except Exception as e:
        logger.error(f"Error checking threat intel: {e}")
        return False
