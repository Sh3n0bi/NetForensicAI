"""Threat intelligence enrichment: an explicit, opt-in, cached lookup
against an external provider (VirusTotal today; more can be added later
behind the same _CHECKERS mapping) for a single entity.

Never called automatically against evidence - always requires an explicit
API key and an explicit investigator action (`investigate`). Results are
cached in the case's store (CaseStore.record_threat_intel /
get_threat_intel) so repeated `investigate` or `report generate` runs
don't re-query the provider - VirusTotal rate-limits free API keys
aggressively - and so a report can show what's already been checked
without making a new network call itself.
"""

import logging
from datetime import datetime, timedelta, timezone

from netforensicai.intel import virustotal

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = timedelta(hours=24)

PROVIDER_VIRUSTOTAL = "virustotal"

# (entity_type, provider) -> name of a netforensicai.intel.virustotal
# function, looked up via getattr() at call time (not bound directly) so
# that patching virustotal.check_ip/check_hash - e.g. in tests - is
# actually honored.
_CHECKERS = {
    ("ip_address", PROVIDER_VIRUSTOTAL): "check_ip",
    ("hash", PROVIDER_VIRUSTOTAL): "check_hash",
}


def supported_entity_types():
    return sorted({entity_type for entity_type, _provider in _CHECKERS})


def check_entity(store, entity_id, entity_type, value, api_key, ttl=DEFAULT_CACHE_TTL, force=False):
    """Return a threat-intel result dict for (entity_type, value), or None
    if no provider can check this entity_type.

    Uses a cached result from the store if one is still fresh (unless
    force=True), otherwise calls the provider live and caches the new
    result. checked_at in the returned dict is always an ISO 8601 string
    (or None), and "cached" says whether this result came from the cache
    or a fresh call.
    """
    checker_name = _CHECKERS.get((entity_type, PROVIDER_VIRUSTOTAL))
    if checker_name is None:
        return None

    if not force:
        cached = store.get_threat_intel(entity_id, PROVIDER_VIRUSTOTAL)
        if cached and _is_fresh(cached["checked_at"], ttl):
            return _finalize(cached, cached=True)

    if not api_key:
        return _finalize({"malicious": False, "error": "no API key", "checked_at": None}, cached=False)

    result = getattr(virustotal, checker_name)(value, api_key)
    checked_at = datetime.now(timezone.utc)
    store.record_threat_intel(entity_id, entity_type, value, PROVIDER_VIRUSTOTAL, result, checked_at)
    return _finalize({**result, "checked_at": checked_at}, cached=False)


def _is_fresh(checked_at, ttl):
    if checked_at is None:
        return False
    return datetime.now(timezone.utc) - checked_at < ttl


def _finalize(result, cached):
    checked_at = result.get("checked_at")
    return {
        "malicious": result.get("malicious"),
        "malicious_count": result.get("malicious_count"),
        "total_engines": result.get("total_engines"),
        "permalink": result.get("permalink"),
        "error": result.get("error"),
        "cached": cached,
        "checked_at": checked_at.isoformat() if hasattr(checked_at, "isoformat") else checked_at,
    }
