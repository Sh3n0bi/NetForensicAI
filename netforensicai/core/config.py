"""Local settings: API keys and provider preferences the investigator can
set once from the web UI instead of passing on every command.

Stored as a single JSON file (default ~/.netforensicai/config.json, or
NETFORENSIC_CONFIG_DIR) with 0600 permissions where the OS supports it -
NOT inside a case directory, because a case gets exported and handed to
another investigator (see core/export.py) and credentials must never ride
along in that archive.

Resolution order for any key, most specific first:
  1. an explicit value passed to the call (a CLI flag, or a web request
     that included one)
  2. the provider's own environment variable (VT_API_KEY,
     ANTHROPIC_API_KEY, ...) - so existing setups keep working unchanged
  3. this config file

Environment deliberately beats the config file: an env var is the more
deliberate, per-session choice, and a stale saved key silently overriding
one the investigator just exported would be surprising.

Keys are never returned to the browser in full - see masked_settings().
The web UI shows only whether a key is set and its last four characters,
which is enough to confirm "the right key is saved" without putting the
secret back on the wire on every page load.
"""

import json
import logging
import os
import stat
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_DIR_ENV = "NETFORENSIC_CONFIG_DIR"
CONFIG_FILENAME = "config.json"

# setting key -> environment variable that overrides it
SECRET_KEYS = {
    "virustotal_api_key": "VT_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "openai_api_key": "OPENAI_API_KEY",
    "gemini_api_key": "GEMINI_API_KEY",
}

PLAIN_KEYS = {
    "ai_provider": "anthropic",
    "ai_model": "",
    "ollama_base_url": "",
    # Which pcap dissection engine to use: "auto" (tshark when Wireshark
    # is installed, otherwise scapy), "tshark", or "scapy". See
    # parsers/pcap_engine.py.
    "pcap_engine": "auto",
}


def config_dir():
    override = os.environ.get(CONFIG_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".netforensicai"


def config_path():
    return config_dir() / CONFIG_FILENAME


def load_settings():
    """Return the saved settings dict (empty if nothing saved yet).
    Never raises - a corrupt config must not break the whole tool."""
    path = config_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        logger.warning(f"Ignoring unreadable config at {path}: {e}")
        return {}
    return data if isinstance(data, dict) else {}


def save_settings(updates):
    """Merge `updates` into the saved settings and write them back.

    A value of "" clears that setting rather than storing an empty
    string, so the UI's "clear this field" and "leave it alone" cases
    stay distinct: omit a key to leave it untouched, pass "" to remove it.
    """
    settings = load_settings()
    for key, value in updates.items():
        if key not in SECRET_KEYS and key not in PLAIN_KEYS:
            continue  # ignore unknown keys rather than persisting junk
        if value is None:
            continue
        value = value.strip() if isinstance(value, str) else value
        if value == "":
            settings.pop(key, None)
        else:
            settings[key] = value

    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2, sort_keys=True), encoding="utf-8")
    try:
        # Owner read/write only. No-op in effect on Windows (which ignores
        # the group/other bits here), so this is a best-effort hardening on
        # POSIX rather than something to depend on everywhere.
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        logger.warning(f"Could not restrict permissions on {path}: {e}")
    return settings


def get_secret(key, explicit=None):
    """Resolve one secret: explicit value, then env var, then config file.
    Returns None if none of the three is set."""
    if explicit:
        return explicit
    env_var = SECRET_KEYS.get(key)
    if env_var:
        from_env = os.environ.get(env_var)
        if from_env:
            return from_env
    saved = load_settings().get(key)
    return saved or None


def get_plain(key, explicit=None):
    """Resolve one non-secret preference: explicit, then config file, then
    the documented default. No env var layer - these aren't credentials."""
    if explicit:
        return explicit
    saved = load_settings().get(key)
    if saved:
        return saved
    return PLAIN_KEYS.get(key, "")


def _mask(value):
    if not value:
        return None
    return f"...{value[-4:]}" if len(value) > 4 else "...."


def masked_settings():
    """What the web UI is allowed to see: for each secret, whether it's
    set, where it came from, and a masked hint - never the key itself."""
    saved = load_settings()
    secrets = {}
    for key, env_var in SECRET_KEYS.items():
        from_env = os.environ.get(env_var)
        from_file = saved.get(key)
        effective = from_env or from_file
        secrets[key] = {
            "set": bool(effective),
            "source": "environment" if from_env else ("config" if from_file else None),
            "env_var": env_var,
            "hint": _mask(effective),
            # An env var wins over the saved value (see module docstring),
            # so the UI can warn that editing this field won't take effect.
            "overridden_by_env": bool(from_env and from_file),
        }
    return {
        "secrets": secrets,
        "preferences": {key: get_plain(key) for key in PLAIN_KEYS},
        "config_path": str(config_path()),
    }
