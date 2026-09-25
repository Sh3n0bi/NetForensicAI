"""Environment diagnostics behind `netforensic doctor`.

Read-only and non-destructive: it inspects what is installed and configured and
reports it, and never changes anything. The command is a thin renderer over
`run_checks()`; the logic lives here so it can be tested and reused.

Statuses:
  ok       - present and usable
  warning  - usable but worth noting
  missing  - an OPTIONAL capability is absent; a documented fallback exists
  error    - a CORE dependency is broken; the tool will not work correctly
Only `error` should make the command exit non-zero - a missing optional
dependency (tshark, evtx, an AI key) is not a failure.
"""

import importlib
import importlib.metadata as _md
import os
import sys
from dataclasses import dataclass
from pathlib import Path

OK = "ok"
WARNING = "warning"
MISSING = "missing"
ERROR = "error"

_ORDER = {ERROR: 3, WARNING: 2, MISSING: 1, OK: 0}


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""

    def to_dict(self):
        return {"name": self.name, "status": self.status, "detail": self.detail}


def _importable(module):
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def _dist_version(dist):
    try:
        return _md.version(dist)
    except Exception:
        return None


def _check_cases_dir(cases_dir):
    path = Path(cases_dir or os.environ.get("NETFORENSIC_CASES_DIR") or "cases")
    if path.exists():
        if not path.is_dir():
            return Check("Cases directory", ERROR, f"{path} exists but is not a directory")
        writable = os.access(path, os.W_OK)
        return Check("Cases directory", OK if writable else ERROR, f"{path}" + ("" if writable else " (not writable)"))
    # Not existing yet is fine as long as its parent is writable - it is created
    # on the first case.
    parent = path.parent if str(path.parent) else Path(".")
    try:
        parent.mkdir(parents=True, exist_ok=True)
        writable = os.access(parent, os.W_OK)
    except OSError:
        writable = False
    return Check(
        "Cases directory",
        OK if writable else ERROR,
        f"{path} (will be created on first case)" if writable else f"{path.parent} is not writable",
    )


def run_checks(cases_dir=None):
    """Return the ordered list of environment checks. Never raises."""
    checks = []

    v = sys.version_info
    checks.append(Check("Python", OK if v[:2] >= (3, 9) else ERROR, f"{v.major}.{v.minor}.{v.micro}"))

    pkg = _dist_version("netforensicai")
    checks.append(Check("NetForensicAI", OK if pkg else WARNING, pkg or "not installed as a package (running from source)"))

    # --- core (an error here means the tool is broken) ---
    duck = _dist_version("duckdb")
    checks.append(Check("DuckDB (case store)", OK if _importable("duckdb") else ERROR, duck or "not importable - core dependency missing"))
    checks.append(_check_cases_dir(cases_dir))

    from netforensicai.core import config

    checks.append(Check("Config directory", OK, str(config.config_dir())))

    # --- optional evidence engines (missing => fallback, not failure) ---
    checks.append(Check("scapy (pcap engine)", OK if _importable("scapy") else MISSING, _dist_version("scapy") or "not installed - install the [pcap] extra to parse captures"))
    checks.append(Check("scikit-learn (anomaly detection)", OK if _importable("sklearn") else MISSING, _dist_version("scikit-learn") or "not installed - anomaly flagging disabled"))
    checks.append(Check("python-evtx (Windows Event Logs)", OK if _importable("Evtx") else MISSING, _dist_version("python-evtx") or "not installed - install the [evtx] extra for .evtx"))
    checks.append(Check("Flask (web UI)", OK if _importable("flask") else MISSING, _dist_version("flask") or "not installed - install the [web] extra for `netforensic web`"))

    # --- Wireshark integration (optional; the built-in engine is the fallback) ---
    from netforensicai.integrations import wireshark

    tshark = wireshark.tshark_path()
    checks.append(Check("tshark (fast pcap engine)", OK if tshark else MISSING, (wireshark.version() or tshark) if tshark else "not found - the built-in scapy engine is used instead (slower)"))
    dumpcap = wireshark.dumpcap_path()
    checks.append(Check("dumpcap (live capture)", OK if dumpcap else MISSING, dumpcap or "not found - live capture unavailable; file analysis is unaffected"))

    from netforensicai.parsers import pcap_engine

    status = pcap_engine.engine_status()
    checks.append(Check("Active pcap engine", OK, status.get("selected") or status.get("error") or "unknown"))

    # --- optional external services (not configured is a note, never an error) ---
    ai_keys = [name for name in ("anthropic_api_key", "openai_api_key", "gemini_api_key") if config.get_secret(name)]
    ai_ollama = bool(config.get_plain("ollama_base_url"))
    if ai_keys or ai_ollama:
        detail = ", ".join([n.replace("_api_key", "") for n in ai_keys] + (["ollama"] if ai_ollama else []))
        checks.append(Check("AI assistant provider", OK, f"configured: {detail}"))
    else:
        checks.append(Check("AI assistant provider", MISSING, "none configured - the AI assistant is optional; set a key or use local Ollama"))

    vt = config.get_secret("virustotal_api_key")
    checks.append(Check("Threat intel (VirusTotal)", OK if vt else MISSING, "key configured" if vt else "no key - VirusTotal lookups are optional and off by default"))

    return checks


def overall_status(checks):
    """The worst status across all checks (error > warning > missing > ok)."""
    return max((c.status for c in checks), key=lambda s: _ORDER.get(s, 0), default=OK)
