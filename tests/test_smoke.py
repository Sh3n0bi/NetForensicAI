"""Packaging smoke tests: is the package importable and does the CLI entry
point actually run. Deliberately minimal and extras-free - pcap/EVTX/
threat-intel/AI/web code paths each have their own dedicated test files
(test_parsers.py, test_evtx.py, test_virustotal.py, test_ai_assistant.py,
test_web.py) with the relevant optional extra installed."""

import subprocess
import sys


def test_package_importable():
    import importlib.metadata

    import netforensicai

    # One source of truth: pyproject.toml, via the installed metadata.
    assert netforensicai.__version__ == importlib.metadata.version("netforensicai")


def test_cli_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "netforensicai.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "netforensic" in result.stdout.lower()
