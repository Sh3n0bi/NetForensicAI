"""Packaging smoke tests for Step 1 (installable package restructure).

Deliberately does not touch pcap/dashboard/VT code paths here: those
depend on optional extras (pyshark+tshark, dash, requests) and get real
coverage once the pcap parser is refactored to emit normalized events
(migration step 5) with synthetic fixtures.
"""

import subprocess
import sys


def test_package_importable():
    import netforensicai

    assert netforensicai.__version__ == "0.1.0"


def test_cli_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "netforensicai.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "netforensic" in result.stdout.lower()
