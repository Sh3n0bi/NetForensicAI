"""Shared pytest fixtures."""

import pytest


@pytest.fixture(autouse=True)
def _pin_engines_to_scapy(monkeypatch):
    """Pin both pcap dissection and live capture to the scapy backends for
    the whole suite.

    The pcap fixtures here are scapy-synthesized, the assertions describe
    the scapy engine's seven analyses exactly, and the capture tests drive
    a mocked scapy AsyncSniffer. Without this pin the suite would use
    Wireshark's engines on any machine that happens to have Wireshark
    installed and scapy's everywhere else - so the same commit would pass
    on one developer's laptop and fail on another's, for reasons having
    nothing to do with the change under test.

    Tests that exercise the Wireshark backends opt into them explicitly
    and skip when the tooling is absent - see test_wireshark.py.
    """
    from netforensicai.core import capture
    from netforensicai.parsers import pcap_engine

    monkeypatch.setenv(pcap_engine.ENGINE_ENV, pcap_engine.ENGINE_SCAPY)
    monkeypatch.setenv(capture.CAPTURE_ENGINE_ENV, capture.ENGINE_SCAPY)


@pytest.fixture(autouse=True)
def _reset_capture_sessions():
    """core.capture._SESSIONS is a module-level registry keyed by case_id.
    Every test's fresh case reuses "INC-0001", so without this, a capture
    session registered by one test would leak into the next - this isn't
    a real production issue (one `netforensic web` process has one
    _SESSIONS dict, and doesn't reuse case_ids across genuinely different
    cases directories), but pytest runs every test in the same process,
    so the module-level dict persists across tests unless cleared."""
    from netforensicai.core import capture

    capture._SESSIONS.clear()
    yield
    capture._SESSIONS.clear()
