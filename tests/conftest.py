"""Shared pytest fixtures."""

import pytest


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
