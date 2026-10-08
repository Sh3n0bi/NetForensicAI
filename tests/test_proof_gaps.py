"""Executable proof of known gaps.

Each test here states the behaviour the tool SHOULD have and is marked
``xfail(strict=True)``:

* While the gap exists, the test fails -> reported as xfail (expected). This
  is the reproducible proof that the gap is real.
* When someone fixes the gap, the test starts passing -> strict mode turns that
  into a hard failure ("XPASS(strict)"), which forces the fix's author to
  delete the marker. The gap then becomes an ordinary regression test.

Gaps that have been fixed live on as regression tests elsewhere (the custody
and evidence-hashing ones are in tests/test_integrity.py).

Run just these with:  pytest tests/test_proof_gaps.py -rx
"""

import pytest

from netforensicai.web.app import create_app

TOKEN = "proof-token-0123456789abcdef"


def _gap(reason):
    return pytest.mark.xfail(strict=True, reason=reason)


# --------------------------------------------------------------------------
# Web UI hardening
# --------------------------------------------------------------------------


@pytest.fixture
def secured_client(tmp_path):
    flask_app = create_app(cases_dir=str(tmp_path / "cases"), auth_token=TOKEN)
    return flask_app.test_client()


@_gap("failed token guesses are never throttled (measured ~4,000/s in-process)")
def test_web_throttles_repeated_failed_auth(secured_client):
    statuses = {
        secured_client.get("/api/cases", headers={"X-Auth-Token": f"wrong-{i}"}).status_code for i in range(200)
    }

    assert 429 in statuses, f"saw only {sorted(statuses)}"


@_gap("UI responses carry no CSP, X-Frame-Options, nosniff or Referrer-Policy")
def test_web_ui_sends_security_headers(secured_client):
    response = secured_client.get("/", headers={"X-Auth-Token": TOKEN})

    assert "Content-Security-Policy" in response.headers
    assert "X-Frame-Options" in response.headers or "frame-ancestors" in response.headers.get(
        "Content-Security-Policy", ""
    )
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Referrer-Policy" in response.headers


@_gap("the shared token is accepted in the URL query string, so it lands in logs, history and Referer")
def test_web_does_not_accept_the_token_in_the_query_string(secured_client):
    response = secured_client.get(f"/api/cases?token={TOKEN}")

    assert response.status_code == 401
