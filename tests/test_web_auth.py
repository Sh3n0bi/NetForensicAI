"""The optional shared-secret auth that guards a non-loopback web deployment.

When create_app is given an auth_token, every request must carry it (header,
cookie, or one-time query param); without a token the app stays open for local
single-user use. These tests pin both halves of that contract.
"""

from netforensicai.web.app import AUTH_COOKIE, AUTH_HEADER, create_app


def test_no_token_means_open_app(tmp_path):
    # Default behaviour is unchanged: no auth_token, no gate.
    client = create_app(tmp_path / "cases").test_client()
    assert client.get("/api/cases").status_code == 200


def test_request_without_token_is_rejected(tmp_path):
    client = create_app(tmp_path / "cases", auth_token="s3cret").test_client()
    resp = client.get("/api/cases")
    assert resp.status_code == 401


def test_wrong_token_is_rejected(tmp_path):
    client = create_app(tmp_path / "cases", auth_token="s3cret").test_client()
    resp = client.get("/api/cases", headers={AUTH_HEADER: "wrong"})
    assert resp.status_code == 401


def test_correct_token_via_header_is_accepted(tmp_path):
    client = create_app(tmp_path / "cases", auth_token="s3cret").test_client()
    resp = client.get("/api/cases", headers={AUTH_HEADER: "s3cret"})
    assert resp.status_code == 200


def test_query_token_bootstraps_a_cookie(tmp_path):
    client = create_app(tmp_path / "cases", auth_token="s3cret").test_client()
    resp = client.get("/api/cases?token=s3cret")
    assert resp.status_code == 200
    cookies = resp.headers.getlist("Set-Cookie")
    assert any(AUTH_COOKIE in c for c in cookies)
    assert any("HttpOnly" in c for c in cookies)
    # The cookie now carries the credential on its own.
    follow = client.get("/api/cases")
    assert follow.status_code == 200


def test_auth_is_enforced_before_csrf(tmp_path):
    # An unauthenticated POST is a 401 (auth), not a 403 (CSRF): the caller
    # should be turned away without learning anything about the CSRF contract.
    client = create_app(tmp_path / "cases", auth_token="s3cret").test_client()
    resp = client.post("/api/cases/NOPE/analyze")
    assert resp.status_code == 401
