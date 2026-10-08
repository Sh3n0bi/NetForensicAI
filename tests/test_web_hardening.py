"""Web UI hardening: failed-auth throttling, the login flow, and security headers.

Added after the proof scorecard (proof/scorecard.py) showed that wrong tokens
could be tried thousands of times a second, that the UI sent no security
headers, and that the token was accepted in the URL query string.
"""

import re
from pathlib import Path

import pytest

from netforensicai.web import ratelimit
from netforensicai.web.app import (
    AUTH_COOKIE,
    AUTH_HEADER,
    CSRF_HEADER,
    CSRF_HEADER_VALUE,
    DEFAULT_SECURITY_HEADERS,
    STATIC_DIR,
    UI_CONTENT_SECURITY_POLICY,
    create_app,
)
from netforensicai.web.ratelimit import FailureLimiter

TOKEN = "correct-horse-battery-staple-0123"
CSRF = {CSRF_HEADER: CSRF_HEADER_VALUE}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def make_client(tmp_path, clock):
    def build(max_failures=3, global_max_failures=1000, remote_addr="10.0.0.1"):
        limiter = FailureLimiter(
            max_failures=max_failures, window_seconds=60, global_max_failures=global_max_failures, clock=clock
        )
        app = create_app(tmp_path / "cases", auth_token=TOKEN, auth_limiter=limiter)
        return app.test_client(), limiter

    return build


def get(client, path="/api/cases", token=None, addr="10.0.0.1", **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if token is not None:
        headers[AUTH_HEADER] = token
    return client.get(path, headers=headers, environ_base={"REMOTE_ADDR": addr}, **kwargs)


def login(client, token, addr="10.0.0.1", headers=CSRF, **kwargs):
    return client.post(
        "/api/login", json=token if isinstance(token, dict) else {"token": token},
        headers=headers, environ_base={"REMOTE_ADDR": addr}, **kwargs,
    )  # fmt: skip


# --------------------------------------------------------------------------
# The limiter itself
# --------------------------------------------------------------------------


def test_limiter_blocks_at_the_limit_and_reports_a_precise_wait(clock):
    limiter = FailureLimiter(max_failures=3, window_seconds=60, clock=clock)
    for _ in range(3):
        assert limiter.blocked_for("a") == 0
        limiter.record_failure("a")
        clock.advance(10)

    # failures were at t=0,10,20; now t=30; the first ages out at t=60
    assert limiter.blocked_for("a") == 30


def test_limiter_forgets_after_the_window(clock):
    limiter = FailureLimiter(max_failures=2, window_seconds=60, clock=clock)
    limiter.record_failure("a")
    limiter.record_failure("a")
    assert limiter.blocked_for("a") > 0

    clock.advance(60)

    assert limiter.blocked_for("a") == 0


def test_limiter_tracks_clients_independently(clock):
    limiter = FailureLimiter(max_failures=1, window_seconds=60, clock=clock)
    limiter.record_failure("a")

    assert limiter.blocked_for("a") > 0
    assert limiter.blocked_for("b") == 0


def test_limiter_global_cap_blocks_everyone_even_with_fresh_addresses(clock):
    limiter = FailureLimiter(max_failures=5, window_seconds=60, global_max_failures=4, clock=clock)
    for i in range(4):
        limiter.record_failure(f"client-{i}")

    assert limiter.blocked_for("a-brand-new-client") > 0


def test_limiter_memory_is_bounded(clock, monkeypatch):
    monkeypatch.setattr(ratelimit, "MAX_TRACKED_CLIENTS", 50)
    limiter = FailureLimiter(max_failures=3, window_seconds=60, clock=clock)

    for i in range(500):
        limiter.record_failure(f"client-{i}")
        clock.advance(0.01)

    assert limiter.tracked_clients() <= 50


# --------------------------------------------------------------------------
# Throttling through the app
# --------------------------------------------------------------------------


def test_wrong_tokens_are_throttled_with_retry_after(make_client):
    client, _ = make_client(max_failures=3)

    codes = [get(client, token=f"wrong-{i}").status_code for i in range(5)]

    assert codes == [401, 401, 401, 429, 429]
    response = get(client, token="wrong-again")
    assert 1 <= int(response.headers["Retry-After"]) <= 60
    assert "Too many" in response.get_json()["error"]


def test_the_correct_token_is_refused_while_locked_out_and_works_after(make_client, clock):
    client, _ = make_client(max_failures=3)
    for i in range(3):
        get(client, token=f"wrong-{i}")

    assert get(client, token=TOKEN).status_code == 429, "otherwise guessing could watch for the one request that passes"

    clock.advance(61)
    assert get(client, token=TOKEN).status_code == 200


def test_hammering_a_locked_out_client_does_not_extend_the_lockout(make_client, clock):
    client, _ = make_client(max_failures=3)
    for i in range(3):
        get(client, token=f"wrong-{i}")
    clock.advance(30)
    for i in range(100):
        assert get(client, token=f"more-{i}").status_code == 429

    clock.advance(31)  # 61s after the real failures

    assert get(client, token=TOKEN).status_code == 200


def test_requests_without_any_credential_are_not_failures(make_client):
    client, _ = make_client(max_failures=3)

    for _ in range(50):
        assert get(client).status_code == 401  # e.g. someone loading the login page

    assert get(client, token=TOKEN).status_code == 200


def test_lockout_is_per_client_address(make_client):
    client, _ = make_client(max_failures=3)
    for i in range(3):
        get(client, token=f"wrong-{i}", addr="10.0.0.1")

    assert get(client, token=TOKEN, addr="10.0.0.1").status_code == 429
    assert get(client, token=TOKEN, addr="10.0.0.2").status_code == 200


def test_x_forwarded_for_cannot_be_used_to_dodge_the_limit(make_client):
    client, _ = make_client(max_failures=3)

    codes = [
        get(client, token=f"wrong-{i}", headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code for i in range(5)
    ]

    assert codes == [401, 401, 401, 429, 429]


def test_global_cap_applies_across_addresses(make_client):
    client, _ = make_client(max_failures=50, global_max_failures=5)
    for i in range(5):
        get(client, token="wrong", addr=f"10.0.1.{i}")

    assert get(client, token=TOKEN, addr="10.0.9.9").status_code == 429


def test_a_wrong_cookie_counts_like_a_wrong_header(make_client):
    client, _ = make_client(max_failures=2)
    client.set_cookie(AUTH_COOKIE, "stale-token", domain="localhost")
    for _ in range(2):
        assert get(client).status_code == 401

    assert get(client).status_code == 429


# --------------------------------------------------------------------------
# Login
# --------------------------------------------------------------------------


def test_login_sets_an_httponly_samesite_cookie_that_authenticates(make_client):
    client, _ = make_client()

    response = login(client, TOKEN)

    assert response.status_code == 200
    cookie = next(c for c in response.headers.getlist("Set-Cookie") if c.startswith(f"{AUTH_COOKIE}="))
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "Secure" not in cookie  # plain http
    assert client.get("/api/cases").status_code == 200


def test_login_cookie_is_secure_over_https(make_client):
    client, _ = make_client()

    response = client.post("/api/login", json={"token": TOKEN}, headers=CSRF, base_url="https://localhost")

    assert "Secure" in next(c for c in response.headers.getlist("Set-Cookie") if c.startswith(AUTH_COOKIE))


def test_login_with_a_wrong_token_is_401_and_counts_towards_the_limit(make_client):
    client, _ = make_client(max_failures=2)

    assert [login(client, f"wrong-{i}").status_code for i in range(3)] == [401, 401, 429]
    assert login(client, TOKEN).status_code == 429


def test_login_needs_the_csrf_header(make_client):
    client, _ = make_client()

    assert login(client, TOKEN, headers={}).status_code == 403


def test_login_is_404_when_auth_is_not_enabled(tmp_path):
    client = create_app(tmp_path / "cases").test_client()

    assert client.post("/api/login", json={"token": "x"}, headers=CSRF).status_code == 404


@pytest.mark.parametrize("body", [{}, {"token": ""}, {"token": None}, {"token": ["a"]}, {"token": 123}, []])
def test_login_with_a_missing_or_malformed_token_is_401_and_not_a_guess(make_client, body):
    client, _ = make_client(max_failures=2)

    for _ in range(10):
        assert login(client, body).status_code == 401  # never 500, never 429

    assert login(client, TOKEN).status_code == 200


@pytest.mark.parametrize("token", ["café", "токен", "\U0001f512"])
def test_non_ascii_tokens_are_rejected_not_a_server_error(make_client, token):
    """hmac.compare_digest raises TypeError on a non-ASCII str; that used to be a 500."""
    client, _ = make_client()

    assert login(client, token).status_code == 401
    assert get(client, token=token.encode("utf-8").decode("latin-1")).status_code == 401


def test_a_non_ascii_expected_token_still_works(tmp_path):
    app = create_app(tmp_path / "cases", auth_token="töken-über")
    client = app.test_client()

    assert client.post("/api/login", json={"token": "töken-über"}, headers=CSRF).status_code == 200


# --------------------------------------------------------------------------
# The token is not accepted in the URL
# --------------------------------------------------------------------------


def test_the_token_in_the_query_string_is_not_accepted(make_client):
    client, _ = make_client()

    response = client.get(f"/api/cases?token={TOKEN}")

    assert response.status_code == 401
    assert "query string" in response.get_json()["error"]


def test_a_token_in_the_query_string_of_the_ui_url_does_not_set_a_cookie(make_client):
    client, _ = make_client()

    response = client.get(f"/?token={TOKEN}")

    assert response.status_code == 401
    assert not response.headers.getlist("Set-Cookie")
    assert client.get("/api/cases").status_code == 401


# --------------------------------------------------------------------------
# The login page
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/index.html"])
def test_unauthenticated_navigation_gets_the_login_page(make_client, path):
    client, _ = make_client()

    response = client.get(path)

    assert response.status_code == 401
    assert response.mimetype == "text/html"
    body = response.get_data(as_text=True)
    assert 'src="login.js"' in body and 'type="password"' in body
    assert response.headers["Cache-Control"] == "no-store"


def test_the_login_script_is_public_but_the_app_is_not(make_client):
    client, _ = make_client()

    assert client.get("/login.js").status_code == 200
    for path in ("/app.js", "/style.css", "/login.html", "/api/cases"):
        response = client.get(path)
        assert response.status_code == 401, path
        assert response.mimetype == "application/json", path


def test_after_login_the_root_serves_the_real_ui(make_client):
    client, _ = make_client()
    login(client, TOKEN)

    response = client.get("/")

    assert response.status_code == 200
    assert 'src="app.js"' in response.get_data(as_text=True)


def test_a_stale_cookie_on_the_root_shows_the_login_page(make_client):
    client, _ = make_client()
    client.set_cookie(AUTH_COOKIE, "old-token", domain="localhost")

    response = client.get("/")

    assert response.status_code == 401 and response.mimetype == "text/html"


def test_without_auth_the_root_is_the_ui(tmp_path):
    client = create_app(tmp_path / "cases").test_client()

    assert 'src="app.js"' in client.get("/").get_data(as_text=True)


# --------------------------------------------------------------------------
# Security headers
# --------------------------------------------------------------------------


def _authed(make_client):
    client, _ = make_client()
    login(client, TOKEN)
    return client


@pytest.mark.parametrize("path", ["/", "/app.js", "/style.css", "/api/cases", "/api/no-such-route", "/login.js"])
def test_every_response_carries_the_security_headers(make_client, path):
    client = _authed(make_client)

    response = client.get(path)

    for name in DEFAULT_SECURITY_HEADERS:
        assert response.headers.get(name) == DEFAULT_SECURITY_HEADERS[name], (path, name)


def test_error_and_login_responses_carry_the_headers_too(make_client):
    client, _ = make_client()

    for response in (client.get("/api/cases"), client.get("/"), client.get("/login.js")):
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers


def test_headers_are_also_sent_when_auth_is_off(tmp_path):
    response = create_app(tmp_path / "cases").test_client().get("/")

    assert response.headers["Content-Security-Policy"] == UI_CONTENT_SECURITY_POLICY


def test_the_csp_forbids_inline_script_eval_framing_and_plugins():
    directives = {d.split()[0]: d.split()[1:] for d in UI_CONTENT_SECURITY_POLICY.split(";") if d.strip()}

    assert directives["default-src"] == ["'none'"]
    assert directives["script-src"] == ["'self'"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert "'unsafe-eval'" not in UI_CONTENT_SECURITY_POLICY
    assert "'unsafe-inline'" not in directives["script-src"]


def test_api_responses_are_not_cacheable_but_static_assets_still_revalidate(make_client):
    client = _authed(make_client)

    assert client.get("/api/cases").headers["Cache-Control"] == "no-store"
    assert client.get("/app.js").headers["Cache-Control"] == "no-cache"


def test_a_route_that_sets_its_own_csp_keeps_it(tmp_path):
    """Recovered artifacts carry a sandboxing CSP; the default must not replace it."""
    app = create_app(tmp_path / "cases")

    @app.route("/_test/own-csp")
    def own_csp():
        response = app.response_class("x")
        response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
        return response

    response = app.test_client().get("/_test/own-csp")

    assert response.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert response.headers["X-Frame-Options"] == "DENY"


# --------------------------------------------------------------------------
# The CSP must stay compatible with the UI's own assets
# --------------------------------------------------------------------------

STATIC = Path(STATIC_DIR)
HTML_FILES = ["index.html", "login.html"]


@pytest.mark.parametrize("name", HTML_FILES)
def test_html_pages_have_no_inline_script_or_event_handler_attributes(name):
    html = (STATIC / name).read_text(encoding="utf-8")

    for match in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.S | re.I):
        attrs, body = match.groups()
        assert re.search(r'\bsrc="[^":/]+\.js"', attrs), f"{name}: script must be a same-origin file: {attrs}"
        assert not body.strip(), f"{name}: inline script body would be blocked by the CSP"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), f"{name}: inline event handler attribute"
    assert "javascript:" not in html.lower()


def test_app_js_uses_nothing_the_csp_blocks():
    source = (STATIC / "app.js").read_text(encoding="utf-8")

    assert not re.search(r"\beval\s*\(|new\s+Function\s*\(", source)
    assert "javascript:" not in source
    assert not re.search(
        r"""\son(click|change|input|submit|load|error|keydown|keyup|focus|blur|mouse\w+)\s*=\s*["']""", source
    )
    assert "createObjectURL" not in source and "WebSocket" not in source and "EventSource" not in source


@pytest.mark.parametrize("name", HTML_FILES)
def test_external_resources_are_limited_to_hosts_the_csp_allows(name):
    html = (STATIC / name).read_text(encoding="utf-8")
    allowed = {"fonts.googleapis.com", "fonts.gstatic.com"}
    hosts = set(re.findall(r"""(?:href|src)\s*=\s*["']https?://([^/"']+)""", html))

    assert hosts <= allowed, f"{name} loads from {hosts - allowed}, which the CSP would block"
    for host in hosts:
        assert host in UI_CONTENT_SECURITY_POLICY


def test_the_login_page_pulls_in_no_external_resource():
    html = (STATIC / "login.html").read_text(encoding="utf-8")

    assert not re.search(r"https?://", html), "the sign-in page should work with no outside network"
