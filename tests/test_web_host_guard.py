"""The DNS-rebinding guard on the web UI.

A page on attacker.example can rebind its own name to 127.0.0.1 and then
talk to the tokenless loopback UI as same-origin - the X-Requested-With
CSRF header is no obstacle then. The Host header still names the attacker,
so the app must refuse any Host that is not loopback. These tests pin that,
and that legitimate loopback and token-protected deployments keep working.
"""

import pytest

from netforensicai.web.app import AUTH_HEADER, CSRF_HEADER, CSRF_HEADER_VALUE, _hostname, create_app

WRITE_HEADERS = {CSRF_HEADER: CSRF_HEADER_VALUE}


@pytest.mark.parametrize(
    "header, expected",
    [
        ("localhost", "localhost"),
        ("LOCALHOST:8000", "localhost"),
        ("127.0.0.1:8000", "127.0.0.1"),
        ("[::1]", "::1"),
        ("[::1]:8000", "::1"),
        ("attacker.example:8000", "attacker.example"),
        ("", ""),
    ],
)
def test_hostname_strips_port_and_brackets(header, expected):
    assert _hostname(header) == expected


@pytest.mark.parametrize("host", ["localhost:8000", "127.0.0.1:8000", "[::1]:8000", "localhost"])
def test_loopback_hosts_are_served(tmp_path, host):
    client = create_app(tmp_path / "cases").test_client()
    assert client.get("/api/cases", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "host",
    ["attacker.example:8000", "attacker.example", "127.0.0.1.nip.io:8000", "localhost.:8000", "192.168.1.5:8000"],
)
def test_rebound_read_is_refused(tmp_path, host):
    client = create_app(tmp_path / "cases").test_client()
    resp = client.get("/api/cases", headers={"Host": host})
    assert resp.status_code == 403
    assert "DNS-rebinding" in resp.get_json()["error"]


def test_rebound_write_is_refused_even_with_csrf_header(tmp_path):
    # The exact attack: same-origin after rebinding, so the custom header is
    # sent - the Host check is what has to stop it.
    cases_dir = tmp_path / "cases"
    client = create_app(cases_dir).test_client()
    resp = client.post(
        "/api/cases",
        json={"name": "forged"},
        headers={**WRITE_HEADERS, "Host": "attacker.example:8000"},
    )
    assert resp.status_code == 403
    assert client.get("/api/cases").get_json() == []


def test_static_ui_is_also_guarded(tmp_path):
    client = create_app(tmp_path / "cases").test_client()
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 403


def test_allowed_host_is_accepted_alongside_loopback(tmp_path):
    client = create_app(tmp_path / "cases", allowed_hosts=["Forensics.Internal:443"]).test_client()
    assert client.get("/api/cases", headers={"Host": "forensics.internal"}).status_code == 200
    assert client.get("/api/cases", headers={"Host": "127.0.0.1:8000"}).status_code == 200
    assert client.get("/api/cases", headers={"Host": "attacker.example"}).status_code == 403


def test_token_deployment_accepts_any_host(tmp_path):
    # Off-loopback deployments (e.g. the Docker image on 0.0.0.0) are reached
    # by whatever name/IP the operator uses; the token already defeats
    # rebinding because the attacker's origin never holds it.
    client = create_app(tmp_path / "cases", auth_token="s3cret").test_client()
    resp = client.get("/api/cases", headers={"Host": "10.0.0.7:8000", AUTH_HEADER: "s3cret"})
    assert resp.status_code == 200


def test_token_deployment_with_allowed_hosts_enforces_them(tmp_path):
    client = create_app(tmp_path / "cases", auth_token="s3cret", allowed_hosts=["nf.lan"]).test_client()
    ok = client.get("/api/cases", headers={"Host": "nf.lan", AUTH_HEADER: "s3cret"})
    bad = client.get("/api/cases", headers={"Host": "other.lan", AUTH_HEADER: "s3cret"})
    assert ok.status_code == 200
    assert bad.status_code == 403


def test_cli_passes_allow_host_through(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from netforensicai.cli import app

    seen = {}

    class _FakeApp:
        def run(self, **_kwargs):
            pass

    def fake_create_app(cases_dir, auth_token=None, allowed_hosts=None):
        seen["allowed_hosts"] = allowed_hosts
        return _FakeApp()

    monkeypatch.setattr("netforensicai.web.app.create_app", fake_create_app)
    result = CliRunner().invoke(
        app,
        ["web", "--cases-dir", str(tmp_path), "--allow-host", "a.lan", "--allow-host", "b.lan"],
    )
    assert result.exit_code == 0, result.output
    assert seen["allowed_hosts"] == ["a.lan", "b.lan"]
