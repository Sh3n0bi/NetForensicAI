"""Executable proof of known gaps.

Each test here states the behaviour the tool SHOULD have and is marked
``xfail(strict=True)``:

* While the gap exists, the test fails -> reported as xfail (expected). This
  is the reproducible proof that the gap is real.
* When someone fixes the gap, the test starts passing -> strict mode turns that
  into a hard failure ("XPASS(strict)"), which forces the fix's author to
  delete the marker. The gap then becomes an ordinary regression test.

Run just these with:  pytest tests/test_proof_gaps.py -rx
"""

import json
import os
import stat

import pytest
from typer.testing import CliRunner

from netforensicai.cli import app as cli_app
from netforensicai.core import audit
from netforensicai.core.evidence import EvidenceManager
from netforensicai.web.app import create_app

runner = CliRunner()

TOKEN = "proof-token-0123456789abcdef"


def _gap(reason):
    return pytest.mark.xfail(strict=True, reason=reason)


# --------------------------------------------------------------------------
# Integrity: chain of custody and evidence hashing
# --------------------------------------------------------------------------


@_gap("audit log head is not anchored: deleting the LAST entry still verifies as intact")
def test_audit_tail_truncation_is_detected(tmp_path):
    for i in range(5):
        audit.record(tmp_path, audit.EVIDENCE_ADDED, {"evidence_id": f"EV-{i:04d}"})

    path = audit.audit_path(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # drop the newest entry

    ok, problems = audit.verify(tmp_path)

    assert not ok, "removing the most recent custody entry went undetected"
    assert problems


def _case_with_one_evidence_file(tmp_path):
    cases_dir = tmp_path / "cases"
    created = runner.invoke(cli_app, ["case", "create", "--name", "Proof", "--cases-dir", str(cases_dir)])
    assert created.exit_code == 0, created.output

    source = tmp_path / "events.json"
    source.write_text(
        json.dumps([{"timestamp": "2026-01-01T00:00:00Z", "event_type": "dns_query", "domain": "example.test"}]),
        encoding="utf-8",
    )
    added = runner.invoke(
        cli_app, ["evidence", "add", str(source), "--case", "INC-0001", "--cases-dir", str(cases_dir)]
    )
    assert added.exit_code == 0, added.output
    return cases_dir


def _tamper_with_stored_evidence(cases_dir):
    case_dir = cases_dir / "INC-0001"
    manager = EvidenceManager(case_dir)
    stored = manager.stored_file_path("EV-0001")
    os.chmod(stored, os.stat(stored).st_mode | stat.S_IWUSR)
    with open(stored, "ab") as handle:
        handle.write(b"\n ")
    assert manager.verify("EV-0001") is False  # the library knows; the question is whether the CLI says so
    return case_dir


@_gap("no `evidence verify` command: EvidenceManager.verify() exists but is not exposed on the CLI")
def test_cli_has_an_evidence_verify_command_that_catches_tampering(tmp_path):
    cases_dir = _case_with_one_evidence_file(tmp_path)
    _tamper_with_stored_evidence(cases_dir)

    result = runner.invoke(cli_app, ["evidence", "verify", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    assert result.exit_code != 0, result.output
    assert "mismatch" in result.output.lower() or "tamper" in result.output.lower()


@_gap("`analyze` parses evidence without re-hashing it, so a modified file is analysed silently")
def test_analyze_flags_evidence_modified_after_ingest(tmp_path):
    cases_dir = _case_with_one_evidence_file(tmp_path)
    _tamper_with_stored_evidence(cases_dir)

    result = runner.invoke(cli_app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases_dir)])

    out = result.output.lower()
    assert "mismatch" in out or "tamper" in out or "hash" in out, result.output


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
