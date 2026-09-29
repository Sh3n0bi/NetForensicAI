"""`netforensic demo` - the one-command tour on a fabricated incident."""

import sys

import pytest
from typer.testing import CliRunner

from netforensicai.cli import DEMO_CASE_NAME, app
from netforensicai.core.case import CaseManager
from netforensicai.core.store import CaseStore

pytest.importorskip("scapy")

runner = CliRunner()


def test_demo_builds_analyzes_and_tells_the_story(tmp_path):
    cases_dir = tmp_path / "cases"
    result = runner.invoke(app, ["demo", "--cases-dir", str(cases_dir)])

    assert result.exit_code == 0, result.output
    cases = CaseManager(cases_dir).list()
    assert [c.name for c in cases] == [DEMO_CASE_NAME]
    case = cases[0]
    assert len(case.evidence) == 1

    with CaseStore(cases_dir / case.case_id) as store:
        rules = {d["rule_id"] for d in store.list_detections()}
    # The acts of the incident, each caught by the engine that is running.
    assert {"EXECUTABLE-DOWNLOAD", "CLEARTEXT-CREDENTIALS", "CREDENTIAL-REUSE",
            "KEY-MATERIAL-IN-TRANSIT", "PERIODIC-BEACON"} <= rules

    assert "Assessment [critical]" in result.output
    assert f"netforensic web --cases-dir {cases_dir}" in result.output
    # The temporary capture is gone; only the case's own evidence copy remains.
    assert not list(tmp_path.glob("*.pcap"))


def test_demo_never_touches_an_existing_case(tmp_path):
    cases_dir = tmp_path / "cases"
    existing = CaseManager(cases_dir).create(name="Real investigation", investigator="analyst")

    first = runner.invoke(app, ["demo", "--cases-dir", str(cases_dir)])
    second = runner.invoke(app, ["demo", "--cases-dir", str(cases_dir)])

    assert first.exit_code == 0 and second.exit_code == 0
    cases = CaseManager(cases_dir).list()
    assert len(cases) == 3
    assert CaseManager(cases_dir).load(existing.case_id).evidence == []


def test_demo_without_scapy_explains_the_extra(tmp_path, monkeypatch):
    # A None entry in sys.modules makes the import raise ImportError - once
    # the package attribute an earlier import left behind is removed too.
    import netforensicai

    monkeypatch.delattr(netforensicai, "demo", raising=False)
    monkeypatch.setitem(sys.modules, "netforensicai.demo", None)
    result = runner.invoke(app, ["demo", "--cases-dir", str(tmp_path / "cases")])

    assert result.exit_code == 1
    assert "netforensicai[pcap]" in result.output
    assert not (tmp_path / "cases").exists() or CaseManager(tmp_path / "cases").list() == []


def test_demo_capture_is_deterministic(tmp_path):
    from netforensicai import demo

    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    assert demo.write_capture(a) == demo.write_capture(b) == 82
    assert a.read_bytes() == b.read_bytes()


def test_demo_open_launches_the_story_and_serves_locally(tmp_path, monkeypatch):
    import typer

    seen = {}

    class _FakeApp:
        def run(self, **kwargs):
            seen["run"] = kwargs

    monkeypatch.setattr(typer, "launch", lambda url: seen.setdefault("url", url))
    monkeypatch.setattr("netforensicai.web.app.create_app", lambda cases_dir: _FakeApp())

    result = runner.invoke(app, ["demo", "--cases-dir", str(tmp_path / "cases"), "--open", "--port", "8123"])

    assert result.exit_code == 0, result.output
    assert seen["url"] == "http://127.0.0.1:8123/#/case/INC-0001/story"
    assert seen["run"]["host"] == "127.0.0.1"  # loopback only, like `netforensic web`
    assert seen["run"]["debug"] is False
