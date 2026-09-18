"""Tests for starting an investigation from the browser, and the home list.

The web UI's first screen used to tell a new user to open a terminal and
run `netforensic case create`. These pin what replaced that: a case can be
created over the API with the same chain-of-custody record the CLI writes,
and the case list carries enough state to tell an empty case from a
finished one without opening either.
"""

from datetime import datetime, timezone

import pytest

from netforensicai.core import audit
from netforensicai.core.case import CaseManager
from netforensicai.core.detections import scan_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore
from netforensicai.web.app import create_app


@pytest.fixture
def cases_dir(tmp_path):
    return tmp_path / "cases"


@pytest.fixture
def client(cases_dir):
    test_client = create_app(cases_dir).test_client()
    test_client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"
    return test_client


def test_a_case_can_be_created_from_the_browser(client, cases_dir):
    response = client.post(
        "/api/cases",
        json={"name": "  Finance laptop  ", "investigator": "Asha", "description": "Beaconing alert"},
    )

    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["case_id"] == "INC-0001"
    assert body["name"] == "Finance laptop", "surrounding whitespace is trimmed"
    assert body["investigator"] == "Asha"
    assert body["status"] == "open"
    assert CaseManager(cases_dir).load("INC-0001").description == "Beaconing alert"


def test_a_case_created_in_the_browser_opens_the_same_custody_record_as_the_cli(client, cases_dir):
    client.post("/api/cases", json={"name": "Custody"})

    entries = audit.read_entries(cases_dir / "INC-0001")
    assert entries and entries[0]["action"] == audit.CASE_CREATED
    assert audit.verify(cases_dir / "INC-0001")


def test_consecutive_creates_get_distinct_case_ids(client):
    first = client.post("/api/cases", json={"name": "One"}).get_json()
    second = client.post("/api/cases", json={"name": "Two"}).get_json()

    assert first["case_id"] != second["case_id"]


@pytest.mark.parametrize(
    "payload, fragment",
    [
        ({}, "name"),
        ({"name": "   "}, "name"),
        ({"name": "x" * 201}, "too long"),
        ({"name": "ok", "description": "d" * 2001}, "too long"),
        ({"name": "ok", "investigator": "i" * 121}, "too long"),
    ],
)
def test_invalid_case_details_are_refused_with_a_reason(client, cases_dir, payload, fragment):
    """Refused before anything is written: a rejected create must not leave
    a half-made case directory behind."""
    response = client.post("/api/cases", json=payload)

    assert response.status_code == 400
    assert fragment in response.get_json()["error"].lower()
    assert not cases_dir.exists() or not any(cases_dir.iterdir())


def test_creating_a_case_requires_the_csrf_header(cases_dir):
    bare = create_app(cases_dir).test_client()

    assert bare.post("/api/cases", json={"name": "Forged"}).status_code == 403


def _analyzed_case(cases_dir, name="Analyzed"):
    case = CaseManager(cases_dir).create(name=name, investigator="analyst")
    case_dir = cases_dir / case.case_id
    events = [
        Event(
            event_id="EVT-EV-0001-000001",
            evidence_id="EV-0001",
            source="pcap",
            event_type="http_request",
            timestamp=datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.5",
            dst_ip="45.33.32.156",
            dst_port=80,
            url="http://bad.top/x.exe",
            domain="bad.top",
        )
    ]
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence("EV-0001", events)
        extract_and_store(store, events)
        scan_case(store)
    return case


def test_the_case_list_tells_an_empty_case_from_an_analyzed_one(client, cases_dir):
    """Without this the home screen had to show both identically, and the
    only way to find the finished investigation was to open each case."""
    CaseManager(cases_dir).create(name="Empty", investigator="analyst")
    _analyzed_case(cases_dir)

    rows = {row["name"]: row for row in client.get("/api/cases").get_json()}

    empty, analyzed = rows["Empty"], rows["Analyzed"]
    assert (empty["evidence_count"], empty["event_count"], empty["severity"]) == (0, 0, None)
    assert analyzed["event_count"] == 1
    assert analyzed["detection_count"] >= 1
    assert analyzed["severity"] in ("low", "medium", "high", "critical")
    assert analyzed["assessment"]
    assert analyzed["summary_error"] is None


def test_the_brief_list_skips_the_summaries(client, cases_dir):
    """The case switcher renders on every page. It needs names, not every
    case store opened on each navigation."""
    _analyzed_case(cases_dir)

    rows = client.get("/api/cases?brief=1").get_json()

    assert rows[0]["name"] == "Analyzed"
    assert "severity" not in rows[0]
    assert "event_count" not in rows[0]


def test_one_unreadable_case_does_not_take_down_the_list(client, cases_dir, monkeypatch):
    from netforensicai.core import store as store_module

    CaseManager(cases_dir).create(name="Broken", investigator="analyst")  # INC-0001, listed first
    CaseManager(cases_dir).create(name="Fine", investigator="analyst")
    real = store_module.CaseStore.count_events
    calls = {"n": 0}

    def fails_once(self):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("store unreadable")
        return real(self)

    monkeypatch.setattr(store_module.CaseStore, "count_events", fails_once)
    response = client.get("/api/cases")

    assert response.status_code == 200
    rows = {row["name"]: row for row in response.get_json()}
    assert "unreadable" in rows["Broken"]["summary_error"]
    assert rows["Fine"]["summary_error"] is None


def test_the_home_screen_no_longer_sends_new_users_to_the_terminal(client):
    """The empty state used to be the text 'Create one with: netforensic
    case create'. Pinned so it does not come back."""
    script = client.get("/app.js").get_data(as_text=True)

    # The instruction itself, not the phrase: the code comment explaining
    # why the old empty state was replaced is allowed to quote it.
    assert "Create one with: netforensic case create" not in script
    assert "function openNewCaseModal" in script
