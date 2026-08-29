"""API tests for the dig surfaces (search, streams, triage, artifacts) and
the dashboard counters added alongside them.

These wrap core modules already covered elsewhere, so the tests here are
about the WEB layer's own decisions: what it resolves, what it refuses,
what shape it returns, and the one thing that would be easy to get wrong
- a GET that quietly writes to disk.
"""

import json

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

from netforensicai.core.case import CaseManager
from netforensicai.core.correlation import correlate_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.store import CaseStore
from netforensicai.integrations import wireshark
from netforensicai.web.app import create_app

requires_tshark = pytest.mark.skipif(
    not wireshark.available(), reason="Wireshark/tshark is not installed on this machine"
)

FLAG = "flag{web_route_works}"


@pytest.fixture(autouse=True)
def _unpin_engine(monkeypatch):
    from netforensicai.parsers import pcap_engine

    monkeypatch.delenv(pcap_engine.ENGINE_ENV, raising=False)


def _capture(path):
    client, server = "10.0.0.5", "93.184.216.34"

    def tcp(sport, dport, flags, seq, ack, payload=b"", offset=0.0, forward=True):
        src, dst = (client, server) if forward else (server, client)
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        if payload:
            pkt = pkt / Raw(load=payload)
        pkt.time = 1_700_000_000.0 + offset
        return pkt

    request_bytes = b"GET /flag HTTP/1.1\r\nHost: ctf.example.com\r\n\r\n"
    body = FLAG.encode()
    response_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body

    wrpcap(
        str(path),
        [
            tcp(44000, 80, "S", 1000, 0, offset=0.1),
            tcp(80, 44000, "SA", 5000, 1001, offset=0.2, forward=False),
            tcp(44000, 80, "A", 1001, 5001, offset=0.3),
            tcp(44000, 80, "PA", 1001, 5001, request_bytes, offset=0.4),
            tcp(80, 44000, "PA", 5001, 1001 + len(request_bytes), response_bytes, offset=0.5, forward=False),
        ],
    )
    return path


@pytest.fixture
def pcap_client(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="Dig", investigator="analyst")
    case_dir = cases_dir / case.case_id
    evidence = EvidenceManager(case_dir).add(_capture(tmp_path / "dig.pcap"), case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)

    client = create_app(cases_dir).test_client()
    client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"
    return client, case, evidence, case_dir


@pytest.fixture
def json_client(tmp_path):
    """A case with normalized events but no capture - the shape most of
    the dashboard counters are computed from."""
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="Counters", investigator="analyst")
    case_dir = cases_dir / case.case_id

    source = tmp_path / "events.json"
    source.write_text(
        json.dumps(
            [
                {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe", "src_ip": "192.168.1.10"},
                {"timestamp": "2026-08-27T09:00:30Z", "type": "network_connection", "src_ip": "192.168.1.10", "dst_ip": "203.0.113.7", "dst_port": 4444},
                {"timestamp": "2026-08-27T09:01:00Z", "type": "network_connection", "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "dst_port": 53},
            ]
        ),
        encoding="utf-8",
    )
    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)

    from netforensicai.parsers.generic import JsonParser

    events = JsonParser().parse(
        EvidenceManager(case_dir).stored_file_path(evidence.evidence_id), evidence_id=evidence.evidence_id
    )
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence(evidence.evidence_id, events)
        extract_and_store(store, events)
        correlate_case(store)

    client = create_app(cases_dir).test_client()
    client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"
    return client, case, case_dir


# --- dashboard counters -------------------------------------------------


def test_the_case_payload_carries_the_counters_the_dashboard_shows(json_client):
    client, case, _case_dir = json_client

    payload = client.get(f"/api/cases/{case.case_id}").get_json()

    assert payload["event_count"] == 3
    assert payload["entity_count"] > 0
    assert payload["correlation_count"] >= 1
    assert payload["artifact_count"] == 0
    assert isinstance(payload["correlation_by_type"], dict)


def test_correlations_are_split_by_strength_not_just_totalled(json_client):
    """`related` and `possible_relationship` are different strengths of
    claim; one number reads as though they were the same."""
    client, case, _case_dir = json_client

    payload = client.get(f"/api/cases/{case.case_id}").get_json()

    assert sum(payload["correlation_by_type"].values()) == payload["correlation_count"]
    assert "related" in payload["correlation_by_type"]


def test_entities_carry_event_and_link_counts(json_client):
    client, case, _case_dir = json_client

    entities = client.get(f"/api/cases/{case.case_id}/entities").get_json()

    assert entities
    assert all("event_count" in e and "link_count" in e for e in entities)
    shared = next(e for e in entities if e["value"] == "192.168.1.10")
    # The IP appears in all three events.
    assert shared["event_count"] == 3


def test_an_entity_in_one_event_twice_counts_that_event_once(json_client):
    """entity_events is keyed on (entity, event, field), so an address that
    is both source and destination has two rows for one event."""
    client, case, _case_dir = json_client

    entities = client.get(f"/api/cases/{case.case_id}/entities").get_json()

    for entity in entities:
        assert entity["event_count"] <= 3, entity


def test_entities_can_be_ranked_by_event_count(json_client):
    client, case, _case_dir = json_client

    ranked = client.get(f"/api/cases/{case.case_id}/entities?sort=events").get_json()

    counts = [e["event_count"] for e in ranked]
    assert counts == sorted(counts, reverse=True)


# --- search -------------------------------------------------------------


@requires_tshark
def test_search_finds_the_flag_and_names_the_evidence(pcap_client):
    client, case, evidence, _case_dir = pcap_client

    response = client.post(f"/api/cases/{case.case_id}/search", json={"pattern": "flag{"})

    assert response.status_code == 200, response.get_json()
    payload = response.get_json()
    assert payload["evidence_id"] == evidence.evidence_id
    assert payload["hits"]
    assert FLAG in payload["hits"][0]["excerpt"]
    assert payload["hits"][0]["stream"] is not None


@requires_tshark
def test_search_supports_regex_mode(pcap_client):
    client, case, _evidence, _case_dir = pcap_client

    payload = client.post(
        f"/api/cases/{case.case_id}/search", json={"pattern": r"flag\{[^}]+\}", "mode": "regex"}
    ).get_json()

    assert payload["hits"][0]["matched"] == FLAG


def test_search_requires_a_pattern(pcap_client):
    client, case, _evidence, _case_dir = pcap_client

    response = client.post(f"/api/cases/{case.case_id}/search", json={})

    assert response.status_code == 400


@requires_tshark
def test_a_bad_pattern_is_the_callers_fault_not_a_server_error(pcap_client):
    client, case, _evidence, _case_dir = pcap_client

    response = client.post(
        f"/api/cases/{case.case_id}/search", json={"pattern": "flag{[", "mode": "regex"}
    )

    assert response.status_code == 400
    assert "regular expression" in response.get_json()["error"]


def test_search_on_a_case_with_no_capture_says_so(json_client):
    client, case, _case_dir = json_client

    response = client.post(f"/api/cases/{case.case_id}/search", json={"pattern": "x"})

    assert response.status_code == 404
    assert "no capture evidence" in response.get_json()["error"].lower()


def test_an_unknown_evidence_id_is_rejected(pcap_client):
    client, case, _evidence, _case_dir = pcap_client

    response = client.post(
        f"/api/cases/{case.case_id}/search", json={"pattern": "x", "evidence_id": "EV-9999"}
    )

    assert response.status_code == 404


# --- streams ------------------------------------------------------------


@requires_tshark
def test_streams_are_listed_and_followed(pcap_client):
    client, case, evidence, _case_dir = pcap_client

    listed = client.get(f"/api/cases/{case.case_id}/streams").get_json()
    assert listed["evidence_id"] == evidence.evidence_id
    assert listed["streams"]

    index = listed["streams"][0]["stream"]
    followed = client.get(f"/api/cases/{case.case_id}/streams/{index}").get_json()

    assert followed["stream"] == index
    assert followed["turns"]
    conversation = "\n".join(turn["text"] for turn in followed["turns"])
    assert FLAG in conversation


@requires_tshark
def test_following_a_stream_that_does_not_exist_is_a_404(pcap_client):
    client, case, _evidence, _case_dir = pcap_client

    response = client.get(f"/api/cases/{case.case_id}/streams/9999")

    assert response.status_code == 404


# --- triage -------------------------------------------------------------


@requires_tshark
def test_triage_reports_every_section(pcap_client):
    client, case, evidence, _case_dir = pcap_client

    payload = client.get(f"/api/cases/{case.case_id}/triage").get_json()

    assert payload["evidence_id"] == evidence.evidence_id
    assert payload["protocols"]
    assert any(c["value"] == FLAG for c in payload["candidates"])
    assert "top_streams" in payload


@requires_tshark
def test_triage_does_not_write_files_from_a_get(pcap_client):
    """Object export writes to disk. A GET a dashboard polls must not have
    that side effect, so the route reports recoverable files without
    saving them."""
    client, case, _evidence, case_dir = pcap_client
    artifacts = case_dir / "artifacts"
    before = sorted(p.name for p in artifacts.rglob("*")) if artifacts.exists() else []

    payload = client.get(f"/api/cases/{case.case_id}/triage").get_json()

    after = sorted(p.name for p in artifacts.rglob("*")) if artifacts.exists() else []
    assert after == before
    assert all(f["path"] is None for f in payload["files"])


@requires_tshark
def test_triage_does_not_create_findings_or_audit_entries(pcap_client):
    """Asking a question of evidence is not an action taken on it."""
    from netforensicai.core import audit
    from netforensicai.core.finding import FindingManager

    client, case, _evidence, case_dir = pcap_client
    before = len(audit.read_entries(case_dir))

    client.get(f"/api/cases/{case.case_id}/triage")

    assert len(audit.read_entries(case_dir)) == before
    assert FindingManager(case_dir).list() == []


# --- artifacts ----------------------------------------------------------


def test_artifacts_are_listed_with_sizes(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="Artifacts", investigator="analyst")
    case_dir = cases_dir / case.case_id

    carved = case_dir / "artifacts" / "EV-0001" / "http"
    carved.mkdir(parents=True)
    (carved / "malware.exe").write_bytes(b"MZ" + b"\x00" * 40)
    manager.register_artifact(case.case_id, "artifacts/EV-0001/http/malware.exe")

    client = create_app(cases_dir).test_client()
    rows = client.get(f"/api/cases/{case.case_id}/artifacts").get_json()

    assert len(rows) == 1
    assert rows[0]["name"] == "malware.exe"
    assert rows[0]["protocol"] == "http"
    assert rows[0]["size_bytes"] == 42
    assert rows[0]["missing"] is False


def test_a_registered_artifact_that_has_gone_missing_is_reported_not_hidden(tmp_path):
    """A carved file that is no longer on disk is something an
    investigator needs to see, not something to quietly drop."""
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="Artifacts", investigator="analyst")
    manager.register_artifact(case.case_id, "artifacts/EV-0001/http/vanished.bin")

    client = create_app(cases_dir).test_client()
    rows = client.get(f"/api/cases/{case.case_id}/artifacts").get_json()

    assert len(rows) == 1
    assert rows[0]["missing"] is True
    assert rows[0]["size_bytes"] is None
