"""Plain language for newcomers (core/explain.py) and where it surfaces.

The words are deterministic, so they are tested like any other output: the
direction of a transfer, whether each side is local or on the internet, and
whether the content can be read must all come out right.
"""

import pytest

from netforensicai.core import explain
from netforensicai.core.artifacts import _content_notes
from netforensicai.core.streams import StreamSummary


def _stream(a, b, sent, received, apps):
    return StreamSummary(stream=5, protocol="tcp", endpoint_a=a, endpoint_b=b, packets=9,
                         bytes=sent + received, first_frame=1, applications=apps,
                         bytes_a_to_b=sent, bytes_b_to_a=received)


def test_upload_from_the_network_to_the_internet():
    d = explain.describe_stream(_stream("10.10.4.17:49241", "104.21.7.19:20", 5090, 40, ["TCP", "FTP-DATA"]))
    assert d["headline"] == "10.10.4.17 (on your network) sent 5.0 KB to 104.21.7.19 (on the internet) using FTP-DATA."
    assert d["encrypted"] is False
    assert any("Not encrypted" in p for p in d["points"])
    assert any("data left your network" in p for p in d["points"])


def test_download_is_attributed_to_the_sender():
    d = explain.describe_stream(_stream("192.168.1.5:50000", "45.33.32.156:80", 400, 90_000, ["TCP", "HTTP"]))
    assert d["headline"].startswith("45.33.32.156 (on the internet) sent 87.9 KB to 192.168.1.5 (on your network)")
    assert not any("data left your network" in p for p in d["points"])


def test_balanced_conversation_is_an_exchange_and_tls_is_encrypted():
    d = explain.describe_stream(_stream("10.0.0.2:51000", "142.250.1.1:443", 3000, 2500, ["TCP", "TLSv1.3"]))
    assert "exchanged" in d["headline"] and "using TLS" in d["headline"]
    assert d["encrypted"] is True
    assert any("Encrypted" in p for p in d["points"])


def test_loopback_and_ipv6_endpoints():
    d = explain.describe_stream(_stream("127.0.0.1:5000", "127.0.0.1:8000", 100, 100, ["TCP"]))
    assert "this same computer" in d["headline"]
    d = explain.describe_stream(_stream("[fe80::1]:5000", "[2606:4700::1111]:443", 10, 10, ["TCP", "TLSv1.2"]))
    assert "fe80::1 (on your network)" in d["headline"]
    assert "2606:4700::1111 (on the internet)" in d["headline"]


def test_unknown_protocol_still_reads_and_makes_no_claim_about_encryption():
    d = explain.describe_stream(_stream("10.0.0.2:1", "10.0.0.3:2", 10, 0, ["TCP", "WEIRDPROTO"]))
    assert "using WEIRDPROTO" in d["headline"]
    assert d["encrypted"] is None


@pytest.mark.parametrize(
    "raw, name",
    [("TLSv1.2", "TLS"), ("SSLv3", "SSL"), ("HTTP", "HTTP"), ("HTTP/JSON", "HTTP"), ("FTP-DATA", "FTP-DATA"),
     ("data-text-lines", "Text lines"), ("SMB2", "SMB2")],
)
def test_protocol_names_resolve_despite_versions(raw, name):
    assert explain.protocol_info(raw)["name"] == name


def test_event_labels():
    assert explain.event_label("anomaly") == "Unusual packet (statistical outlier)"
    assert explain.event_label("windows_event:Microsoft-Windows-Kernel-Power") == "Windows event (Microsoft-Windows-Kernel-Power)"
    assert explain.event_label("some_new_type") == "Some new type"


def test_glossary_entries_are_complete():
    g = explain.glossary()
    assert len(g["protocols"]) >= 40
    for key, entry in g["protocols"].items():
        assert entry["name"] and entry["what"].endswith("."), key
        assert entry["encrypted"] in (True, False, None), key


@pytest.mark.parametrize(
    "text, expected",
    [
        (b"USER bob\r\nPASS s3cret\r\n", True),
        (b"GET / HTTP/1.1\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n", True),
        (b"a1 LOGIN bob hunter2\r\n", True),
        (b"The password policy says passwords expire every 90 days.\n", False),
        (b"passport number\n", False),
    ],
)
def test_plain_text_login_hint(text, expected):
    assert any("login" in n for n in _content_notes(text, "text")) is expected


# --- surfaces -----------------------------------------------------------------


def test_glossary_route():
    from netforensicai.web.app import create_app

    body = create_app("unused-cases").test_client().get("/api/glossary").get_json()
    assert body["protocols"]["ftp-data"]["name"] == "FTP-DATA"
    assert body["event_types"]["credential_exposure"] == "Password sent without encryption"


def test_reserved_ranges_are_not_called_local():
    # Regression: ipaddress.is_private includes documentation ranges, so an
    # address like 203.0.113.9 was described as "on your network".
    assert explain._host("203.0.113.9:80")[1] == "a reserved address"
    assert explain._host("10.1.2.3:80")[1] == "on your network"
    assert explain._host("172.20.0.1:80")[1] == "on your network"
    assert explain._host("172.32.0.1:80")[1] == "on the internet"
    assert explain._host("[fd00::5]:80")[1] == "on your network"


def test_conversations_api_speaks_plainly(tmp_path, monkeypatch):
    # Real tshark over the demo incident: the list leads with a sentence, and
    # opening the FTP upload / FTP login surfaces what they carried.
    from netforensicai.integrations import wireshark

    if not wireshark.available():
        pytest.skip("Wireshark/tshark is not installed")
    pytest.importorskip("scapy")
    from netforensicai import demo
    from netforensicai.core.case import CaseManager
    from netforensicai.core.evidence import EvidenceManager
    from netforensicai.web.app import create_app

    capture = tmp_path / "incident.pcap"
    demo.write_capture(capture)
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="plain", investigator="t")
    evidence = EvidenceManager(cases_dir / case.case_id).add(capture, case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)
    client = create_app(cases_dir).test_client()

    streams = client.get(f"/api/cases/{case.case_id}/streams").get_json()["streams"]
    upload = next(s for s in streams if "FTP-DATA" in s["applications"])
    login = next(s for s in streams if s["applications"][-1] == "FTP")
    assert upload["plain"]["headline"].startswith("10.10.4.17 (on your network) sent")
    assert upload["bytes_a_to_b"] > upload["bytes_b_to_a"]

    hints = client.get(f"/api/cases/{case.case_id}/streams/{upload['stream']}").get_json()["hints"]
    assert any("email addresses" in h for h in hints)
    hints = client.get(f"/api/cases/{case.case_id}/streams/{login['stream']}").get_json()["hints"]
    assert any("login" in h for h in hints)
