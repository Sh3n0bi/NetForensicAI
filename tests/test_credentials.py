"""Tests for cleartext credential detection, and for the two engines
agreeing about it.

The bug this guards against was an ABSENCE, not a wrong answer: the tshark
engine detected credentials, the scapy engine silently did not, and so
CLEARTEXT-CREDENTIALS and CREDENTIAL-REUSE reported nothing at all on a
machine without Wireshark. Nothing failed. The parity test at the bottom
is the one that would have caught it.
"""

import base64

import pytest

from netforensicai.parsers import credentials

pytest.importorskip("scapy")

from scapy.all import IP, TCP, Raw, wrpcap  # noqa: E402

from netforensicai.integrations import wireshark  # noqa: E402
from netforensicai.parsers.pcap import PcapParser  # noqa: E402

requires_tshark = pytest.mark.skipif(
    not wireshark.available(), reason="Wireshark/tshark is not installed on this machine"
)

CLIENT, SERVER = "10.0.0.5", "45.33.32.156"
PASSWORD = "W1nter2023!"


# --- the vocabulary, tested directly ------------------------------------


def test_a_form_body_credential_is_found():
    body = f"username=svc_backup&password={PASSWORD}".encode()
    payload = (
        b"POST /login HTTP/1.1\r\nHost: x.example\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n" + body
    )
    secrets, user = credentials.scan_payload(payload, dst_port=80, is_http_request=True)

    assert ("password", PASSWORD) in secrets
    assert user == "svc_backup"


def test_a_credential_in_the_query_string_is_found():
    """A GET puts it in the URL, where it also lands in every proxy log."""
    payload = b"GET /login?user=admin&password=hunter2 HTTP/1.1\r\nHost: x.example\r\n\r\n"
    secrets, user = credentials.scan_payload(payload, dst_port=80, is_http_request=True)

    assert ("password", "hunter2") in secrets
    assert user == "admin"


def test_http_basic_auth_is_decoded_to_name_the_account():
    """base64 is an encoding, not a protection. Naming the account is what
    makes the finding actionable."""
    token = base64.b64encode(f"svc_backup:{PASSWORD}".encode()).decode()
    payload = f"GET /admin HTTP/1.1\r\nHost: x.example\r\nAuthorization: Basic {token}\r\n\r\n".encode()
    secrets, user = credentials.scan_payload(payload, dst_port=80, is_http_request=True)

    assert user == "svc_backup"
    assert any(field == "authorization" for field, _ in secrets)


def test_a_login_form_in_a_response_is_not_a_credential():
    """A page that ASKS for a password contains the field names and no
    values. Reporting it would be exactly the false positive that teaches
    people to ignore the rule."""
    page = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        b'<form><input name="username"><input name="password" type="password"></form>'
    )
    secrets, _user = credentials.scan_payload(page, dst_port=80, is_http_request=False)

    assert secrets == []


def test_ftp_pass_is_a_credential_and_the_server_prompt_is_not():
    secrets, _ = credentials.scan_payload(b"PASS " + PASSWORD.encode() + b"\r\n", dst_port=21)
    assert ("password", PASSWORD) in secrets

    prompt, _ = credentials.scan_payload(b"331 Password required\r\n", dst_port=21)
    assert prompt == []


def test_imap_login_carries_both_halves():
    secrets, user = credentials.scan_payload(b"a1 LOGIN svc_backup s3cret\r\n", dst_port=143)

    assert ("password", "s3cret") in secrets
    assert user == "svc_backup"


def test_smtp_auth_plain_is_unwrapped():
    blob = base64.b64encode(b"\x00svc_backup\x00" + PASSWORD.encode()).decode()
    secrets, user = credentials.scan_payload(f"AUTH PLAIN {blob}\r\n".encode(), dst_port=25)

    assert ("password", PASSWORD) in secrets
    assert user == "svc_backup"


def test_telnet_is_not_guessed_at():
    """Telnet negotiates in-band and sends a character per packet, so a
    line reader produces confident nonsense. Reporting nothing beats
    that."""
    secrets, _ = credentials.scan_payload(b"\xff\xfd\x18\xff\xfd\x20login: root\r\n", dst_port=23)

    assert secrets == []


def test_encrypted_traffic_is_left_alone():
    secrets, _ = credentials.scan_payload(b"\x16\x03\x01\x02\x00\x01\x00", dst_port=443)

    assert secrets == []


def test_the_secret_is_never_returned_in_the_reference():
    reference = credentials.reference_for(7, "password", "HTTP", PASSWORD, "scapy")

    assert PASSWORD not in str(reference)
    assert len(reference["secret_sha256"]) == 64


def test_the_same_secret_hashes_the_same_across_engines():
    """CREDENTIAL-REUSE joins on this value. If the two engines hashed
    differently, reuse would be invisible in any mixed-engine case."""
    from_scapy = credentials.reference_for(1, "password", "FTP", PASSWORD, "scapy")
    from_tshark = credentials.reference_for(9, "password", "HTTP", PASSWORD, "tshark")

    assert from_scapy["secret_sha256"] == from_tshark["secret_sha256"]


# --- end to end, through the scapy engine -------------------------------


def _flow(packets, payloads, dport, sport=49000):
    cseq = 1000
    for payload in payloads:
        packets.append(
            IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq)
            / Raw(load=payload)
        )
        cseq += len(payload)
    return packets


@pytest.fixture
def capture(tmp_path):
    body = f"username=svc_backup&password={PASSWORD}".encode()
    packets = []
    _flow(packets, [
        b"POST /login HTTP/1.1\r\nHost: portal.example\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
    ], 80, 49001)
    _flow(packets, [
        b"USER svc_backup\r\n",
        b"PASS " + PASSWORD.encode() + b"\r\n",
    ], 21, 49002)

    for i, packet in enumerate(packets):
        packet.time = 1700000000.0 + i

    path = tmp_path / "creds.pcap"
    wrpcap(str(path), packets)
    return path


def _credential_events(path, evidence_id="EV-0001"):
    events = list(PcapParser().parse(path, evidence_id))
    return [e for e in events if e.event_type == "credential_exposure"]


def test_the_scapy_engine_emits_credential_events(capture):
    """The gap this whole module exists to close."""
    found = _credential_events(capture)

    protocols = {e.raw_event_reference["protocol"] for e in found}
    assert protocols == {"HTTP", "FTP"}
    assert all(e.severity == "high" for e in found)
    assert all(e.raw_event_reference["engine"] == "scapy" for e in found)


def test_the_same_password_on_two_protocols_shares_one_hash(capture):
    """What CREDENTIAL-REUSE joins on, produced by the scapy engine alone."""
    found = _credential_events(capture)
    hashes = {e.raw_event_reference["secret_sha256"] for e in found
              if e.raw_event_reference["field"] == "password"}

    assert len(hashes) == 1, "the same password should hash to one value"


def test_no_event_carries_the_password(capture):
    """The property that lets this run at all: the case database never
    holds a working credential."""
    events = list(PcapParser().parse(capture, "EV-0001"))

    for event in events:
        assert PASSWORD not in str(event.to_dict() if hasattr(event, "to_dict") else event)


@requires_tshark
def test_both_engines_report_the_same_credentials(capture):
    """ENGINE PARITY - the test that would have caught the original gap.

    The two engines see the packet completely differently (dissected
    fields versus raw bytes), so they will not agree on packet counts or
    on every field. They must agree on what the credentials were.
    """
    from netforensicai.parsers import pcap_tshark

    scapy_events = _credential_events(capture)
    tshark_events = [
        e for e in pcap_tshark.iter_parse(capture, "EV-0001")
        if e.event_type == "credential_exposure"
    ]

    def summary(events):
        return {
            (e.raw_event_reference["field"], e.raw_event_reference["protocol"],
             e.raw_event_reference["secret_sha256"])
            for e in events
        }

    assert summary(scapy_events) == summary(tshark_events)
