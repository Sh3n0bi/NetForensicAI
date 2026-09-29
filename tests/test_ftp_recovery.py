"""Recovering files moved over FTP when Wireshark's exporter cannot.

The synthetic incident uploads customers-export.csv over FTP with no
PASV/PORT negotiation in the capture, so `--export-objects ftp-data` recovers
nothing. These run the real tshark engine over that capture and check the
file comes back byte-exact, attributed to the right hosts and stream - and
that the stream it came from is downloadable too. Needs Wireshark.
"""

import pytest

from netforensicai.integrations import wireshark
from netforensicai.parsers.pcap_tshark import _safe_file_name

requires_tshark = pytest.mark.skipif(not wireshark.available(), reason="Wireshark/tshark is not installed")


@pytest.fixture(scope="module")
def incident(tmp_path_factory):
    pytest.importorskip("scapy")
    from netforensicai import demo

    path = tmp_path_factory.mktemp("ftp") / "incident.pcap"
    demo.write_capture(path)
    return path


def _expected_csv(capture):
    # Reassemble the upload independently of the recovery code: the demo's
    # FTP data packets, client -> server, in order.
    from scapy.all import TCP, Raw, rdpcap

    return b"".join(
        bytes(p[Raw].load) for p in rdpcap(str(capture))
        if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == 20
    )


@requires_tshark
def test_ftp_upload_is_recovered_byte_exact(incident, tmp_path):
    from netforensicai.parsers import pcap_tshark

    out = tmp_path / "artifacts" / "EV-0001"
    events = list(pcap_tshark.iter_parse(incident, "EV-0001", output_dir=out))
    [ftp] = [e for e in events if e.event_type == "file_transfer" and e.protocol == "FTP-DATA"]

    recovered = out / "ftp-data" / "customers-export.csv"
    assert recovered.read_bytes() == _expected_csv(incident)
    assert ftp.file_name == "customers-export.csv"
    assert (ftp.src_ip, ftp.dst_ip) == ("10.10.4.17", "104.21.7.19")
    ref = ftp.raw_event_reference
    assert ref["recovered_by"] == "ftp-command-pairing"
    assert ref["ftp_command"] == "STOR"
    assert "uploaded over FTP" in ftp.message


@requires_tshark
def test_stream_data_route_serves_the_same_bytes(incident, tmp_path, monkeypatch):
    from netforensicai.core.case import CaseManager
    from netforensicai.core.evidence import EvidenceManager
    from netforensicai.web.app import create_app

    monkeypatch.setenv("NETFORENSIC_PCAP_ENGINE", "tshark")
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="FTP", investigator="analyst")
    evidence = EvidenceManager(cases_dir / case.case_id).add(incident, case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)
    client = create_app(cases_dir).test_client()

    streams = client.get(f"/api/cases/{case.case_id}/streams").get_json()["streams"]
    [data_stream] = [s for s in streams if "FTP-DATA" in (s.get("applications") or [])]
    resp = client.get(f"/api/cases/{case.case_id}/streams/{data_stream['stream']}/data", query_string={"direction": "a"})
    assert resp.status_code == 200
    assert resp.data == _expected_csv(incident)
    assert resp.headers["Content-Disposition"].startswith("attachment")


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("customers-export.csv", "customers-export.csv"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\system32\\evil.dll", "evil.dll"),
        ("a<b>c|d?.txt", "a_b_c_d_.txt"),
        ("   ", "fallback.bin"),
        ("..", "fallback.bin"),
        (None, "fallback.bin"),
    ],
)
def test_safe_file_name(raw, expected):
    # The name comes from the evidence; it must never escape the output folder.
    assert _safe_file_name(raw, "fallback.bin") == expected


# --- names Wireshark gives exported objects (seen on real captures) ---------

HAWKEYE_SUBJECT = (
    "=%3futf-8%3fB%3fSGF3a0V5ZSBLZXlsb2dnZXIgLSBSZWJvcm4gdjkgLSBQYXNzd29yZHMgTG9ncyAtIHJvbWFuLm1jZ3VpcmUg"
    "XCBCRUlKSU5HLTVDRDEtUEMgLSAxNzMuNjYuMTQ2LjExMg==%3f=(1).eml"
)


@pytest.mark.parametrize(
    "raw, protocol, expected",
    [
        ("%5c", "http", "index"),  # the site root
        ("%5c(3)", "http", "index(3)"),  # tshark's copy suffix is kept
        ("%5cpizzajukebox.com%5cPolicies%5c{31B2F340-016D-11D2-945F-00C04FB984F9}%5cgpt.ini", "smb", "gpt.ini"),
        ("tkraw_Protected99.exe", "http", "tkraw_Protected99.exe"),
        ("..%2f..%2fetc%2fpasswd", "http", "passwd"),
        ("", "http", "index"),
    ],
)
def test_export_names(raw, protocol, expected):
    from netforensicai.parsers.pcap_tshark import _export_name

    assert _export_name(raw, protocol) == expected


def test_mime_encoded_email_subject_becomes_a_short_readable_name():
    # Regression: this ~200-character encoded name pushed the path past
    # Windows' limit, the write failed, and the whole capture was discarded.
    from netforensicai.parsers.pcap_tshark import MAX_RECOVERED_NAME, _export_name, _readable_export_name

    name = _export_name(HAWKEYE_SUBJECT, "imf")
    assert name.startswith("HawkEye Keylogger - Reborn v9 - Passwords Logs")
    assert name.endswith(".eml")
    assert len(name) <= MAX_RECOVERED_NAME
    assert "\\" not in name and "/" not in name
    assert "roman.mcguire \\ BEIJING-5CD1-PC" in _readable_export_name(HAWKEYE_SUBJECT)


def test_long_names_keep_their_extension():
    from netforensicai.parsers.pcap_tshark import MAX_RECOVERED_NAME

    name = _safe_file_name("x" * 300 + ".docx", "f.bin")
    assert len(name) == MAX_RECOVERED_NAME and name.endswith(".docx")


def test_one_unwritable_export_does_not_discard_the_capture(tmp_path, monkeypatch):
    from netforensicai.core.event import EventSequence
    from netforensicai.parsers import pcap_tshark

    staging = tmp_path / "staged"
    staging.mkdir()
    (staging / "good.txt").write_bytes(b"fine")
    (staging / "bad.txt").write_bytes(b"cannot be written")
    monkeypatch.setattr(pcap_tshark, "EXPORT_OBJECT_PROTOCOLS", ("http",))
    monkeypatch.setattr(pcap_tshark.wireshark, "export_objects", lambda *a: sorted(staging.iterdir()))

    real_fs_path = pcap_tshark.fs_path

    class _Refuses:
        def __init__(self, path):
            self.path = path

        def exists(self):
            return False

        def write_bytes(self, _data):
            raise OSError("path too long")

    monkeypatch.setattr(
        pcap_tshark, "fs_path", lambda p: _Refuses(p) if str(p).endswith("bad.txt") else real_fs_path(p)
    )
    events = pcap_tshark._export_objects("capture.pcap", tmp_path / "out", "EV-0001", EventSequence())

    assert [e.file_name for e in events] == ["good.txt"]
