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
