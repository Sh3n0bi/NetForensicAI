"""Tests for the triage presets.

Pattern definition and classification are pure logic and tested
unconditionally - a regex that silently stops matching is exactly the
failure a preset suite dies of. The parts that shell out to tshark run
against a small purpose-built capture and skip when it is absent.
"""

import re

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
from typer.testing import CliRunner

from netforensicai.cli import app as cli_app
from netforensicai.core import ctf
from netforensicai.core.case import CaseManager
from netforensicai.core.evidence import EvidenceManager
from netforensicai.integrations import wireshark

runner = CliRunner()

requires_tshark = pytest.mark.skipif(
    not wireshark.available(), reason="Wireshark/tshark is not installed on this machine"
)

FLAG = "flag{r34ssembly_w0rks}"
FTP_PASSWORD = "PASS Pa55w0rd!ftp"


@pytest.fixture(autouse=True)
def _unpin_engine(monkeypatch):
    from netforensicai.parsers import pcap_engine

    monkeypatch.delenv(pcap_engine.ENGINE_ENV, raising=False)


def _capture(path):
    """A capture holding, deliberately, more than one secret per packet."""
    client, server = "10.0.0.5", "93.184.216.34"
    clock = [0.0]

    def tcp(src, dst, sport, dport, flags, seq, ack, payload=b""):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        if payload:
            pkt = pkt / Raw(load=payload)
        clock[0] += 0.1
        pkt.time = 1_700_000_000.0 + clock[0]
        return pkt

    def exchange(sport, dport, request, response):
        return [
            tcp(client, server, sport, dport, "S", 1000, 0),
            tcp(server, client, dport, sport, "SA", 5000, 1001),
            tcp(client, server, sport, dport, "A", 1001, 5001),
            tcp(client, server, sport, dport, "PA", 1001, 5001, request),
            tcp(server, client, dport, sport, "PA", 5001, 1001 + len(request), response),
        ]

    packets = []
    body = f"Congratulations! {FLAG} -- keep going".encode()
    # One request carrying BOTH an Authorization header and a Cookie.
    packets += exchange(
        44001,
        80,
        b"GET /secret HTTP/1.1\r\nHost: ctf.example.com\r\n"
        b"Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=\r\n"
        b"Cookie: session=deadbeefcafe1234567890\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body,
    )
    form = b"username=alice&password=hunter2trustno1"
    packets += exchange(
        44002,
        80,
        b"POST /login HTTP/1.1\r\nHost: ctf.example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n" % len(form) + form,
        b"HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n",
    )
    # USER and PASS on separate lines of ONE packet.
    packets += exchange(
        44003,
        21,
        b"USER ctfadmin\r\nPASS Pa55w0rd!ftp\r\n",
        b"220 Welcome\r\n230 Login successful\r\n",
    )
    secrets = (
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----\n"
        b"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
    )
    packets += exchange(
        44004,
        80,
        b"GET /backup HTTP/1.1\r\nHost: ctf.example.com\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(secrets) + secrets,
    )
    for i in range(3):
        dns = Ether() / IP(src=client, dst="8.8.8.8") / UDP(sport=51000 + i, dport=53) / Raw(load=b"\x00" * 24)
        clock[0] += 0.1
        dns.time = 1_700_000_000.0 + clock[0]
        packets.append(dns)

    wrpcap(str(path), packets)
    return path


@pytest.fixture
def ctf_case(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="CTF", investigator="player")
    case_dir = cases_dir / case.case_id
    evidence = EvidenceManager(case_dir).add(_capture(tmp_path / "ctf.pcap"), case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)
    return cases_dir, case, evidence


# --- Patterns -----------------------------------------------------------


def test_every_pattern_compiles():
    """A preset suite dies of a regex that stopped compiling, silently."""
    for category, patterns in ctf.CATEGORIES.items():
        for name, expression in patterns.items():
            re.compile(expression), f"{category}/{name}"


def test_classify_prefers_the_specific_pattern_over_the_catch_all():
    """`prefix{}` matches anything flag-shaped and is declared last, so a
    real flag must still be reported as `flag{}`."""
    assert ctf.classify(ctf.FLAG_PATTERNS, "flag{abc123}") == "flag{}"
    assert ctf.classify(ctf.FLAG_PATTERNS, "HTB{abc123}") == "HTB{}"
    # Something flag-shaped with an unknown prefix still gets caught.
    assert ctf.classify(ctf.FLAG_PATTERNS, "myctf{abc123}") == "prefix{}"


def test_classify_returns_none_when_nothing_matches():
    assert ctf.classify(ctf.FLAG_PATTERNS, "just some text") is None


def test_the_combined_pattern_matches_everything_its_parts_do():
    """One tshark pass per category depends on the alternation being
    equivalent to the individual patterns."""
    combined = ctf.combined_pattern(ctf.CREDENTIAL_PATTERNS)
    for sample in (
        "Authorization: Basic YWRtaW46cGFzcw==",
        "password=hunter2",
        "USER bob",
        "Cookie: session=abcdefgh12345678",
    ):
        assert re.search(combined, sample, re.IGNORECASE), sample


def test_line_anchored_patterns_do_not_run_across_lines():
    """USER and PASS arrive in one packet on separate lines. If line
    endings are flattened, one greedy match swallows both and the password
    is never reported separately."""
    payload = "USER ctfadmin\r\nPASS Pa55w0rd!ftp\r\n"

    user = re.search(ctf.CREDENTIAL_PATTERNS["ftp-user"], payload, re.IGNORECASE).group(0).strip()
    password = re.search(ctf.CREDENTIAL_PATTERNS["ftp-pass"], payload, re.IGNORECASE).group(0).strip()

    assert user == "USER ctfadmin"
    assert password == FTP_PASSWORD


def test_an_unknown_category_is_rejected():
    with pytest.raises(ctf.CtfError):
        ctf.hunt("x.pcap", "passwords")


# --- Against a real capture ---------------------------------------------


@requires_tshark
def test_the_flag_is_found(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    candidates, _truncated = ctf.hunt(path, "flags")

    assert [c.value for c in candidates if c.pattern == "flag{}"] == [FLAG]
    assert candidates[0].stream is not None


@requires_tshark
def test_multiple_secrets_in_one_packet_are_all_reported(tmp_path):
    """The bug this pins: reporting only the first match per packet meant
    the Cookie beside the Authorization header, and the JWT beside the
    private key, were silently dropped."""
    path = _capture(tmp_path / "ctf.pcap")

    credentials, _ = ctf.hunt(path, "credentials")
    secrets, _ = ctf.hunt(path, "secrets")

    found = {c.pattern for c in credentials}
    assert {"http-basic", "http-cookie"} <= found, found
    assert {"form-username", "form-password"} <= found, found
    assert {"ftp-user", "ftp-pass"} <= found, found

    assert {s.pattern for s in secrets} == {"private-key", "jwt"}


@requires_tshark
def test_a_repeated_value_is_reported_once(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    candidates, _ = ctf.hunt(path, "credentials")

    values = [c.value for c in candidates]
    assert len(values) == len(set(values))


@requires_tshark
def test_the_protocol_summary_names_what_is_in_the_capture(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    protocols = {p.protocol: p for p in ctf.protocol_summary(path)}

    assert {"tcp", "udp", "http", "ftp", "dns"} <= set(protocols)
    assert protocols["tcp"].frames > 0
    # Cleartext protocols carry a note explaining why they are worth a look.
    assert protocols["http"].note and "leartext" in protocols["http"].note
    assert protocols["eth"].depth < protocols["ip"].depth < protocols["tcp"].depth


@requires_tshark
def test_transferred_files_are_reported_and_hashed(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    files = ctf.extract_files(path)

    assert files
    assert all(len(f.sha256) == 64 for f in files)
    # Reported without being written anywhere when no output dir is given.
    assert all(f.path is None for f in files)


@requires_tshark
def test_files_are_only_written_when_a_destination_is_given(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")
    out = tmp_path / "recovered"

    files = ctf.extract_files(path, output_dir=out)

    assert files
    assert all(f.path for f in files)
    written = list(out.rglob("*"))
    assert [p for p in written if p.is_file()]


@requires_tshark
def test_triage_runs_every_preset(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    report = ctf.triage(path)

    assert report.protocols
    assert report.candidates
    assert report.files
    assert report.top_streams
    assert {c.category for c in report.candidates} == {"flags", "credentials", "secrets"}


@requires_tshark
def test_a_display_filter_narrows_triage(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    report = ctf.triage(path, display_filter="ftp")

    patterns = {c.pattern for c in report.candidates}
    assert "flag{}" not in patterns
    assert "ftp-user" in patterns


# --- CLI ----------------------------------------------------------------


@requires_tshark
def test_cli_triage_reports_every_section(ctf_case):
    cases_dir, case, _evidence = ctf_case

    result = runner.invoke(cli_app, ["ctf", "triage", "--case", case.case_id, "--cases-dir", str(cases_dir)])

    assert result.exit_code == 0, result.output
    assert FLAG in result.output
    assert "Protocols:" in result.output
    assert "CREDENTIALS" in result.output
    assert "Recoverable files" in result.output
    assert "Largest conversations" in result.output
    # Candidates must be presented as candidates, not conclusions.
    assert "not verdicts" in result.output


@requires_tshark
def test_cli_triage_does_not_write_findings(ctf_case):
    """Triage is read-only; turning a candidate into a finding stays an
    explicit investigator action."""
    from netforensicai.core.finding import FindingManager

    cases_dir, case, _evidence = ctf_case

    runner.invoke(cli_app, ["ctf", "triage", "--case", case.case_id, "--cases-dir", str(cases_dir)])

    assert FindingManager(cases_dir / case.case_id).list() == []


@requires_tshark
def test_cli_hunt_one_category(ctf_case):
    cases_dir, case, _evidence = ctf_case

    result = runner.invoke(
        cli_app,
        ["ctf", "hunt", "--case", case.case_id, "--category", "secrets", "--cases-dir", str(cases_dir)],
    )

    assert result.exit_code == 0, result.output
    assert "private-key" in result.output
    assert "flag{" not in result.output


def test_cli_patterns_lists_every_category():
    result = runner.invoke(cli_app, ["ctf", "patterns"])

    assert result.exit_code == 0, result.output
    for category in ctf.CATEGORIES:
        assert category in result.output


def test_cli_option_default_matches_the_module():
    import netforensicai.cli as cli

    assert cli.CTF_DEFAULT_MAX_HITS == ctf.DEFAULT_MAX_HITS_PER_CATEGORY
