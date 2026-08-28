"""Tests for content search and stream reassembly.

Both go back to the capture file rather than to the event store, and both
need tshark, so the parts that shell out are behind `requires_tshark`.
Filter construction and output parsing are pure logic and are tested
unconditionally - they are where the subtle bugs live (escaping, and
tshark's direction-by-indentation follow format).
"""

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
from typer.testing import CliRunner

from netforensicai.cli import app as cli_app
from netforensicai.core import search, streams
from netforensicai.core.case import CaseManager
from netforensicai.core.evidence import EvidenceManager
from netforensicai.integrations import wireshark

runner = CliRunner()

requires_tshark = pytest.mark.skipif(
    not wireshark.available(), reason="Wireshark/tshark is not installed on this machine"
)

FLAG = "flag{n3tw0rk_f0r3ns1cs}"


@pytest.fixture(autouse=True)
def _unpin_engine(monkeypatch):
    from netforensicai.parsers import pcap_engine

    monkeypatch.delenv(pcap_engine.ENGINE_ENV, raising=False)


def _capture(path):
    """A capture with a complete HTTP exchange whose response body carries
    a flag, plus an unrelated DNS packet."""
    client, server = "10.0.0.5", "93.184.216.34"

    def tcp(src, dst, sport, dport, flags, seq, ack, payload=b"", offset=0.0):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        if payload:
            pkt = pkt / Raw(load=payload)
        pkt.time = 1_700_000_000.0 + offset
        return pkt

    request = b"GET /secret HTTP/1.1\r\nHost: ctf.example.com\r\nUser-Agent: curl/8.0\r\n\r\n"
    body = FLAG.encode()
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body)
    ) + body

    dns = Ether() / IP(src=client, dst="8.8.8.8") / UDP(sport=51000, dport=53) / Raw(load=b"\x00" * 20)
    dns.time = 1_700_000_000.0

    packets = [
        dns,
        tcp(client, server, 44000, 80, "S", 1000, 0, offset=0.1),
        tcp(server, client, 80, 44000, "SA", 5000, 1001, offset=0.2),
        tcp(client, server, 44000, 80, "A", 1001, 5001, offset=0.3),
        tcp(client, server, 44000, 80, "PA", 1001, 5001, request, offset=0.4),
        tcp(server, client, 80, 44000, "PA", 5001, 1001 + len(request), response, offset=0.5),
    ]
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def ctf_case(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="CTF", investigator="analyst")
    case_dir = cases_dir / case.case_id
    evidence = EvidenceManager(case_dir).add(_capture(tmp_path / "ctf.pcap"), case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)
    return cases_dir, case, evidence


# --- Filter construction -------------------------------------------------


def test_a_case_sensitive_text_search_uses_contains():
    assert search.build_display_filter("flag{", case_sensitive=True) == 'frame contains "flag{"'


def test_a_case_insensitive_text_search_uses_matches_over_an_escaped_literal():
    """`contains` is case-sensitive and `matches` is not, so an
    insensitive search has to compile to a regex. The term is escaped so
    it stays a literal substring - otherwise searching for `flag{` would
    be an unterminated regex quantifier."""
    built = search.build_display_filter("flag{", case_sensitive=False)

    assert built.startswith("frame matches ")
    assert "\\{" in built


def test_a_search_term_containing_quotes_or_backslashes_is_escaped():
    """Wireshark processes backslash escapes inside a double-quoted filter
    literal, so an unescaped Windows path or quoted string would either
    fail to parse or match something else."""
    built = search.build_display_filter(r'C:\Users\"admin"', mode=search.TEXT, case_sensitive=True)

    assert built.count('\\\\') >= 1
    assert '\\"' in built


def test_hex_searches_accept_the_shapes_people_actually_paste():
    for value in ("4d5a9000", "4d:5a:90:00", "4D 5A 90 00", r"\x4d\x5a\x90\x00"):
        assert search.build_display_filter(value, mode=search.HEX) == "frame contains 4d:5a:90:00"


def test_a_malformed_hex_pattern_is_rejected():
    for value in ("zz", "4d5", ""):
        with pytest.raises(search.SearchError):
            search.build_display_filter(value, mode=search.HEX)


def test_an_invalid_regex_is_reported_as_a_regex_problem():
    """Better than letting tshark report a filter-syntax error naming a
    column in a string the analyst never wrote."""
    with pytest.raises(search.SearchError, match="regular expression"):
        search.build_display_filter("flag{[", mode=search.REGEX)


def test_an_unknown_search_mode_is_rejected():
    with pytest.raises(search.SearchError):
        search.build_display_filter("x", mode="fuzzy")


# --- Follow-output parsing ----------------------------------------------


def test_follow_output_direction_comes_from_indentation():
    """tshark marks node1 -> node0 chunks by a leading TAB and nothing
    else, so that indentation is the entire direction signal."""
    output = (
        "===================================================================\n"
        "Follow: tcp,ascii\n"
        "Filter: tcp.stream eq 4\n"
        "Node 0: 10.0.0.5:44000\n"
        "Node 1: 93.184.216.34:80\n"
        "22\n"
        "GET /secret HTTP/1.1\n"
        "\t17\n"
        "\tHTTP/1.1 200 OK\n"
        "===================================================================\n"
    )

    followed = streams._parse_follow_output(output, "tcp", 4, 64 * 1024)

    assert followed.node_a == "10.0.0.5:44000"
    assert followed.node_b == "93.184.216.34:80"
    assert [turn.sender for turn in followed.turns] == ["a", "b"]
    assert "GET /secret" in followed.turns[0].text
    assert "200 OK" in followed.turns[1].text


def test_following_a_stream_that_does_not_exist_says_so():
    with pytest.raises(streams.StreamError, match="stream list"):
        streams._parse_follow_output("", "tcp", 99, 1024)


def test_a_followed_stream_is_truncated_rather_than_returned_whole():
    body = "\n".join(f"line-{i}" for i in range(500))
    output = f"Node 0: a\nNode 1: b\n10\n{body}\n"

    followed = streams._parse_follow_output(output, "tcp", 0, 100)

    assert followed.truncated
    assert len(followed.turns[0].text) < 500


def test_an_unknown_stream_protocol_is_rejected():
    with pytest.raises(streams.StreamError):
        streams.follow_stream("x.pcap", protocol="sctp", index=0)


# --- Against real captures ----------------------------------------------


@requires_tshark
def test_a_flag_hidden_in_a_response_body_is_found(tmp_path):
    """The CTF case, and the thing the event pipeline structurally cannot
    do: the flag is payload, and parsing never stores payload."""
    path = _capture(tmp_path / "ctf.pcap")

    result = search.search_capture(path, "flag{")

    assert result.hits, "the flag was not found in the capture"
    hit = result.hits[0]
    assert FLAG in hit.excerpt
    assert hit.matched.lower() == "flag{"
    assert hit.frame_number > 0
    assert hit.stream is not None, "a hit must name the stream so it can be followed"


@requires_tshark
def test_a_regex_search_finds_the_whole_flag(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    result = search.search_capture(path, r"flag\{[^}]+\}", mode=search.REGEX)

    assert result.hits
    assert result.hits[0].matched == FLAG


@requires_tshark
def test_search_is_case_insensitive_by_default_and_exact_when_asked(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    assert search.search_capture(path, "FLAG{").hits
    assert not search.search_capture(path, "FLAG{", case_sensitive=True).hits


@requires_tshark
def test_a_hex_search_finds_bytes_that_are_not_printable(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    # "GET" as hex.
    result = search.search_capture(path, "47:45:54", mode=search.HEX)

    assert result.hits


@requires_tshark
def test_a_display_filter_narrows_the_search(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    assert search.search_capture(path, "flag{", display_filter="tcp").hits
    assert not search.search_capture(path, "flag{", display_filter="udp").hits


@requires_tshark
def test_search_stops_at_max_hits_and_says_it_did(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    result = search.search_capture(path, "HTTP", max_hits=1)

    assert len(result.hits) == 1
    assert result.truncated


@requires_tshark
def test_a_search_hit_leads_to_the_conversation_it_appeared_in(tmp_path):
    """Search reports a stream index and follow takes one - that handoff
    is the whole workflow, so it is worth pinning end to end."""
    path = _capture(tmp_path / "ctf.pcap")

    hit = search.search_capture(path, "flag{").hits[0]
    followed = streams.follow_stream(path, protocol="tcp", index=hit.stream)

    conversation = "\n".join(turn.text for turn in followed.turns)
    assert "GET /secret" in conversation
    assert FLAG in conversation
    assert {turn.sender for turn in followed.turns} == {"a", "b"}, "expected both directions"


@requires_tshark
def test_streams_are_listed_largest_first(tmp_path):
    path = _capture(tmp_path / "ctf.pcap")

    found = streams.list_streams(path, protocol="tcp")

    assert found
    assert found[0].packets >= 1
    assert found[0].endpoint_a and found[0].endpoint_b
    assert [s.bytes for s in found] == sorted((s.bytes for s in found), reverse=True)


# --- CLI ----------------------------------------------------------------


@requires_tshark
def test_cli_search_reports_the_flag_and_where_to_look(ctf_case):
    cases_dir, case, _evidence = ctf_case

    result = runner.invoke(
        cli_app, ["search", "--case", case.case_id, "flag{", "--cases-dir", str(cases_dir)]
    )

    assert result.exit_code == 0, result.output
    assert FLAG in result.output
    assert "frame " in result.output


@requires_tshark
def test_cli_search_with_no_match_says_so_rather_than_printing_nothing(ctf_case):
    cases_dir, case, _evidence = ctf_case

    result = runner.invoke(
        cli_app,
        ["search", "--case", case.case_id, "nothing-matches-this", "--cases-dir", str(cases_dir)],
    )

    assert result.exit_code == 0, result.output
    assert "No match" in result.output


@requires_tshark
def test_cli_stream_list_and_follow(ctf_case):
    cases_dir, case, _evidence = ctf_case

    listed = runner.invoke(
        cli_app, ["stream", "list", "--case", case.case_id, "--cases-dir", str(cases_dir)]
    )
    assert listed.exit_code == 0, listed.output
    assert "STREAM" in listed.output

    followed = runner.invoke(
        cli_app, ["stream", "follow", "--case", case.case_id, "0", "--cases-dir", str(cases_dir)]
    )
    assert followed.exit_code == 0, followed.output
    assert FLAG in followed.output


def test_cli_option_defaults_match_the_modules_they_mirror():
    """cli.py duplicates two defaults as literals so that `--help` does not
    import the search stack. Duplication drifts unless something checks."""
    import netforensicai.cli as cli

    assert cli.SEARCH_DEFAULT_MAX_HITS == search.DEFAULT_MAX_HITS
    assert cli.STREAM_DEFAULT_MAX_BYTES == streams.DEFAULT_MAX_BYTES
