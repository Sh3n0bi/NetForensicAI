"""Tests for the Wireshark integration: tool discovery, display filters,
the tshark dissection engine, the dumpcap capture backend, and the CLI and
web surfaces over them.

Everything that actually shells out to Wireshark is behind
`requires_tshark`, so the suite still passes end to end on a machine that
does not have it installed - which is the whole premise of the
integration being optional. The parts that are pure logic (engine
resolution, filter construction, rotation-file selection) are tested
unconditionally, because those are what decide whether Wireshark gets
used at all and must be correct even where it is absent.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap
from typer.testing import CliRunner

from netforensicai.cli import app as cli_app
from netforensicai.core import capture as capture_module
from netforensicai.core.case import CaseManager
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.event import Event
from netforensicai.integrations import wireshark
from netforensicai.parsers import pcap_engine
from netforensicai.web.app import create_app

runner = CliRunner()

requires_tshark = pytest.mark.skipif(
    not wireshark.available(), reason="Wireshark/tshark is not installed on this machine"
)


@pytest.fixture(autouse=True)
def _unpin_engine(monkeypatch):
    """conftest pins every test to the scapy backends. These tests are
    about the Wireshark ones, so they clear the pin and select explicitly."""
    monkeypatch.delenv(pcap_engine.ENGINE_ENV, raising=False)
    monkeypatch.delenv(capture_module.CAPTURE_ENGINE_ENV, raising=False)


def _event(**fields):
    base = {"event_id": "EVT-EV-0001-000001", "evidence_id": "EV-0001", "source": "pcap", "event_type": "network_connection"}
    return Event(**{**base, **fields})


def _sample_pcap(path):
    """A capture with a DNS query, a DNS response and a complete HTTP
    request/response exchange over a real TCP handshake.

    The handshake matters: tshark only dissects an HTTP response as HTTP
    when it can follow the stream, so a bare payload packet - which is
    enough for the scapy engine's byte matching - would silently produce
    no http_response event here.
    """
    client, server = "10.0.0.5", "93.184.216.34"

    def tcp(src, dst, sport, dport, flags, seq, ack, payload=b"", offset=0.0):
        packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        if payload:
            packet = packet / Raw(load=payload)
        packet.time = 1_700_000_000.0 + offset
        return packet

    query = Ether() / IP(src=client, dst="8.8.8.8") / UDP(sport=51000, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="evil.example.com")
    )
    query.time = 1_700_000_000.0
    response = Ether() / IP(src="8.8.8.8", dst=client) / UDP(sport=53, dport=51000) / DNS(
        qr=1, qd=DNSQR(qname="evil.example.com"), an=DNS().an
    )
    response.time = 1_700_000_000.1

    request_bytes = b"GET /malware.exe HTTP/1.1\r\nHost: evil.example.com\r\nUser-Agent: curl/8.0\r\n\r\n"
    body = b"MZ\x90\x00" + b"A" * 40
    response_bytes = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Length: %d\r\n\r\n" % len(body)
    ) + body

    packets = [
        query,
        response,
        tcp(client, server, 44000, 80, "S", 1000, 0, offset=0.2),
        tcp(server, client, 80, 44000, "SA", 5000, 1001, offset=0.3),
        tcp(client, server, 44000, 80, "A", 1001, 5001, offset=0.4),
        tcp(client, server, 44000, 80, "PA", 1001, 5001, request_bytes, offset=0.5),
        tcp(server, client, 80, 44000, "PA", 5001, 1001 + len(request_bytes), response_bytes, offset=0.6),
    ]
    wrpcap(str(path), packets)
    return path


# --- Discovery -----------------------------------------------------------


def test_status_reports_a_consistent_shape_whether_or_not_wireshark_is_installed():
    info = wireshark.status()

    assert set(info) == {"available", "version", "tshark", "dumpcap", "gui"}
    # A caller must be able to trust `available` alone; it has to agree
    # with the tshark path rather than being a separate probe that could
    # disagree with it.
    assert info["available"] is (info["tshark"] is not None)


def test_an_env_override_pointing_at_a_real_file_wins_over_path(tmp_path, monkeypatch):
    fake = tmp_path / "tshark-portable"
    fake.write_text("not really tshark", encoding="utf-8")
    monkeypatch.setenv("NETFORENSIC_TSHARK", str(fake))
    wireshark.reset_cache()

    try:
        assert wireshark.tshark_path() == str(fake)
    finally:
        wireshark.reset_cache()


def test_an_env_override_pointing_at_a_missing_file_is_ignored(monkeypatch):
    """A stale override in a shell profile must not disable an otherwise
    working installation."""
    monkeypatch.setenv("NETFORENSIC_TSHARK", "/definitely/not/here/tshark")
    wireshark.reset_cache()

    try:
        assert wireshark.tshark_path() != "/definitely/not/here/tshark"
    finally:
        wireshark.reset_cache()


# --- Display filters -----------------------------------------------------


@requires_tshark
def test_a_valid_display_filter_is_accepted():
    assert wireshark.validate_display_filter("ip.addr == 10.0.0.5 && tcp.port == 443") == (True, None)


@requires_tshark
def test_an_invalid_display_filter_is_rejected_with_tsharks_own_message():
    valid, error = wireshark.validate_display_filter("ip.addr ===")

    assert valid is False
    assert error
    # tshark's own diagnostic, not a generic one - it names what is wrong
    # with the expression, which is the only useful thing to show back.
    assert "tshark:" not in error


@requires_tshark
def test_an_unknown_protocol_field_is_rejected():
    valid, error = wireshark.validate_display_filter("not.a.real.field == 1")

    assert valid is False
    assert error


def test_an_empty_display_filter_is_rejected_without_running_tshark():
    assert wireshark.validate_display_filter("   ")[0] is False


def test_filter_for_event_prefers_the_exact_frame_number():
    event = _event(src_ip="10.0.0.5", dst_ip="8.8.8.8", raw_event_reference={"packet_number": 42})

    assert wireshark.filter_for_event(event) == "frame.number == 42"


def test_filter_for_event_collapses_many_frames_into_a_single_set_term():
    event = _event(raw_event_reference={"packet_numbers": [7, 3, 3, 5]})

    # One `in {..}` term rather than a chain of ORs: a carved-file event
    # can reference hundreds of frames.
    assert wireshark.filter_for_event(event) == "frame.number in {3, 5, 7}"


def test_filter_for_event_falls_back_to_the_flow_tuple():
    event = _event(src_ip="10.0.0.5", dst_ip="8.8.8.8", src_port=51000, dst_port=53, protocol="udp")

    assert wireshark.filter_for_event(event) == (
        "ip.addr == 10.0.0.5 && ip.addr == 8.8.8.8 && udp.port == 51000 && udp.port == 53"
    )


def test_filter_for_event_uses_the_ipv6_address_field_for_ipv6_flows():
    """ip.addr never matches an IPv6 packet, so a v6 flow filtered with it
    would come back empty and read as 'the evidence isn't there'."""
    event = _event(src_ip="2001:db8::1", dst_ip="2001:db8::2", protocol="tcp", src_port=443, dst_port=51000)

    built = wireshark.filter_for_event(event)

    assert "ipv6.addr == 2001:db8::1" in built
    assert "ip.addr ==" not in built


def test_filter_for_event_falls_back_to_the_domain_when_there_is_no_flow():
    event = _event(event_type="dns_query", domain="evil.example.com")

    built = wireshark.filter_for_event(event)

    assert 'dns.qry.name == "evil.example.com"' in built
    assert "tls.handshake.extensions_server_name" in built


def test_filter_for_event_returns_none_when_there_is_nothing_to_pivot_on():
    assert wireshark.filter_for_event(_event(event_type="process_start", process_name="cmd.exe")) is None


@requires_tshark
def test_every_filter_built_from_an_event_is_one_tshark_accepts():
    """The pivot is worthless if the filter it produces does not parse, and
    quoting or address-family bugs are exactly the kind that only show up
    when Wireshark sees the string."""
    events = [
        _event(raw_event_reference={"packet_number": 42}),
        _event(raw_event_reference={"packet_numbers": [3, 5, 7]}),
        _event(src_ip="10.0.0.5", dst_ip="8.8.8.8", src_port=51000, dst_port=53, protocol="udp"),
        _event(src_ip="2001:db8::1", dst_ip="2001:db8::2", protocol="tcp", src_port=443, dst_port=51000),
        _event(event_type="dns_query", domain="evil.example.com"),
        _event(event_type="http_request", url="http://evil.example.com/a?b=c&d=e"),
    ]

    for event in events:
        built = wireshark.filter_for_event(event)
        assert built, event
        assert wireshark.validate_display_filter(built) == (True, None), built


# --- Slice extraction ----------------------------------------------------


@requires_tshark
def test_extract_slice_keeps_only_the_matching_packets(tmp_path):
    source = _sample_pcap(tmp_path / "source.pcap")

    slice_path, packet_count = wireshark.extract_slice(source, "dns", tmp_path / "out" / "dns.pcap")

    assert slice_path.exists()
    assert packet_count == 2
    assert wireshark.count_packets(slice_path) == 2


@requires_tshark
def test_extract_slice_produces_an_empty_capture_rather_than_failing(tmp_path):
    """A filter that matches nothing is a valid answer, and callers
    distinguish it by the count - not by catching an exception."""
    source = _sample_pcap(tmp_path / "source.pcap")

    _slice_path, packet_count = wireshark.extract_slice(
        source, "ip.addr == 198.51.100.99", tmp_path / "empty.pcap"
    )

    assert packet_count == 0


@requires_tshark
def test_extract_slice_refuses_an_invalid_filter_before_writing_anything(tmp_path):
    source = _sample_pcap(tmp_path / "source.pcap")
    destination = tmp_path / "never.pcap"

    with pytest.raises(wireshark.WiresharkError):
        wireshark.extract_slice(source, "ip.addr ===", destination)

    assert not destination.exists()


# --- Engine resolution ---------------------------------------------------


def test_the_scapy_engine_can_always_be_requested():
    assert pcap_engine.resolve_engine("scapy") == pcap_engine.ENGINE_SCAPY


def test_requesting_tshark_when_it_is_missing_is_an_error_not_a_silent_fallback():
    """An analyst who passed --engine tshark is asking for a reproducible
    dissection; quietly giving them scapy's would put results in a report
    that the command printed beside them cannot reproduce."""
    with patch.object(wireshark, "available", return_value=False):
        with pytest.raises(pcap_engine.EngineUnavailableError):
            pcap_engine.resolve_engine("tshark")


def test_auto_falls_back_to_scapy_when_tshark_is_missing():
    with patch.object(wireshark, "available", return_value=False):
        assert pcap_engine.resolve_engine("auto") == pcap_engine.ENGINE_SCAPY


def test_auto_prefers_tshark_when_it_is_present():
    with patch.object(wireshark, "available", return_value=True):
        assert pcap_engine.resolve_engine("auto") == pcap_engine.ENGINE_TSHARK


def test_an_unknown_engine_name_is_rejected():
    with pytest.raises(pcap_engine.EngineUnavailableError):
        pcap_engine.resolve_engine("pyshark")


def test_the_environment_overrides_the_saved_setting(monkeypatch):
    monkeypatch.setenv(pcap_engine.ENGINE_ENV, "scapy")

    assert pcap_engine.configured_engine() == pcap_engine.ENGINE_SCAPY


def test_a_display_filter_with_the_scapy_engine_is_an_error_not_a_no_op(tmp_path):
    """Silently ignoring the filter would hand back every packet in the
    capture while the analyst believed they were looking at a subset."""
    source = _sample_pcap(tmp_path / "source.pcap")

    with pytest.raises(pcap_engine.EngineUnavailableError):
        list(
            pcap_engine.PcapEngineParser().iter_parse(
                source, "EV-0001", engine="scapy", display_filter="dns"
            )
        )


# --- The tshark dissection engine ---------------------------------------


@requires_tshark
def test_the_tshark_engine_produces_dns_http_and_flow_events(tmp_path):
    source = _sample_pcap(tmp_path / "source.pcap")

    events = pcap_engine.PcapEngineParser().parse(source, "EV-0001", engine="tshark")
    by_type = {}
    for event in events:
        by_type.setdefault(event.event_type, []).append(event)

    assert any(e.domain == "evil.example.com" for e in by_type["dns_query"])
    request = next(e for e in by_type["http_request"])
    assert request.url == "http://evil.example.com/malware.exe"
    assert request.domain == "evil.example.com"
    # The status code paired back to the URL that was requested - the
    # difference between "40,000 paths were requested" and "which existed".
    assert by_type["http_response"][0].url == "http://evil.example.com/malware.exe"
    assert by_type["network_connection"]


@requires_tshark
def test_tshark_events_record_which_engine_produced_them(tmp_path):
    """A report has to be able to say which dissector produced a finding,
    months later, on a machine that may no longer have the same tooling."""
    source = _sample_pcap(tmp_path / "source.pcap")

    events = pcap_engine.PcapEngineParser().parse(source, "EV-0001", engine="tshark")

    assert all((e.raw_event_reference or {}).get("engine") == "tshark" for e in events)


@requires_tshark
def test_every_tshark_event_carries_a_frame_reference_that_pivots_back(tmp_path):
    source = _sample_pcap(tmp_path / "source.pcap")

    events = pcap_engine.PcapEngineParser().parse(source, "EV-0001", engine="tshark")

    per_packet = [e for e in events if e.event_type in ("dns_query", "http_request", "http_response")]
    assert per_packet
    for event in per_packet:
        assert wireshark.filter_for_event(event).startswith("frame.number")


@requires_tshark
def test_object_export_recovers_the_transferred_file(tmp_path):
    """The capability the scapy engine cannot match: a real HTTP object
    with its true boundaries, rather than a magic-byte carve."""
    source = _sample_pcap(tmp_path / "source.pcap")
    output_dir = tmp_path / "artifacts"

    events = pcap_engine.PcapEngineParser().parse(
        source, "EV-0001", output_dir=str(output_dir), engine="tshark"
    )

    transfers = [e for e in events if e.event_type == "file_transfer"]
    assert transfers, "expected the HTTP body to be exported as a file"
    transfer = transfers[0]
    assert transfer.file_name == "malware.exe"
    assert Path(transfer.file_path).read_bytes().startswith(b"MZ")
    assert transfer.file_hash


@requires_tshark
def test_a_display_filter_narrows_what_the_tshark_engine_parses(tmp_path):
    source = _sample_pcap(tmp_path / "source.pcap")

    events = pcap_engine.PcapEngineParser().parse(
        source, "EV-0001", engine="tshark", display_filter="dns"
    )

    assert events
    assert not [e for e in events if e.event_type in ("http_request", "http_response")]


@requires_tshark
def test_pcap_support_survives_scapy_pandas_and_sklearn_all_being_absent(tmp_path):
    """The central claim of the optional-dependency design: on a machine
    with Wireshark but without the [pcap] extra, pcap evidence must still
    register a parser and produce events. If registration went through
    parsers.pcap - which imports scapy at module scope - this would fail.
    """
    import builtins

    source = _sample_pcap(tmp_path / "source.pcap")
    blocked = ("scapy", "pandas", "sklearn")
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.split(".")[0] in blocked:
            raise ImportError(f"simulated missing dependency: {name}")
        return real_import(name, *args, **kwargs)

    from netforensicai.parsers import base, load_parsers

    with patch.object(builtins, "__import__", guarded_import):
        load_parsers()
        parser = base.get_parser("pcap")
        events = parser.parse(source, "EV-0001", engine="tshark")

    types = {e.event_type for e in events}
    assert "http_request" in types
    assert "network_connection" in types
    # The statistical pass needs pandas/scikit-learn, so it is skipped
    # rather than taking the whole parse down with it.
    assert "anomaly" not in types


@requires_tshark
def test_a_missing_capture_file_raises_rather_than_yielding_nothing(tmp_path):
    from netforensicai.parsers.pcap_tshark import TsharkParseError

    with pytest.raises(TsharkParseError):
        list(
            pcap_engine.PcapEngineParser().iter_parse(
                tmp_path / "does-not-exist.pcap", "EV-0001", engine="tshark"
            )
        )


# --- The dumpcap capture backend ----------------------------------------


def test_requesting_dumpcap_when_it_is_missing_is_an_error():
    with patch.object(wireshark, "dumpcap_path", return_value=None):
        with pytest.raises(capture_module.CaptureError):
            capture_module.resolve_capture_engine("dumpcap")


def test_auto_capture_falls_back_to_scapy_without_dumpcap():
    with patch.object(wireshark, "dumpcap_path", return_value=None):
        assert capture_module.resolve_capture_engine("auto") == capture_module.ENGINE_SCAPY


def test_a_running_dumpcap_session_holds_back_the_file_still_being_written(tmp_path):
    """dumpcap is always mid-write on its newest rotation file. Ingesting
    that one would put a truncated capture into the case as though it were
    a complete window."""
    session = capture_module.DumpcapCaptureSession("INC-0001", tmp_path, case_manager=None)
    staging = session._staging_dir
    for name in ("window_00001_A.pcap", "window_00002_B.pcap", "window_00003_C.pcap"):
        (staging / name).write_bytes(b"")

    session._running = True
    assert [p.name for p in session._rotation_files()] == ["window_00001_A.pcap", "window_00002_B.pcap"]

    # Once dumpcap has exited, the last file is complete too.
    session._running = False
    assert len(session._rotation_files()) == 3


def test_the_dumpcap_backend_reports_itself_in_the_status_snapshot(tmp_path):
    session = capture_module.DumpcapCaptureSession("INC-0001", tmp_path, case_manager=None)

    assert session.snapshot()["engine"] == capture_module.ENGINE_DUMPCAP
    assert capture_module.CaptureSession("INC-0001", tmp_path, case_manager=None).snapshot()["engine"] == "scapy"


def test_dumpcap_progress_output_feeds_the_live_packet_counter():
    assert capture_module._DUMPCAP_PROGRESS.search("Packets captured: 1234").group(1) == "1234"
    assert capture_module._DUMPCAP_PROGRESS.search("Packets: 7").group(1) == "7"


def test_list_interfaces_always_returns_name_description_pairs():
    """The web UI and the CLI both render these; a bare string from one
    backend and a dict from the other would break one of them."""
    interfaces = capture_module.list_interfaces()

    assert isinstance(interfaces, list)
    for interface in interfaces:
        assert set(interface) == {"name", "description"}
        assert isinstance(interface["name"], str)


# --- CLI -----------------------------------------------------------------


@requires_tshark
def test_cli_wireshark_status_reports_the_selected_engines():
    result = runner.invoke(cli_app, ["wireshark", "status"])

    assert result.exit_code == 0, result.output
    assert "tshark:" in result.output
    assert "Parse engine:" in result.output


@requires_tshark
def test_cli_check_filter_accepts_and_rejects():
    good = runner.invoke(cli_app, ["wireshark", "check-filter", "tcp.port == 445"])
    bad = runner.invoke(cli_app, ["wireshark", "check-filter", "tcp.port =="])

    assert good.exit_code == 0, good.output
    assert bad.exit_code == 1
    assert "Invalid" in bad.output


@pytest.fixture
def pcap_case(tmp_path):
    """A case with one real capture added as evidence."""
    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Wireshark test case", investigator="alice")
    case_dir = cases_dir / case.case_id

    source = _sample_pcap(tmp_path / "capture.pcap")
    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)
    case_manager.register_evidence(case.case_id, evidence.evidence_id)
    return cases_dir, case, evidence


@requires_tshark
def test_cli_open_prints_the_command_instead_of_launching_the_gui(pcap_case):
    cases_dir, case, evidence = pcap_case

    result = runner.invoke(
        cli_app,
        ["wireshark", "open", "--case", case.case_id, "--evidence", evidence.evidence_id,
         "--display-filter", "dns", "--print", "--cases-dir", str(cases_dir)],
    )

    assert result.exit_code == 0, result.output
    assert "-Y" in result.output and "dns" in result.output


@requires_tshark
def test_cli_open_refuses_non_capture_evidence(tmp_path):
    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Mixed evidence", investigator="alice")
    source = tmp_path / "events.json"
    source.write_text(json.dumps([{"timestamp": "2026-08-27T09:00:00Z", "type": "authentication"}]), encoding="utf-8")
    evidence = EvidenceManager(cases_dir / case.case_id).add(source, case_id=case.case_id)

    result = runner.invoke(
        cli_app,
        ["wireshark", "open", "--case", case.case_id, "--evidence", evidence.evidence_id,
         "--print", "--cases-dir", str(cases_dir)],
    )

    assert result.exit_code == 1
    assert "not a capture file" in result.output


@requires_tshark
def test_cli_slice_adds_the_carved_capture_back_as_traceable_evidence(pcap_case):
    from netforensicai.core import audit

    cases_dir, case, evidence = pcap_case

    result = runner.invoke(
        cli_app,
        ["wireshark", "slice", "--case", case.case_id, "--evidence", evidence.evidence_id,
         "--display-filter", "dns", "--cases-dir", str(cases_dir)],
    )

    assert result.exit_code == 0, result.output
    assert "Wrote 2 packet(s)" in result.output
    assert "EV-0002" in result.output

    # The derived capture has to name its parent and the exact filter, or
    # it cannot be reproduced from the original.
    entries = audit.read_entries(cases_dir / case.case_id)
    sliced = [e for e in entries if e["action"] == audit.EVIDENCE_SLICED]
    assert len(sliced) == 1
    assert sliced[0]["details"]["derived_from"] == evidence.evidence_id
    assert sliced[0]["details"]["display_filter"] == "dns"


@requires_tshark
def test_cli_slice_with_no_matches_adds_no_evidence(pcap_case):
    cases_dir, case, evidence = pcap_case

    result = runner.invoke(
        cli_app,
        ["wireshark", "slice", "--case", case.case_id, "--evidence", evidence.evidence_id,
         "--display-filter", "ip.addr == 198.51.100.99", "--cases-dir", str(cases_dir)],
    )

    assert result.exit_code == 0, result.output
    assert "No packets" in result.output
    assert len(EvidenceManager(cases_dir / case.case_id).list()) == 1


# --- Web API -------------------------------------------------------------


@pytest.fixture
def pcap_client(pcap_case):
    cases_dir, case, evidence = pcap_case
    client = create_app(cases_dir).test_client()
    client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"
    return client, case, evidence, cases_dir


def test_web_wireshark_status_is_available_even_without_wireshark(pcap_client):
    client, _case, _evidence, _cases_dir = pcap_client

    payload = client.get("/api/wireshark/status").get_json()

    assert "available" in payload
    assert "parse_engine" in payload


@requires_tshark
def test_web_check_filter_reports_validity(pcap_client):
    client, _case, _evidence, _cases_dir = pcap_client

    good = client.post("/api/wireshark/check-filter", json={"display_filter": "dns"}).get_json()
    bad = client.post("/api/wireshark/check-filter", json={"display_filter": "dns =="}).get_json()

    assert good == {"valid": True, "error": None}
    assert bad["valid"] is False and bad["error"]


@requires_tshark
def test_web_pivot_returns_a_filter_and_a_command_but_launches_nothing(pcap_client):
    """A browser page must not be able to spawn a desktop application on
    the machine running the server."""
    client, case, evidence, cases_dir = pcap_client

    analyze = client.post(f"/api/cases/{case.case_id}/analyze", json={"engine": "tshark"})
    assert analyze.status_code == 200, analyze.get_json()

    timeline = client.get(f"/api/cases/{case.case_id}/timeline").get_json()
    event_id = timeline[0]["event_id"]

    with patch.object(wireshark, "open_gui") as launched:
        payload = client.get(f"/api/cases/{case.case_id}/events/{event_id}/wireshark").get_json()

    launched.assert_not_called()
    assert payload["display_filter"]
    assert "-Y" in payload["command"]
    assert wireshark.validate_display_filter(payload["display_filter"]) == (True, None)


@requires_tshark
def test_web_slice_creates_a_new_hashed_evidence_item(pcap_client):
    client, case, evidence, cases_dir = pcap_client

    response = client.post(
        f"/api/cases/{case.case_id}/evidence/{evidence.evidence_id}/slice",
        json={"display_filter": "dns"},
    )

    assert response.status_code == 201, response.get_json()
    payload = response.get_json()
    assert payload["packet_count"] == 2

    items = EvidenceManager(cases_dir / case.case_id).list()
    assert len(items) == 2
    assert any(item.evidence_id == payload["evidence_id"] and item.sha256 for item in items)


@requires_tshark
def test_web_slice_with_no_matches_adds_nothing(pcap_client):
    client, case, evidence, cases_dir = pcap_client

    payload = client.post(
        f"/api/cases/{case.case_id}/evidence/{evidence.evidence_id}/slice",
        json={"display_filter": "ip.addr == 198.51.100.99"},
    ).get_json()

    assert payload["packet_count"] == 0
    assert payload["evidence_id"] is None
    assert len(EvidenceManager(cases_dir / case.case_id).list()) == 1


def test_web_slice_rejects_a_missing_display_filter(pcap_client):
    client, case, evidence, _cases_dir = pcap_client

    response = client.post(
        f"/api/cases/{case.case_id}/evidence/{evidence.evidence_id}/slice", json={}
    )

    assert response.status_code == 400
