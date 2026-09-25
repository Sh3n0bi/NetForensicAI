"""Structured fuzzing of the pcap and EVTX parsers.

test_parser_fuzz.py covers the "here is a pile of garbage" case. This goes
further, the way a real capture goes wrong: a *valid* file that has been
truncated, bit-flipped, or had its length fields lied about - and it runs
the pcap cases through BOTH dissection engines, because scapy and tshark
fail in different places and a robustness guarantee that only holds for one
of them is not a guarantee.

The contract under test is always the same: for any input, the parser
returns a list of events or raises its own declared error
(`base.PcapReadError`, which both engines' errors now share; or
`EvtxParseError`) - never an unhandled exception, an OOM, or a hang. The
fixed RNG seed keeps a failure reproducible from the printed case id.
"""

import random
import struct
import time

import pytest

from netforensicai.core.event import EventSequence
from netforensicai.integrations import wireshark
from netforensicai.parsers import base, pcap_engine
from netforensicai.parsers.pcap import PcapParser

# A tiny input must parse effectively instantly; anything slower than this is
# a pathological blow-up (an amplified length field, a decompression bomb) and
# is itself the failure, even without an exception.
MAX_PARSE_SECONDS = 25.0

TSHARK = wireshark.available()
tshark_only = pytest.mark.skipif(not TSHARK, reason="tshark not installed")

# Global pcap header is 24 bytes; each packet record header is 16:
# ts_sec, ts_usec, incl_len (caplen), orig_len.
PCAP_GLOBAL_HEADER = 24
PCAP_RECORD_HEADER = 16


def _valid_pcap_bytes(tmp_path):
    """A small but varied capture: DNS, a TCP payload, a UDP datagram - so a
    mutation has real structure to corrupt, not just one packet shape."""
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

    pkts = [
        IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(qd=DNSQR(qname="example.com")),
        IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=44100, dport=80) / Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        IP(src="93.184.216.34", dst="10.0.0.5") / TCP(sport=80, dport=44100) / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n<html>"),
    ]
    path = tmp_path / "seed.pcap"
    wrpcap(str(path), pkts)
    return path.read_bytes()


def _parse(engine, path, monkeypatch):
    """Parse `path` with the named engine; return (ok, seconds). `ok` means
    the call was handled - a list of events, or a declared PcapReadError."""
    monkeypatch.setenv(pcap_engine.ENGINE_ENV, engine)
    started = time.monotonic()
    try:
        if engine == "scapy":
            result = PcapParser().parse(path, evidence_id="EV-FUZZ")
        else:
            result = pcap_engine.PcapEngineParser().parse(path, evidence_id="EV-FUZZ")
        ok = isinstance(result, list)
    except base.PcapReadError:
        ok = True  # a declared, handled failure is a correct outcome
    return ok, time.monotonic() - started


ENGINES = ["scapy"] + (["tshark"] if TSHARK else [])


# --- pcap: mutation fuzzing --------------------------------------------------

@pytest.mark.parametrize("engine", ENGINES)
def test_pcap_bitflip_mutations_are_handled(engine, tmp_path, monkeypatch):
    seed = _valid_pcap_bytes(tmp_path)
    rng = random.Random(1337)
    # Fewer iterations for tshark: each spawns a subprocess (~0.2s).
    iterations = 60 if engine == "scapy" else 15
    for i in range(iterations):
        data = bytearray(seed)
        for _ in range(rng.randint(1, 12)):
            data[rng.randrange(len(data))] = rng.randint(0, 255)
        path = tmp_path / f"mut_{engine}_{i}.pcap"
        path.write_bytes(bytes(data))
        ok, secs = _parse(engine, path, monkeypatch)
        assert ok, f"unhandled on mutation {i} ({engine})"
        assert secs < MAX_PARSE_SECONDS, f"mutation {i} took {secs:.1f}s ({engine})"


# --- pcap: truncation sweep --------------------------------------------------

@pytest.mark.parametrize("engine", ENGINES)
def test_pcap_truncation_at_every_boundary_is_handled(engine, tmp_path, monkeypatch):
    seed = _valid_pcap_bytes(tmp_path)
    # Every byte for scapy (fast); a sampled subset for tshark (subprocess).
    step = 1 if engine == "scapy" else max(1, len(seed) // 12)
    for cut in range(0, len(seed), step):
        path = tmp_path / f"trunc_{engine}_{cut}.pcap"
        path.write_bytes(seed[:cut])
        ok, secs = _parse(engine, path, monkeypatch)
        assert ok, f"unhandled truncation at {cut} ({engine})"
        assert secs < MAX_PARSE_SECONDS


# --- pcap: crafted lying length fields --------------------------------------
# The classic pcap attack surface: header fields that claim far more data
# than the file contains, aimed at an over-read or a giant allocation.

def _crafted_cases(seed):
    cases = {}
    cases["bad_magic"] = b"\x00\x00\x00\x00" + seed[4:]
    for name, offset in [
        ("huge_caplen", PCAP_GLOBAL_HEADER + 8),
        ("huge_orig_len", PCAP_GLOBAL_HEADER + 12),
        ("huge_snaplen", 16),
    ]:
        b = bytearray(seed)
        struct.pack_into("<I", b, offset, 0xFFFFFFFF)
        cases[name] = bytes(b)
    # caplen claims 2GB but the record body is a few bytes.
    b = bytearray(seed[: PCAP_GLOBAL_HEADER + PCAP_RECORD_HEADER + 4])
    struct.pack_into("<I", b, PCAP_GLOBAL_HEADER + 8, 0x7FFFFFFF)
    cases["caplen_overrun"] = bytes(b)
    return cases


@pytest.mark.parametrize("engine", ENGINES)
def test_pcap_crafted_length_fields_are_handled(engine, tmp_path, monkeypatch):
    cases = _crafted_cases(_valid_pcap_bytes(tmp_path))
    for name, data in cases.items():
        path = tmp_path / f"crafted_{engine}_{name}.pcap"
        path.write_bytes(data)
        ok, secs = _parse(engine, path, monkeypatch)
        assert ok, f"unhandled crafted case {name!r} ({engine})"
        # A lied-about 2GB caplen must not trigger a 2GB read/allocation.
        assert secs < MAX_PARSE_SECONDS, f"{name} took {secs:.1f}s ({engine})"


def test_both_engines_share_one_error_type():
    # The consistency the shared base buys: a caller of either engine can
    # catch base.PcapReadError, not two unrelated types.
    from netforensicai.parsers.pcap import PcapParseError
    from netforensicai.parsers.pcap_tshark import TsharkParseError

    assert issubclass(PcapParseError, base.PcapReadError)
    assert issubclass(TsharkParseError, base.PcapReadError)


# --- EVTX: file layer --------------------------------------------------------

@pytest.mark.parametrize(
    "data",
    [b"", b"ElfFile\x00", b"ElfFile\x00" + b"\xff" * 512, b"\x00" * 256, bytes(range(256))],
    ids=["empty", "magic_only", "magic_garbage", "nulls", "allbytes"],
)
def test_evtx_malformed_file_is_handled(data, tmp_path):
    pytest.importorskip("Evtx", reason="python-evtx not installed (evtx extra)")
    from netforensicai.parsers.evtx import EvtxParseError, EvtxParser

    path = tmp_path / "evidence.evtx"
    path.write_bytes(data)
    started = time.monotonic()
    try:
        result = EvtxParser().parse(path, evidence_id="EV-FUZZ")
        assert isinstance(result, list)
    except EvtxParseError:
        pass
    assert time.monotonic() - started < MAX_PARSE_SECONDS


# --- EVTX: the XML->event layer (this module's own logic) --------------------
# The binary EVTX dissection is python-evtx's job; turning one record's XML
# into a normalized Event is NetForensicAI's. That is what is fuzzed here.

_VALID_EVENT_XML = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    "<System>"
    '<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>'
    "<EventID>3</EventID>"
    '<TimeCreated SystemTime="2026-08-27T09:00:00.1234567Z"></TimeCreated>'
    "<EventRecordID>12345</EventRecordID>"
    "<Computer>WORKSTATION01</Computer>"
    "</System>"
    "<EventData>"
    '<Data Name="SourceIp">10.0.0.5</Data>'
    '<Data Name="DestinationIp">93.184.216.34</Data>'
    '<Data Name="DestinationPort">443</Data>'
    "</EventData>"
    "</Event>"
)


def test_evtx_record_xml_mutations_are_handled():
    from netforensicai.parsers.evtx import record_to_event

    base_xml = _VALID_EVENT_XML.encode()
    rng = random.Random(2024)
    for i in range(120):
        data = bytearray(base_xml)
        # Mix of byte flips and blunt truncation - both produce the malformed
        # or well-formed-but-wrong-shape XML a corrupt record really yields.
        if rng.random() < 0.5:
            data = data[: rng.randrange(len(data) + 1)]
        else:
            for _ in range(rng.randint(1, 8)):
                if data:
                    data[rng.randrange(len(data))] = rng.randint(0, 255)
        text = bytes(data).decode("utf-8", errors="replace")
        # Must return an Event or None, or raise nothing unhandled. A crash
        # here (AttributeError, ValueError deep in field parsing) is the bug.
        try:
            result = record_to_event(text, evidence_id="EV-FUZZ", sequence=EventSequence())
        except Exception as e:
            pytest.fail(f"record_to_event raised {type(e).__name__} on mutation {i}: {e}")
        assert result is None or hasattr(result, "event_id")
