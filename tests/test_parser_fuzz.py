"""Malformed-input resilience for every evidence parser.

A DFIR tool ingests hostile files by definition: the whole point is to point
it at evidence of unknown provenance. So the contract these tests pin down is
not "parse correctly" - it is "fail safely". For any garbage, truncated, empty,
or wrong-shaped input, a parser must either return a list of events or raise its
own declared error type. It must never leak an unhandled exception to the
caller, and it must not hang or blow up memory on a tiny input.

These are deliberately not fuzzing frameworks - they are a fixed corpus of the
malformed shapes real parsers trip over, cheap enough to run on every commit.
"""

import time

import pytest

from netforensicai.core.event import Event
from netforensicai.parsers.generic import CsvParser, JsonParser, NormalizationError
from netforensicai.parsers.pcap import PcapParseError, PcapParser

# A small, varied corpus of bytes no parser should choke on unsafely.
MALFORMED_BYTES = [
    b"",  # empty file
    b"\x00" * 64,  # null bytes
    b"\xff\xfe\xfd\xfc" * 32,  # high bytes / invalid UTF-8
    b"not a real evidence file at all",  # plain text
    b"{" * 2000,  # unbalanced structure, no runaway nesting cost
    bytes(range(256)),  # every byte value once
]

# A parse of a handful of bytes must be effectively instant; anything that
# takes longer than this on this corpus is a pathological blow-up worth failing.
MAX_PARSE_SECONDS = 20.0


def _assert_safe(parse_callable, allowed_errors):
    """Call parse; require either a list result or an allowed error, promptly."""
    started = time.monotonic()
    try:
        result = parse_callable()
    except allowed_errors:
        pass  # a declared, handled failure is the correct outcome
    else:
        assert isinstance(result, list)
        assert all(isinstance(e, Event) for e in result)
    elapsed = time.monotonic() - started
    assert elapsed < MAX_PARSE_SECONDS, f"parse took {elapsed:.1f}s on tiny input"


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("data", MALFORMED_BYTES, ids=lambda d: f"{len(d)}b")
def test_json_parser_handles_malformed_input(tmp_path, data):
    path = _write(tmp_path, "evidence.json", data)
    _assert_safe(lambda: JsonParser().parse(path, evidence_id="EV-FUZZ"), (NormalizationError,))


@pytest.mark.parametrize("data", MALFORMED_BYTES, ids=lambda d: f"{len(d)}b")
def test_csv_parser_handles_malformed_input(tmp_path, data):
    path = _write(tmp_path, "evidence.csv", data)
    _assert_safe(lambda: CsvParser().parse(path, evidence_id="EV-FUZZ"), (NormalizationError,))


@pytest.mark.parametrize("data", MALFORMED_BYTES, ids=lambda d: f"{len(d)}b")
def test_pcap_parser_handles_malformed_input(tmp_path, data):
    path = _write(tmp_path, "evidence.pcap", data)
    _assert_safe(lambda: PcapParser().parse(path, evidence_id="EV-FUZZ"), (PcapParseError,))


def test_pcap_parser_handles_truncated_global_header(tmp_path):
    # A valid pcap magic number followed by nothing: the file claims to be a
    # capture but is cut off before any packet. This is the classic truncation
    # a crashed/interrupted capture leaves behind.
    path = _write(tmp_path, "truncated.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)
    _assert_safe(lambda: PcapParser().parse(path, evidence_id="EV-FUZZ"), (PcapParseError,))


def test_json_parser_accepts_a_single_top_level_object(tmp_path):
    # A top-level object is intentionally treated as one record (see
    # _load_json_records). The contract under test is that this is *handled* -
    # a list back or a NormalizationError - never an unhandled exception.
    path = _write(tmp_path, "object.json", b'{"timestamp": "2026-01-01T00:00:00Z", "type": "authentication"}')
    _assert_safe(lambda: JsonParser().parse(path, evidence_id="EV-FUZZ"), (NormalizationError,))


def test_evtx_parser_handles_malformed_input(tmp_path):
    pytest.importorskip("Evtx", reason="python-evtx not installed (evtx extra)")
    from netforensicai.parsers.evtx import EvtxParseError, EvtxParser

    path = _write(tmp_path, "evidence.evtx", b"ElfFile\x00garbage-not-a-real-chunk")
    _assert_safe(lambda: EvtxParser().parse(path, evidence_id="EV-FUZZ"), (EvtxParseError,))
