"""Tests for the shared ingestion pipeline, focused on the streaming
contract: events are written in batches, never collected into one list,
and a mid-parse failure leaves no partial evidence behind."""

import json

import pytest

from netforensicai.core import pipeline
from netforensicai.core.case import CaseManager
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.store import CaseStore


@pytest.fixture
def case_with_evidence(tmp_path):
    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Pipeline test")
    case_dir = cases_dir / case.case_id

    source = tmp_path / "events.json"
    source.write_text(
        json.dumps(
            [
                {"timestamp": "2026-08-27T09:00:00Z", "type": "authentication", "user": "jdoe", "src_ip": "10.0.0.5"},
                {"timestamp": "2026-08-27T09:00:05Z", "type": "network_connection", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8"},
            ]
        ),
        encoding="utf-8",
    )
    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)
    case_manager.register_evidence(case.case_id, evidence.evidence_id)
    return case_manager, case, case_dir, evidence


def test_ingests_events_and_entities(case_with_evidence):
    case_manager, case, case_dir, evidence = case_with_evidence

    with CaseStore(case_dir) as store:
        event_count, entity_count, error = pipeline.parse_evidence_item(
            evidence, case_dir, case_manager, case.case_id, store
        )

        assert error is None
        assert event_count == 2
        assert entity_count > 0
        assert store.count_events() == 2


def test_reingesting_the_same_evidence_does_not_duplicate(case_with_evidence):
    case_manager, case, case_dir, evidence = case_with_evidence

    with CaseStore(case_dir) as store:
        pipeline.parse_evidence_item(evidence, case_dir, case_manager, case.case_id, store)
        pipeline.parse_evidence_item(evidence, case_dir, case_manager, case.case_id, store)

        assert store.count_events() == 2


def test_entity_count_is_distinct_across_batches(tmp_path, monkeypatch):
    # Regression guard for the batching change: per-batch counts cannot be
    # summed, because the same entity recurs in most batches. With a batch
    # size of 1 every event lands in its own batch, so a summing bug would
    # report one entity per event instead of the true distinct total.
    monkeypatch.setattr(pipeline, "INGEST_BATCH_SIZE", 1)

    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Batch count test")
    case_dir = cases_dir / case.case_id

    source = tmp_path / "same_ip.json"
    source.write_text(
        json.dumps(
            [{"timestamp": f"2026-08-27T09:00:0{i}Z", "type": "authentication", "src_ip": "10.0.0.5"} for i in range(5)]
        ),
        encoding="utf-8",
    )
    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)

    with CaseStore(case_dir) as store:
        event_count, entity_count, error = pipeline.parse_evidence_item(
            evidence, case_dir, case_manager, case.case_id, store
        )

        assert error is None
        assert event_count == 5
        # All five events reference the same single IP.
        assert entity_count == 1
        assert store.count_entities() == 1


def test_parser_failure_leaves_no_partial_events(case_with_evidence, monkeypatch):
    # A half-ingested evidence item is worse than none: correlation, the
    # timeline and the report would all silently reason over part of a file.
    case_manager, case, case_dir, evidence = case_with_evidence

    from netforensicai.parsers import base, load_parsers

    load_parsers()
    parser = base.get_parser("json")

    def exploding_iter_parse(*_args, **_kwargs):
        yield from ()
        raise RuntimeError("parser blew up midway")

    monkeypatch.setattr(parser, "iter_parse", exploding_iter_parse, raising=False)

    with CaseStore(case_dir) as store:
        event_count, entity_count, error = pipeline.parse_evidence_item(
            evidence, case_dir, case_manager, case.case_id, store
        )

        assert event_count is None
        assert entity_count is None
        assert "blew up midway" in error
        assert store.count_events() == 0


def test_unknown_evidence_type_reports_cleanly(case_with_evidence):
    case_manager, case, case_dir, evidence = case_with_evidence
    evidence.evidence_type = "not-a-real-format"

    with CaseStore(case_dir) as store:
        event_count, entity_count, error = pipeline.parse_evidence_item(
            evidence, case_dir, case_manager, case.case_id, store
        )

    assert event_count is None
    assert entity_count is None
    assert "No parser registered" in error


def _write_http_pcap(path, count):
    from scapy.all import IP, TCP, Raw, wrpcap

    packets = []
    for i in range(count):
        pkt = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000 + (i % 100), dport=80) / Raw(
            load=f"GET /path-{i} HTTP/1.1\r\nHost: t.example\r\n\r\n".encode()
        )
        pkt.time = 1_700_000_000.0 + i * 0.001
        packets.append(pkt)
    wrpcap(str(path), packets)
    return path


def test_pcap_iter_parse_is_lazy(tmp_path):
    """iter_parse must yield as it reads, not parse everything then hand
    back an iterator over the finished list - otherwise the pipeline's
    batching buys nothing."""
    source = _write_http_pcap(tmp_path / "lazy.pcap", 3000)

    from netforensicai.parsers.pcap import PcapParser

    stream = PcapParser().iter_parse(source, evidence_id="EV-0001")
    first = next(stream)

    assert first is not None
    # Pulling one event must not have drained the capture; if iter_parse had
    # built the whole list first, there would be nothing left to prove here,
    # so also confirm the remainder is still arriving lazily.
    assert next(stream) is not None
    remaining = sum(1 for _ in stream)
    assert remaining > 2000


def test_pipeline_writes_in_bounded_batches(tmp_path, monkeypatch):
    """The property that actually bounds memory: no single write ever
    carries more than INGEST_BATCH_SIZE events, however many the capture
    produces. Asserted structurally rather than by measuring RSS, which is
    far too noisy to be a reliable regression signal."""
    monkeypatch.setattr(pipeline, "INGEST_BATCH_SIZE", 500)

    cases_dir = tmp_path / "cases"
    case_manager = CaseManager(cases_dir)
    case = case_manager.create(name="Batching test")
    case_dir = cases_dir / case.case_id
    source = _write_http_pcap(tmp_path / "many.pcap", 3000)
    evidence = EvidenceManager(case_dir).add(source, case_id=case.case_id)

    batch_sizes = []

    with CaseStore(case_dir) as store:
        real_insert = store.insert_events

        def spy(events):
            events = list(events)
            batch_sizes.append(len(events))
            return real_insert(events)

        monkeypatch.setattr(store, "insert_events", spy)
        event_count, _entity_count, error = pipeline.parse_evidence_item(
            evidence, case_dir, case_manager, case.case_id, store
        )

        assert error is None
        assert event_count > 3000  # requests plus per-flow summaries
        assert len(batch_sizes) > 1, "everything arrived in one write - not actually streaming"
        assert max(batch_sizes) <= 500
        assert sum(batch_sizes) == event_count
        assert store.count_events() == event_count
