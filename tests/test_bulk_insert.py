"""Tests for the bulk-insert fast path.

The DataFrame path is a 15x difference on the row counts pcap ingestion
produces, and nothing about it is visible in behaviour - which is exactly
why it needs pinning. A silent regression to chunked VALUES would look
like nothing at all until somebody ingested a real capture.
"""

from unittest.mock import patch

import pytest

from netforensicai.core import store as store_module
from netforensicai.core.store import CaseStore


def _links(n, offset=0):
    return [
        (f"ENT-ip-{i % 97:04d}", f"EVT-EV-0001-{i + offset:06d}", ["src_ip", "dst_ip"][i % 2])
        for i in range(n)
    ]


@pytest.fixture
def store(tmp_path):
    with CaseStore(tmp_path) as s:
        yield s


def _stored(store):
    return store.conn.execute("SELECT count(*) FROM entity_events").fetchone()[0]


def test_a_large_batch_takes_the_dataframe_path(store):
    with patch.object(store_module, "_insert_via_dataframe", wraps=store_module._insert_via_dataframe) as spy:
        store.link_entity_events(_links(store_module.BULK_INSERT_DATAFRAME_MIN_ROWS))

    assert spy.called, "a batch at the threshold should use the DataFrame path"
    assert _stored(store) == store_module.BULK_INSERT_DATAFRAME_MIN_ROWS


def test_a_small_batch_stays_on_the_values_path(store):
    """Below the threshold the DataFrame round trip costs more than the
    binding it saves."""
    with patch.object(store_module, "_insert_via_dataframe") as spy:
        store.link_entity_events(_links(10))

    spy.assert_not_called()
    assert _stored(store) == 10


def test_the_values_path_is_used_when_pandas_is_missing(store, monkeypatch):
    """Core installs have no pandas. The rows must still land."""
    import builtins

    real_import = builtins.__import__

    def no_pandas(name, *args, **kwargs):
        if name == "pandas":
            raise ImportError("simulated: pandas not installed")
        return real_import(name, *args, **kwargs)

    rows = _links(store_module.BULK_INSERT_DATAFRAME_MIN_ROWS + 50)
    with patch.object(builtins, "__import__", no_pandas):
        store.link_entity_events(rows)

    assert _stored(store) == len(rows)


def test_both_paths_store_identical_rows(tmp_path):
    """The fast path must not change what ends up in the table."""
    rows = _links(store_module.BULK_INSERT_DATAFRAME_MIN_ROWS + 7)
    (tmp_path / "fast").mkdir()
    (tmp_path / "slow").mkdir()

    with CaseStore(tmp_path / "fast") as fast:
        fast.link_entity_events(rows)
        via_frame = sorted(fast.conn.execute("SELECT * FROM entity_events").fetchall())

    with CaseStore(tmp_path / "slow") as slow:
        with patch.object(store_module, "_insert_via_dataframe", return_value=False):
            slow.link_entity_events(rows)
        via_values = sorted(slow.conn.execute("SELECT * FROM entity_events").fetchall())

    assert via_frame == via_values
    assert len(via_frame) == len(rows)


def test_the_fast_path_still_honours_the_conflict_clause(store):
    """Re-inserting overlapping rows must not duplicate or raise."""
    rows = _links(store_module.BULK_INSERT_DATAFRAME_MIN_ROWS + 100)
    store.link_entity_events(rows)
    store.link_entity_events(rows)

    assert _stored(store) == len(rows)


def test_the_fast_path_cleans_up_its_registration(store):
    """The DataFrame is registered under a fixed name; leaving it behind
    would leak the previous batch into the next statement that referenced
    it."""
    store.link_entity_events(_links(store_module.BULK_INSERT_DATAFRAME_MIN_ROWS))

    with pytest.raises(Exception):
        store.conn.execute("SELECT * FROM _bulk_incoming").fetchall()


def test_events_insert_through_the_fast_path_round_trips(tmp_path):
    """Events carry richer types than entity links - timestamps, ints, a
    JSON blob - so they are worth checking separately."""
    from datetime import datetime, timezone

    from netforensicai.core.event import Event

    events = [
        Event(
            event_id=f"EVT-EV-0001-{i:06d}",
            evidence_id="EV-0001",
            source="pcap",
            event_type="network_connection",
            timestamp=datetime(2026, 8, 27, 9, 0, tzinfo=timezone.utc),
            src_ip="10.0.0.5",
            src_port=44000 + (i % 100),
            dst_ip="93.184.216.34",
            dst_port=80,
            message=f"flow {i}",
            raw_event_reference={"packet_number": i},
        )
        for i in range(store_module.BULK_INSERT_DATAFRAME_MIN_ROWS + 25)
    ]

    with CaseStore(tmp_path) as store:
        store.insert_events(events)

        assert store.count_events() == len(events)
        back = store.get_event("EVT-EV-0001-000009")
        assert back.src_port == 44009
        assert back.dst_ip == "93.184.216.34"
        assert back.timestamp == datetime(2026, 8, 27, 9, 0, tzinfo=timezone.utc)
        assert back.raw_event_reference == {"packet_number": 9}
