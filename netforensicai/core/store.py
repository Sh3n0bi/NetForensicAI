"""Local per-case analytical store (DuckDB): normalized events and the
entities extracted from them.

One CaseStore == one DuckDB file at cases/<CASE-ID>/case.duckdb. DuckDB is
single-writer, so callers should not open more than one CaseStore against
the same case concurrently.

Re-parsing an evidence item is idempotent: replace_events_for_evidence()
deletes that evidence's previous events (and their entity links) before
inserting the new ones, so running `parse`/`analyze` again never
accumulates duplicates.
"""

import json
import logging
from pathlib import Path

import duckdb

from netforensicai.core.event import Event

logger = logging.getLogger(__name__)

# Event model field, in insertion/selection order. "user" is stored under
# a different column name (see _column) since it's close enough to a SQL
# keyword (USER / CURRENT_USER) in some dialects to be worth just avoiding.
EVENT_FIELDS = [
    "event_id",
    "evidence_id",
    "source",
    "event_type",
    "timestamp",
    "timestamp_precision",
    "user",
    "hostname",
    "device",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "process_name",
    "process_id",
    "parent_process",
    "command_line",
    "file_name",
    "file_path",
    "file_hash",
    "domain",
    "url",
    "severity",
    "message",
    "raw_event_reference",
]

_DB_COLUMN = {"user": "event_user"}


def _column(field):
    return _DB_COLUMN.get(field, field)


CORRELATION_FIELDS = [
    "link_id",
    "event_id_a",
    "event_id_b",
    "relationship_type",
    "basis",
    "shared_entity_id",
    "shared_entity_type",
    "shared_entity_value",
    "time_delta_seconds",
    "confidence",
]

THREAT_INTEL_FIELDS = [
    "entity_id",
    "entity_type",
    "value",
    "provider",
    "checked_at",
    "malicious",
    "malicious_count",
    "total_engines",
    "permalink",
    "error",
]


class CaseStore:
    def __init__(self, case_dir):
        self.case_dir = Path(case_dir)
        self.db_path = self.case_dir / "case.duckdb"
        self.conn = duckdb.connect(str(self.db_path))
        # DuckDB otherwise returns TIMESTAMPTZ values converted to the host
        # machine's local timezone. Since a case can be opened from
        # different machines, pin the session to UTC so timestamps read
        # back exactly as normalized (see core/event.py), not just
        # UTC-equivalent with a different displayed offset.
        self.conn.execute("SET TimeZone='UTC'")
        self._init_schema()

    def _init_schema(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TIMESTAMPTZ,
                timestamp_precision TEXT,
                event_user TEXT,
                hostname TEXT,
                device TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                process_name TEXT,
                process_id INTEGER,
                parent_process TEXT,
                command_line TEXT,
                file_name TEXT,
                file_path TEXT,
                file_hash TEXT,
                domain TEXT,
                url TEXT,
                severity TEXT,
                message TEXT,
                raw_event_reference TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entities (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                value TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entity_events (
                entity_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                field TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS correlation_links (
                link_id TEXT PRIMARY KEY,
                event_id_a TEXT NOT NULL,
                event_id_b TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                basis TEXT NOT NULL,
                shared_entity_id TEXT,
                shared_entity_type TEXT,
                shared_entity_value TEXT,
                time_delta_seconds DOUBLE,
                confidence TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_intel (
                entity_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                value TEXT NOT NULL,
                provider TEXT NOT NULL,
                checked_at TIMESTAMPTZ NOT NULL,
                malicious BOOLEAN,
                malicious_count INTEGER,
                total_engines INTEGER,
                permalink TEXT,
                error TEXT,
                PRIMARY KEY (entity_id, provider)
            )
            """
        )

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # --- events ---

    def replace_events_for_evidence(self, evidence_id, events):
        """Delete any previously stored events (and their entity links) for
        evidence_id, then insert `events`."""
        self.conn.execute(
            "DELETE FROM entity_events WHERE event_id IN "
            "(SELECT event_id FROM events WHERE evidence_id = ?)",
            [evidence_id],
        )
        self.conn.execute("DELETE FROM events WHERE evidence_id = ?", [evidence_id])
        for event in events:
            self._insert_event(event)

    def _insert_event(self, event):
        values = []
        for field in EVENT_FIELDS:
            if field == "raw_event_reference":
                value = json.dumps(event.raw_event_reference) if event.raw_event_reference is not None else None
            else:
                value = getattr(event, field)
            values.append(value)
        columns_sql = ", ".join(_column(f) for f in EVENT_FIELDS)
        placeholders = ", ".join(["?"] * len(EVENT_FIELDS))
        self.conn.execute(f"INSERT INTO events ({columns_sql}) VALUES ({placeholders})", values)

    def _row_to_event(self, row):
        data = dict(zip(EVENT_FIELDS, row))
        raw_ref = data.get("raw_event_reference")
        data["raw_event_reference"] = json.loads(raw_ref) if raw_ref else None
        return Event.model_validate(data)

    def _select_events(self, where_sql="", params=()):
        columns_sql = ", ".join(_column(f) for f in EVENT_FIELDS)
        sql = f"SELECT {columns_sql} FROM events {where_sql} ORDER BY timestamp NULLS LAST"
        rows = self.conn.execute(sql, list(params)).fetchall()
        return [self._row_to_event(row) for row in rows]

    def all_events(self):
        return self._select_events()

    def events_for_evidence(self, evidence_id):
        return self._select_events("WHERE evidence_id = ?", [evidence_id])

    def get_event(self, event_id):
        rows = self._select_events("WHERE event_id = ?", [event_id])
        return rows[0] if rows else None

    def count_events(self):
        return self.conn.execute("SELECT count(*) FROM events").fetchone()[0]

    # --- entities ---

    def upsert_entity(self, entity_id, entity_type, value):
        self.conn.execute(
            "INSERT INTO entities (entity_id, entity_type, value) VALUES (?, ?, ?) "
            "ON CONFLICT (entity_id) DO NOTHING",
            [entity_id, entity_type, value],
        )

    def link_entity_event(self, entity_id, event_id, field):
        exists = self.conn.execute(
            "SELECT 1 FROM entity_events WHERE entity_id = ? AND event_id = ? AND field = ?",
            [entity_id, event_id, field],
        ).fetchone()
        if not exists:
            self.conn.execute(
                "INSERT INTO entity_events (entity_id, event_id, field) VALUES (?, ?, ?)",
                [entity_id, event_id, field],
            )

    def list_entities(self, entity_type=None):
        if entity_type:
            rows = self.conn.execute(
                "SELECT entity_id, entity_type, value FROM entities WHERE entity_type = ? ORDER BY value",
                [entity_type],
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT entity_id, entity_type, value FROM entities ORDER BY entity_type, value"
            ).fetchall()
        return [{"entity_id": r[0], "entity_type": r[1], "value": r[2]} for r in rows]

    def events_for_entity(self, entity_id):
        columns_sql = ", ".join(f"e.{_column(f)}" for f in EVENT_FIELDS)
        rows = self.conn.execute(
            f"SELECT {columns_sql} FROM events e "
            "JOIN entity_events ee ON ee.event_id = e.event_id "
            "WHERE ee.entity_id = ? ORDER BY e.timestamp NULLS LAST",
            [entity_id],
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def count_entities(self):
        return self.conn.execute("SELECT count(*) FROM entities").fetchone()[0]

    def get_entity(self, entity_id):
        row = self.conn.execute(
            "SELECT entity_id, entity_type, value FROM entities WHERE entity_id = ?", [entity_id]
        ).fetchone()
        if row is None:
            return None
        return {"entity_id": row[0], "entity_type": row[1], "value": row[2]}

    def related_entities(self, entity_id):
        """Other entities that co-occur with entity_id on at least one
        event, ranked by how many events they share with it. This is the
        1-hop neighborhood a relational entity_events table can answer
        directly - no graph database needed for that."""
        rows = self.conn.execute(
            """
            SELECT e2.entity_id, e2.entity_type, e2.value, count(DISTINCT ee1.event_id) AS shared_event_count
            FROM entity_events ee1
            JOIN entity_events ee2 ON ee2.event_id = ee1.event_id AND ee2.entity_id != ee1.entity_id
            JOIN entities e2 ON e2.entity_id = ee2.entity_id
            WHERE ee1.entity_id = ?
            GROUP BY e2.entity_id, e2.entity_type, e2.value
            ORDER BY shared_event_count DESC, e2.entity_type, e2.value
            """,
            [entity_id],
        ).fetchall()
        return [
            {"entity_id": r[0], "entity_type": r[1], "value": r[2], "shared_event_count": r[3]} for r in rows
        ]

    def entity_ids_by_event(self):
        """Return {event_id: [(entity_id, entity_type, value, field), ...]}
        for every entity_event link - used by the correlation engine's
        shared-entity lookups and the timeline engine's entity references,
        both without a query per event/pair.

        A list, not a dict keyed by entity_id: the same entity can
        legitimately be linked to one event under two different fields
        (e.g. a reflected connection where src_ip == dst_ip), and
        collapsing those would silently drop one field association.
        """
        rows = self.conn.execute(
            "SELECT ee.event_id, ee.entity_id, e.entity_type, e.value, ee.field "
            "FROM entity_events ee JOIN entities e ON e.entity_id = ee.entity_id"
        ).fetchall()
        result = {}
        for event_id, entity_id, entity_type, value, link_field in rows:
            result.setdefault(event_id, []).append((entity_id, entity_type, value, link_field))
        return result

    # --- correlation links ---

    def replace_correlation_links(self, links):
        """Full rebuild: delete every existing correlation_links row, then
        insert `links`. Correlation is always recomputed for the whole
        case, not scoped to one evidence item - see core/correlation.py."""
        self.conn.execute("DELETE FROM correlation_links")
        for link in links:
            columns_sql = ", ".join(CORRELATION_FIELDS)
            placeholders = ", ".join(["?"] * len(CORRELATION_FIELDS))
            values = [link[field] for field in CORRELATION_FIELDS]
            self.conn.execute(
                f"INSERT INTO correlation_links ({columns_sql}) VALUES ({placeholders})", values
            )

    def list_correlation_links(self, event_id=None, relationship_type=None):
        conditions = []
        params = []
        if event_id:
            conditions.append("(event_id_a = ? OR event_id_b = ?)")
            params.extend([event_id, event_id])
        if relationship_type:
            conditions.append("relationship_type = ?")
            params.append(relationship_type)
        where_sql = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        columns_sql = ", ".join(CORRELATION_FIELDS)
        rows = self.conn.execute(
            f"SELECT {columns_sql} FROM correlation_links {where_sql}", params
        ).fetchall()
        return [dict(zip(CORRELATION_FIELDS, row)) for row in rows]

    def count_correlation_links(self):
        return self.conn.execute("SELECT count(*) FROM correlation_links").fetchone()[0]

    # --- threat intel cache ---

    def record_threat_intel(self, entity_id, entity_type, value, provider, result, checked_at):
        """Upsert one (entity_id, provider) threat-intel result. Only the
        latest check per provider is kept - this is a cache, not a log."""
        self.conn.execute(
            """
            INSERT INTO threat_intel
                (entity_id, entity_type, value, provider, checked_at, malicious, malicious_count, total_engines, permalink, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (entity_id, provider) DO UPDATE SET
                checked_at = excluded.checked_at,
                malicious = excluded.malicious,
                malicious_count = excluded.malicious_count,
                total_engines = excluded.total_engines,
                permalink = excluded.permalink,
                error = excluded.error
            """,
            [
                entity_id,
                entity_type,
                value,
                provider,
                checked_at,
                result.get("malicious"),
                result.get("malicious_count"),
                result.get("total_engines"),
                result.get("permalink"),
                result.get("error"),
            ],
        )

    def get_threat_intel(self, entity_id, provider):
        columns_sql = ", ".join(THREAT_INTEL_FIELDS)
        row = self.conn.execute(
            f"SELECT {columns_sql} FROM threat_intel WHERE entity_id = ? AND provider = ?",
            [entity_id, provider],
        ).fetchone()
        return dict(zip(THREAT_INTEL_FIELDS, row)) if row else None

    def list_threat_intel(self):
        columns_sql = ", ".join(THREAT_INTEL_FIELDS)
        rows = self.conn.execute(f"SELECT {columns_sql} FROM threat_intel ORDER BY checked_at DESC").fetchall()
        return [dict(zip(THREAT_INTEL_FIELDS, row)) for row in rows]
