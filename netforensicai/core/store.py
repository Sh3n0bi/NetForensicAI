"""Local per-case analytical store (DuckDB): normalized events and the
entities extracted from them.

One CaseStore == one DuckDB file at cases/<CASE-ID>/case.duckdb. DuckDB is
single-writer, so callers should not open more than one CaseStore against
the same case concurrently.

Re-parsing an evidence item is idempotent: replace_events_for_evidence()
deletes that evidence's previous events (and their entity links) before
inserting the new ones, so running `parse`/`analyze` again never
accumulates duplicates.

The CLI is single-threaded, so it never needs to worry about the
single-writer rule above - each command opens one CaseStore, uses it, and
closes it before exiting. The web UI is different: it can have a live
capture session's background thread ingesting a just-rotated pcap into
the store at the same moment a browser request is reading the timeline.
GLOBAL_WRITE_LOCK / locked_store() exist for exactly that situation -
use locked_store() instead of CaseStore(...) directly anywhere a
background capture might be running concurrently with the call.
"""

import contextlib
import json
import logging
import threading
from pathlib import Path

import duckdb

from netforensicai.core.event import Event

logger = logging.getLogger(__name__)

# A single, coarse, process-wide lock rather than one per case: this is a
# local single-user tool, true multi-case concurrent access is rare, and
# a simple lock that's always correct beats a per-case lock dict that's
# marginally faster but easier to get wrong.
GLOBAL_WRITE_LOCK = threading.Lock()

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


# Rows per INSERT statement for bulk loads. DuckDB's executemany still
# executes the prepared statement once per row - measured at ~4ms/row, or
# over 3 minutes for the 47k events a single 30 MB pcap produces. Folding
# many rows into one multi-row VALUES clause collapses that to a handful of
# statements. 500 keeps the parameter count per statement well bounded
# (500 x 26 columns for events) while capturing nearly all of the win.
BULK_INSERT_CHUNK_ROWS = 500


def _bulk_insert(conn, table, columns, rows, conflict_clause=""):
    """INSERT many rows using chunked multi-row VALUES clauses.

    Deliberately not executemany (too slow, see BULK_INSERT_CHUNK_ROWS) and
    not the pandas/Arrow bulk path (that would make pandas a hard dependency
    of the core install, when today it only arrives with the [pcap] extra).
    """
    rows = list(rows)
    if not rows:
        return
    columns_sql = ", ".join(columns)
    row_placeholder = "(" + ", ".join(["?"] * len(columns)) + ")"
    for start in range(0, len(rows), BULK_INSERT_CHUNK_ROWS):
        chunk = rows[start : start + BULK_INSERT_CHUNK_ROWS]
        values_sql = ", ".join([row_placeholder] * len(chunk))
        flat = [value for row in chunk for value in row]
        conn.execute(f"INSERT INTO {table} ({columns_sql}) VALUES {values_sql}{conflict_clause}", flat)


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

DETECTION_FIELDS = [
    "detection_id",
    "rule_id",
    "rule_name",
    "severity",
    "event_id",
    "evidence_id",
    "description",
    "detected_at",
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
        # PRIMARY KEY, not a bare table: link_entity_event() used to run a
        # SELECT before every INSERT to avoid duplicates, and with no index
        # each of those was a full scan of a table that grows to hundreds of
        # thousands of rows on a real capture - quadratic, and the reason a
        # 30 MB pcap took over 15 minutes to ingest. The key lets DuckDB
        # dedupe with ON CONFLICT in constant time instead.
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entity_events (
                entity_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                field TEXT NOT NULL,
                PRIMARY KEY (entity_id, event_id, field)
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
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_techniques (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT NOT NULL,
                confidence TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_technique_events (
                technique_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                basis TEXT NOT NULL,
                PRIMARY KEY (technique_id, event_id)
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detections (
                detection_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                description TEXT NOT NULL,
                detected_at TIMESTAMPTZ NOT NULL
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

    def delete_events_for_evidence(self, evidence_id):
        """Drop this evidence item's events and their entity links.

        Separate from replace_events_for_evidence so a caller streaming
        events in batches can clear once up front and then insert
        incrementally, without ever holding the full set.
        """
        self.conn.execute(
            "DELETE FROM entity_events WHERE event_id IN "
            "(SELECT event_id FROM events WHERE evidence_id = ?)",
            [evidence_id],
        )
        self.conn.execute("DELETE FROM events WHERE evidence_id = ?", [evidence_id])

    def replace_events_for_evidence(self, evidence_id, events):
        """Delete any previously stored events (and their entity links) for
        evidence_id, then insert `events`."""
        self.delete_events_for_evidence(evidence_id)
        self.insert_events(events)

    def _event_row(self, event):
        values = []
        for field in EVENT_FIELDS:
            if field == "raw_event_reference":
                value = json.dumps(event.raw_event_reference) if event.raw_event_reference is not None else None
            else:
                value = getattr(event, field)
            values.append(value)
        return values

    def insert_events(self, events):
        """Insert many events in one round trip. A real pcap yields tens of
        thousands of events, and DuckDB is an analytical engine - one
        INSERT statement per row is dramatically slower than a single
        executemany, so batching here is a correctness-of-experience issue,
        not micro-optimization."""
        _bulk_insert(
            self.conn,
            "events",
            [_column(f) for f in EVENT_FIELDS],
            [self._event_row(event) for event in events],
        )

    def _insert_event(self, event):
        self.insert_events([event])

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

    def iter_events(self, where_sql="", params=(), chunk_size=2_000, timestamped_only=False):
        """Yield events in timestamp order without materializing them all.

        all_events() builds every row into a pydantic Event up front, which
        on a real capture (84k events from one 30 MB pcap) is hundreds of
        megabytes. Analyses that only need to walk events in order should
        iterate instead, so their memory tracks their own working set rather
        than the size of the case.

        timestamped_only filters out events with no timestamp in SQL, which
        is what any time-ordered analysis wants and avoids materializing
        rows it would only discard.
        """
        columns_sql = ", ".join(_column(f) for f in EVENT_FIELDS)
        clauses = [where_sql] if where_sql else []
        if timestamped_only:
            clauses.append("WHERE timestamp IS NOT NULL" if not where_sql else "AND timestamp IS NOT NULL")
        sql = (
            f"SELECT {columns_sql} FROM events {' '.join(clauses)} ORDER BY timestamp NULLS LAST"
        )
        cursor = self.conn.execute(sql, list(params))
        while True:
            rows = cursor.fetchmany(chunk_size)
            if not rows:
                return
            for row in rows:
                yield self._row_to_event(row)

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
        self.link_entity_events([(entity_id, event_id, field)])

    def upsert_entities(self, rows):
        """Batch form of upsert_entity. `rows` is an iterable of
        (entity_id, entity_type, value)."""
        # Collapse duplicate entity_ids within the batch for the same reason
        # link_entity_events() does - see its docstring.
        deduped = {row[0]: row for row in rows}
        _bulk_insert(
            self.conn,
            "entities",
            ["entity_id", "entity_type", "value"],
            deduped.values(),
            conflict_clause=" ON CONFLICT (entity_id) DO NOTHING",
        )

    def link_entity_events(self, rows):
        """Batch form of link_entity_event. `rows` is an iterable of
        (entity_id, event_id, field).

        Dedupes via the table's primary key rather than a SELECT-then-INSERT
        per row - see the entity_events schema comment for why that mattered.
        Duplicates *within* the batch are collapsed first: ON CONFLICT
        resolves against rows already committed, not against another row in
        the same statement, so a repeated key inside one executemany would
        still raise.
        """
        _bulk_insert(
            self.conn,
            "entity_events",
            ["entity_id", "event_id", "field"],
            dict.fromkeys(rows),
            conflict_clause=" ON CONFLICT (entity_id, event_id, field) DO NOTHING",
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

    def entity_event_counts(self):
        """{entity_id: distinct events it appears in}, for the whole case.

        One aggregate rather than a count per entity: the alternative is a
        query per row, which on a case with thousands of entities is the
        difference between one round trip and thousands. DISTINCT because
        entity_events is keyed on (entity, event, FIELD) - an IP that is
        both source and destination of the same event has two rows there
        and is still one event.
        """
        rows = self.conn.execute(
            "SELECT entity_id, count(DISTINCT event_id) FROM entity_events GROUP BY entity_id"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def entity_link_counts(self):
        """{entity_id: correlation links resting on it}. Only `related`
        links name a shared entity; `possible_relationship` rows carry no
        entity, so they are absent here by construction rather than by a
        filter."""
        rows = self.conn.execute(
            "SELECT shared_entity_id, count(*) FROM correlation_links "
            "WHERE shared_entity_id IS NOT NULL GROUP BY shared_entity_id"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

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
        # Bulk path, not a statement per row: correlation can legitimately
        # produce tens of thousands of links (DEFAULT_MAX_PAIRS is 50k).
        _bulk_insert(
            self.conn,
            "correlation_links",
            CORRELATION_FIELDS,
            [[link[field] for field in CORRELATION_FIELDS] for link in links],
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

    def count_correlation_links_by_type(self):
        """{relationship_type: count}. The two tiers mean different things -
        a shared entity plus time proximity, versus time proximity alone -
        so a single total hides the part of the number that carries the
        signal."""
        rows = self.conn.execute(
            "SELECT relationship_type, count(*) FROM correlation_links GROUP BY relationship_type"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

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

    # --- ATT&CK technique mappings ---

    def upsert_technique(self, technique_id, technique_name, confidence, now):
        """Insert a newly-detected technique with status "potential", or -
        if it already exists - leave its investigator-set status untouched
        and only refresh confidence/updated_at. Mirrors upsert_entity()'s
        idempotency."""
        self.conn.execute(
            """
            INSERT INTO attack_techniques (technique_id, technique_name, confidence, status, created_at, updated_at)
            VALUES (?, ?, ?, 'potential', ?, ?)
            ON CONFLICT (technique_id) DO UPDATE SET
                confidence = excluded.confidence,
                updated_at = excluded.updated_at
            """,
            [technique_id, technique_name, confidence, now, now],
        )

    def link_technique_event(self, technique_id, event_id, evidence_id, basis):
        # ON CONFLICT against the primary key rather than SELECT-then-INSERT,
        # for the same scaling reason as link_entity_events().
        self.conn.execute(
            "INSERT INTO attack_technique_events (technique_id, event_id, evidence_id, basis) "
            "VALUES (?, ?, ?, ?) ON CONFLICT (technique_id, event_id) DO NOTHING",
            [technique_id, event_id, evidence_id, basis],
        )

    def list_techniques(self):
        rows = self.conn.execute(
            "SELECT technique_id, technique_name, confidence, status, created_at, updated_at "
            "FROM attack_techniques ORDER BY technique_id"
        ).fetchall()
        cols = ["technique_id", "technique_name", "confidence", "status", "created_at", "updated_at"]
        result = []
        for row in rows:
            d = dict(zip(cols, row))
            d["event_count"] = self.conn.execute(
                "SELECT count(*) FROM attack_technique_events WHERE technique_id = ?", [d["technique_id"]]
            ).fetchone()[0]
            result.append(d)
        return result

    def get_technique(self, technique_id):
        row = self.conn.execute(
            "SELECT technique_id, technique_name, confidence, status, created_at, updated_at "
            "FROM attack_techniques WHERE technique_id = ?",
            [technique_id],
        ).fetchone()
        if row is None:
            return None
        cols = ["technique_id", "technique_name", "confidence", "status", "created_at", "updated_at"]
        return dict(zip(cols, row))

    def technique_events(self, technique_id):
        rows = self.conn.execute(
            "SELECT event_id, evidence_id, basis FROM attack_technique_events WHERE technique_id = ?",
            [technique_id],
        ).fetchall()
        return [{"event_id": r[0], "evidence_id": r[1], "basis": r[2]} for r in rows]

    def update_technique_status(self, technique_id, status, now):
        self.conn.execute(
            "UPDATE attack_techniques SET status = ?, updated_at = ? WHERE technique_id = ?",
            [status, now, technique_id],
        )

    def count_techniques(self):
        return self.conn.execute("SELECT count(*) FROM attack_techniques").fetchone()[0]

    # --- bundled detection rules (core/detections.py) ---

    def replace_detections(self, detections):
        """Full rebuild: delete every existing detections row, then insert
        `detections`. Always recomputed for the whole case on every
        analyze - a detection has no investigator-set status to preserve
        across runs, unlike an ATT&CK mapping, so there's nothing an
        upsert would need to protect."""
        self.conn.execute("DELETE FROM detections")
        _bulk_insert(
            self.conn,
            "detections",
            DETECTION_FIELDS,
            [[d[field] for field in DETECTION_FIELDS] for d in detections],
        )

    def list_detections(self, severity=None):
        conditions = []
        params = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        where_sql = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        columns_sql = ", ".join(DETECTION_FIELDS)
        rows = self.conn.execute(
            f"SELECT {columns_sql} FROM detections {where_sql} ORDER BY detected_at DESC", params
        ).fetchall()
        return [dict(zip(DETECTION_FIELDS, row)) for row in rows]

    def count_detections(self):
        return self.conn.execute("SELECT count(*) FROM detections").fetchone()[0]


@contextlib.contextmanager
def locked_store(case_dir):
    """CaseStore usage serialized against GLOBAL_WRITE_LOCK. Use this
    instead of CaseStore(...) directly in the web UI and the capture
    module - see the module docstring for why."""
    with GLOBAL_WRITE_LOCK:
        with CaseStore(case_dir) as store:
            yield store
