"""Entity extraction: pull User/IP/Hostname/Device/Domain/URL/File/Hash/
Process/Port/NetworkConnection entities out of normalized events, and
record which event field each one came from.

entity_id is deterministic - derived from (entity_type, normalized value),
not sequentially assigned - so extracting entities from the same event
twice (e.g. re-parsing one evidence item, or two evidence items that both
mention the same IP) never creates duplicate entity rows: the same
real-world entity always resolves to the same id, which is what makes
correlation across evidence sources possible later.
"""

import hashlib
import logging

logger = logging.getLogger(__name__)

# Event field -> entity_type this field's value represents.
#
# src_port is deliberately ABSENT. A source port is ephemeral - the OS
# picks it per socket - so it identifies a connection, never a thing an
# investigation is about. Indexing it produced 50,958 distinct "port"
# entities on one 100k-packet capture, none of which anybody would ever
# look up. dst_port stays: that identifies a SERVICE, and "show me
# everything touching port 4444" is a real question. The value is still on
# the event either way, so timeline filters and search are unaffected.
FIELD_ENTITY_TYPES = {
    "user": "user",
    "hostname": "hostname",
    "device": "device",
    "src_ip": "ip_address",
    "dst_ip": "ip_address",
    "domain": "domain",
    "url": "url",
    "file_name": "file",
    "file_hash": "hash",
    "process_name": "process",
    "dst_port": "port",
}

ENTITY_TYPES = tuple(sorted(set(FIELD_ENTITY_TYPES.values()) | {"network_connection"}))

# Entity types that are worth INDEXING but not worth CORRELATING ON.
#
# The two are different questions. "Show me everything touching port 4444"
# is a good use of an entity; "these two events are related because both
# involved port 80" is not a relationship at all - on an HTTP capture it
# is true of nearly every pair. Measured on a 3,000-packet capture: 38,782
# of 50,000 correlation links were shared-port links, 29,333 of them just
# "both touched port 80", against 33 links keyed on a shared domain. The
# noise did not merely dilute the signal, it consumed the budget the
# signal needed.
NON_CORRELATING_ENTITY_TYPES = frozenset({"port"})


def generate_entity_id(entity_type, value):
    """Deterministic id for one (entity_type, value) pair, case/whitespace
    insensitive so e.g. "Alice" and "alice " resolve to the same entity."""
    normalized = str(value).strip().lower()
    digest = hashlib.sha256(f"{entity_type}:{normalized}".encode("utf-8")).hexdigest()
    return f"ENT-{entity_type}-{digest[:12]}"


def extract_entities(event):
    """Return (entity_id, entity_type, value, field) tuples found in one event."""
    found = []
    for field, entity_type in FIELD_ENTITY_TYPES.items():
        value = getattr(event, field, None)
        if value is None or value == "":
            continue
        value_str = str(value)
        found.append((generate_entity_id(entity_type, value_str), entity_type, value_str, field))

    if event.src_ip and event.dst_ip:
        # Keyed on the HOST PAIR, not the full flow tuple. Including the
        # ports made this entity unique per flow, so it could never be
        # *shared* between two events - an entity that by construction
        # correlates with nothing, while costing one row per event and
        # 99,892 distinct entities on a 100k-packet capture. Keyed on the
        # pair it means "these two hosts talked", which is a fact worth
        # having and is genuinely shared across every flow between them.
        connection_value = f"{event.src_ip}->{event.dst_ip}"
        found.append(
            (
                generate_entity_id("network_connection", connection_value),
                "network_connection",
                connection_value,
                "src_ip+dst_ip",
            )
        )
    return found


def extract_and_store_ids(store, events):
    """Extract entities from `events`, persist entities + entity_events links
    into `store`, and return the SET of distinct entity_ids touched.

    Returning ids rather than a count is what lets a caller process events in
    batches and still report a correct distinct total: counts from separate
    batches cannot be added without double-counting every entity that appears
    in more than one batch, which for a busy capture is most of them.
    """
    entity_rows = {}
    link_rows = []
    for event in events:
        for entity_id, entity_type, value, field in extract_entities(event):
            # Dedupe entities in memory first: a busy capture references the
            # same IP tens of thousands of times, so collapsing here keeps
            # the batch handed to the store proportional to the number of
            # distinct entities rather than total references.
            entity_rows.setdefault(entity_id, (entity_id, entity_type, value))
            link_rows.append((entity_id, event.event_id, field))

    store.upsert_entities(entity_rows.values())
    store.link_entity_events(link_rows)
    return set(entity_rows)


def extract_and_store(store, events):
    """Extract entities from `events` and persist entities + entity_events
    links into `store`. Returns the number of distinct entities touched."""
    return len(extract_and_store_ids(store, events))
