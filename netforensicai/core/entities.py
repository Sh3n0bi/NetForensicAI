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
    "src_port": "port",
    "dst_port": "port",
}

ENTITY_TYPES = tuple(sorted(set(FIELD_ENTITY_TYPES.values()) | {"network_connection"}))


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
        src_port = event.src_port if event.src_port is not None else "?"
        dst_port = event.dst_port if event.dst_port is not None else "?"
        connection_value = f"{event.src_ip}:{src_port}->{event.dst_ip}:{dst_port}"
        found.append(
            (
                generate_entity_id("network_connection", connection_value),
                "network_connection",
                connection_value,
                "src_ip+dst_ip",
            )
        )
    return found


def extract_and_store(store, events):
    """Extract entities from `events` and persist entities + entity_events
    links into `store`. Returns the number of distinct entities touched."""
    seen_entity_ids = set()
    for event in events:
        for entity_id, entity_type, value, field in extract_entities(event):
            store.upsert_entity(entity_id, entity_type, value)
            store.link_entity_event(entity_id, event.event_id, field)
            seen_entity_ids.add(entity_id)
    return len(seen_entity_ids)
