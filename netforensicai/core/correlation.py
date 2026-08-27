"""Deterministic correlation engine.

Two kinds of event-to-event relationship get materialized as
correlation_links rows:

  - "related": events that share at least one entity (same IP, user,
    hostname, device, file hash, process, or domain - see core/entities.py)
    AND fall within a configurable time window of each other. The
    strongest signal this engine produces.
  - "possible_relationship": events with NO shared entity that merely fall
    within the same time window. Temporal proximity alone is weak evidence
    of a real connection - see the warning below - so this is always the
    lower-confidence tier, worded accordingly.

Deliberately NOT materialized here: plain same-entity relationships with
no time-window constraint. Those are already fully represented by
entities.py's entity_events table (one row per event<->entity link, O(n));
turning that into pairwise correlation_links would be O(n^2) per entity
for no informational gain. A caller who wants "every event that shares
entity X" should query entity_events (or CaseStore.events_for_entity),
not correlation_links.

Do NOT read "related" or "possible_relationship" as claims of causality.
Temporal and entity proximity are exactly that - proximity - never
evidence that one event caused, or is part of the same causal chain as,
another. That judgment belongs to the investigator (or, later, a hedged
AI hypothesis checked against evidence), never to this engine.

Every link records which event happened first (event_id_a always precedes
or is concurrent with event_id_b) - this positional ordering IS the
"preceded"/"followed" relationship, expressed once per pair rather than
as two mirrored rows.
"""

import hashlib
import logging

logger = logging.getLogger(__name__)

DEFAULT_TIME_WINDOW_SECONDS = 300
DEFAULT_MAX_PAIRS = 50_000

RELATED = "related"
POSSIBLE_RELATIONSHIP = "possible_relationship"

CONFIDENCE_BY_TYPE = {
    RELATED: "medium",
    POSSIBLE_RELATIONSHIP: "low",
}


def _link_id(event_id_a, event_id_b, relationship_type):
    digest = hashlib.sha256(f"{event_id_a}:{event_id_b}:{relationship_type}".encode("utf-8")).hexdigest()
    return f"LINK-{digest[:16]}"


def _find_time_window_pairs(sorted_events, window_seconds, max_pairs):
    """Yield (event_a, event_b, delta_seconds) for every pair of
    chronologically-sorted, timestamped events within window_seconds of
    each other. a always precedes or is concurrent with b.

    O(n + pairs_found) rather than O(n^2): the inner loop breaks as soon as
    a candidate falls outside the window, since events are sorted. Capped
    at max_pairs as a safety net for pathological cases (e.g. thousands of
    events sharing near-identical timestamps), which would otherwise still
    degrade toward O(n^2) since that many pairs genuinely are within the
    window.
    """
    n = len(sorted_events)
    emitted = 0
    for i in range(n):
        a = sorted_events[i]
        for j in range(i + 1, n):
            b = sorted_events[j]
            delta = (b.timestamp - a.timestamp).total_seconds()
            if delta > window_seconds:
                break
            yield a, b, delta
            emitted += 1
            if emitted >= max_pairs:
                logger.warning(
                    f"Correlation pair limit ({max_pairs}) reached; some possible "
                    "time-window correlations were not computed. Consider a smaller "
                    "time window for this case."
                )
                return


def _shared_entity(event_id_a, event_id_b, entities_by_event):
    entities_a = entities_by_event.get(event_id_a, {})
    entities_b = entities_by_event.get(event_id_b, {})
    for entity_id in entities_a:
        if entity_id in entities_b:
            entity_type, entity_value = entities_a[entity_id]
            return entity_id, entity_type, entity_value
    return None


def correlate_case(store, time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS, max_pairs=DEFAULT_MAX_PAIRS):
    """Recompute every correlation_links row for the whole case in `store`.

    Always a full rebuild, never an incremental update: correlation crosses
    evidence-item boundaries by design, so there's no single evidence_id to
    scope an incremental recompute to, and a full rebuild is simple,
    correct, and cheap enough at this data scale to just always do.

    Returns the list of link dicts that were written.
    """
    events = [e for e in store.all_events() if e.timestamp is not None]
    events.sort(key=lambda e: e.timestamp)

    entities_by_event = store.entity_ids_by_event()

    links = []
    for a, b, delta in _find_time_window_pairs(events, time_window_seconds, max_pairs):
        shared = _shared_entity(a.event_id, b.event_id, entities_by_event)
        if shared:
            entity_id, entity_type, entity_value = shared
            relationship_type = RELATED
            basis = (
                f"share {entity_type} '{entity_value}' and occurred within "
                f"{time_window_seconds}s of each other"
            )
        else:
            entity_id = entity_type = entity_value = None
            relationship_type = POSSIBLE_RELATIONSHIP
            basis = (
                f"occurred within {time_window_seconds}s of each other with no shared "
                "entity - temporal proximity only, not a confirmed relationship"
            )

        links.append(
            {
                "link_id": _link_id(a.event_id, b.event_id, relationship_type),
                "event_id_a": a.event_id,
                "event_id_b": b.event_id,
                "relationship_type": relationship_type,
                "basis": basis,
                "shared_entity_id": entity_id,
                "shared_entity_type": entity_type,
                "shared_entity_value": entity_value,
                "time_delta_seconds": delta,
                "confidence": CONFIDENCE_BY_TYPE[relationship_type],
            }
        )

    store.replace_correlation_links(links)
    return links
