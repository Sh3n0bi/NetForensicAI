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
from collections import deque

logger = logging.getLogger(__name__)

DEFAULT_TIME_WINDOW_SECONDS = 300
DEFAULT_MAX_PAIRS = 50_000

# Bounds CPU, not output. Deliberately far larger than DEFAULT_MAX_PAIRS:
# the link budget decides what is worth *keeping*, this only stops a
# pathologically dense case from pairing forever.
DEFAULT_MAX_SCANNED_PAIRS = 2_000_000

# No single entity may take more than this share of the link budget.
#
# Correlation is pairwise, so a HIGH-DEGREE entity produces links
# quadratically: a DNS resolver that appears in three thousand events can
# generate millions of "these two events both involve 8.8.8.8" pairs and
# fill the budget by itself. Measured on a 3,000-packet capture, one
# address took 49,536 of 50,000 links, leaving 100 for every domain in
# the case combined. Capping per entity is what keeps a hub from crowding
# out the rest - the budget then covers at least 1/share distinct
# entities, which is the difference between a picture of the case and a
# picture of its busiest node.
MAX_LINKS_PER_ENTITY_SHARE = 0.1

RELATED = "related"
POSSIBLE_RELATIONSHIP = "possible_relationship"

CONFIDENCE_BY_TYPE = {
    RELATED: "medium",
    POSSIBLE_RELATIONSHIP: "low",
}


def _link_id(event_id_a, event_id_b, relationship_type):
    digest = hashlib.sha256(f"{event_id_a}:{event_id_b}:{relationship_type}".encode("utf-8")).hexdigest()
    return f"LINK-{digest[:16]}"


def _find_time_window_pairs(sorted_events, window_seconds, max_scanned_pairs=DEFAULT_MAX_SCANNED_PAIRS):
    """Yield (event_a, event_b, delta_seconds) for every pair of
    chronologically-sorted, timestamped events within window_seconds of
    each other. a always precedes or is concurrent with b.

    Takes an ITERABLE, not a list, and holds only the events currently
    inside the window: on a real capture the full event set is hundreds of
    megabytes of pydantic objects, and nothing here needs random access.
    Memory is therefore a function of how many events fall inside one
    window, not of the size of the case.

    O(n + pairs_found) rather than O(n^2): events leaving the window are
    discarded, so the inner loop only ever visits genuine candidates.

    Candidates for each event are yielded MOST RECENT PREDECESSOR FIRST.
    That ordering is what lets correlate_case spend a limited link budget
    on the temporally closest pairs - the ones most likely to mean
    anything - instead of on whichever pairs happened to come first.

    max_scanned_pairs bounds CPU only, and is deliberately far larger than
    any link budget. Choosing which pairs survive is the caller's job:
    stopping here truncates strictly chronologically, which on a growing
    case silently discards the newest events - exactly the ones an analyst
    running a live capture is watching for.
    """
    window = deque()
    scanned = 0
    for b in sorted_events:
        # Events too old to pair with anything from here on are dropped;
        # the input is sorted, so this can never discard a future match.
        while window and (b.timestamp - window[0].timestamp).total_seconds() > window_seconds:
            window.popleft()
        for a in reversed(window):
            yield a, b, (b.timestamp - a.timestamp).total_seconds()
            scanned += 1
            if scanned >= max_scanned_pairs:
                logger.warning(
                    f"Correlation stopped after scanning {max_scanned_pairs:,} candidate pairs. "
                    "The case is dense enough that time-proximity pairing over this window is "
                    "not informative - use a shorter --time-window."
                )
                return
        window.append(b)


def _shared_entity(event_id_a, event_id_b, entities_by_event):
    """The strongest entity two events genuinely have in common, or None.

    Types listed in NON_CORRELATING_ENTITY_TYPES are skipped: a shared
    port is not a relationship. Measured on a 3,000-packet capture before
    this skip, 38,782 of 50,000 links were shared-port links and 29,333 of
    those were "both events touched port 80" - which on an HTTP capture is
    true of nearly every pair. They consumed the budget that shared-domain
    and shared-host links needed, so the entity that ended up on a link
    was whichever happened to be checked first.
    """
    from netforensicai.core.entities import NON_CORRELATING_ENTITY_TYPES

    entities_a = entities_by_event.get(event_id_a, [])
    entities_b = entities_by_event.get(event_id_b, [])
    ids_b = {entity_id for entity_id, _entity_type, _value, _field in entities_b}
    for entity_id, entity_type, value, _field in entities_a:
        if entity_type in NON_CORRELATING_ENTITY_TYPES:
            continue
        if entity_id in ids_b:
            return entity_id, entity_type, value
    return None


def correlate_case(
    store,
    time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS,
    max_pairs=DEFAULT_MAX_PAIRS,
    include_possible=True,
):
    """Recompute every correlation_links row for the whole case in `store`.

    Always a full rebuild, never an incremental update: correlation crosses
    evidence-item boundaries by design, so there's no single evidence_id to
    scope an incremental recompute to, and a full rebuild is simple,
    correct, and cheap enough at this data scale to just always do.

    THE LINK BUDGET IS SPENT ON SIGNAL FIRST. `related` links - a shared
    entity plus time proximity, the strongest thing this engine produces -
    are never dropped in favour of `possible_relationship` links, which are
    temporal proximity alone and explicitly weak. On a busy capture almost
    every pair within the window shares no entity, so a single undifferen-
    tiated budget is spent almost entirely on the weak tier while the
    shared-entity links an investigation actually turns on get crowded out.

    include_possible=False drops the weak tier entirely. That is the right
    setting for a dense source such as live capture, where "these two
    packets happened within five minutes of each other" is true of
    essentially every pair and therefore says nothing.

    Returns the list of link dicts that were written.
    """
    # Streamed in timestamp order straight from SQL, with untimestamped rows
    # filtered out there too - materializing and sorting every event in
    # Python cost hundreds of megabytes on a real capture.
    events = store.iter_events(timestamped_only=True)

    entities_by_event = store.entity_ids_by_event()

    links = []
    possible_links = []
    dropped_possible = 0
    per_entity = {}
    crowded_out = 0
    entity_ceiling = max(1, int(max_pairs * MAX_LINKS_PER_ENTITY_SHARE))
    for a, b, delta in _find_time_window_pairs(events, time_window_seconds):
        shared = _shared_entity(a.event_id, b.event_id, entities_by_event)
        if shared:
            entity_id, entity_type, entity_value = shared
            relationship_type = RELATED
            basis = (
                f"share {entity_type} '{entity_value}' and occurred within "
                f"{time_window_seconds}s of each other"
            )
        else:
            if not include_possible:
                continue
            entity_id = entity_type = entity_value = None
            relationship_type = POSSIBLE_RELATIONSHIP
            basis = (
                f"occurred within {time_window_seconds}s of each other with no shared "
                "entity - temporal proximity only, not a confirmed relationship"
            )

        if relationship_type == RELATED:
            # One hub must not consume the budget - see
            # MAX_LINKS_PER_ENTITY_SHARE. Counted rather than silently
            # skipped so the caller can say how much was held back.
            seen = per_entity.get(entity_id, 0)
            if seen >= entity_ceiling:
                crowded_out += 1
                continue
            per_entity[entity_id] = seen + 1

            if len(links) >= max_pairs:
                # Strong links alone have filled the budget. Stopping here
                # still truncates chronologically, but only once there is
                # genuinely more strong signal than the case can hold -
                # which is a real "this case is too dense" signal rather
                # than an artefact of weak links getting there first.
                logger.warning(
                    f"Correlation reached its link budget ({max_pairs:,}) on shared-entity "
                    "links alone; later events were not correlated. Use a shorter "
                    "--time-window."
                )
                break
            if len(links) + len(possible_links) >= max_pairs and possible_links:
                # A strong link DISPLACES a weak one rather than being
                # queued behind it. Without this the budget silently
                # overshoots, and worse, whether a shared-entity link
                # survives would depend on how much temporal noise happened
                # to precede it.
                possible_links.pop()
                dropped_possible += 1
        elif len(links) + len(possible_links) >= max_pairs:
            # Weak links only ever use budget left over by strong ones, and
            # are counted rather than silently discarded so the caller can
            # say how much temporal noise was suppressed.
            dropped_possible += 1
            continue

        target = links if relationship_type == RELATED else possible_links
        target.append(
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

    if crowded_out:
        logger.info(
            f"{crowded_out:,} shared-entity pair(s) were held back so no single entity could take "
            f"more than {entity_ceiling:,} of the {max_pairs:,} link budget. Correlation covers "
            f"{len(per_entity):,} distinct entities."
        )
    if dropped_possible:
        logger.info(
            f"Kept {len(links):,} shared-entity link(s) and {len(possible_links):,} "
            f"time-proximity link(s); {dropped_possible:,} further time-proximity pair(s) "
            "were suppressed once the budget was full. No shared-entity link was dropped."
        )

    # Weak links are appended after strong ones so that a truncated budget
    # can never have cost a shared-entity link.
    links.extend(possible_links)
    store.replace_correlation_links(links)
    return links
