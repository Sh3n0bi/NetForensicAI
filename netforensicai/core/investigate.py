"""Entity-centric investigation: pull together everything the platform
knows about one entity - info, related evidence, events, timeline,
related entities, and simple deterministic leads - for
`netforensic investigate`.

Leads generated here are plain, rule-based observations grounded in data
already computed elsewhere (correlation links, entity co-occurrence,
evidence/event counts) - never a fabricated conclusion, never phrased as
certainty. This is deliberately NOT the AI assistant layer (a later,
separate, explicitly-hedged step) - it's the deterministic floor that
layer will eventually sit on top of, and it works whether or not that
layer ever gets enabled.
"""

import logging

from netforensicai.core.entities import generate_entity_id
from netforensicai.core.timeline import build_timeline

logger = logging.getLogger(__name__)


class InvestigationResult:
    def __init__(self, entity, events, evidence_ids, timeline_entries, related_entities, correlation_links, leads):
        self.entity = entity
        self.events = events
        self.evidence_ids = evidence_ids
        self.timeline_entries = timeline_entries
        self.related_entities = related_entities
        self.correlation_links = correlation_links
        self.leads = leads


def investigate_entity(store, entity_type, value):
    """Return an InvestigationResult for (entity_type, value), or None if
    this entity has never been observed in this case.

    entity_id is deterministic (see core/entities.py), so this never needs
    a fuzzy search step - an entity either was observed under this exact
    (type, value) or it wasn't.
    """
    entity_id = generate_entity_id(entity_type, value)
    entity = store.get_entity(entity_id)
    if entity is None:
        return None

    events = store.events_for_entity(entity_id)
    evidence_ids = sorted({e.evidence_id for e in events})

    event_ids = {e.event_id for e in events}
    timeline_entries = [t for t in build_timeline(store) if t.event_id in event_ids]

    related = store.related_entities(entity_id)

    correlation_links = []
    seen_link_ids = set()
    for event_id in event_ids:
        for link in store.list_correlation_links(event_id=event_id):
            if link["link_id"] not in seen_link_ids:
                seen_link_ids.add(link["link_id"])
                correlation_links.append(link)

    leads = _generate_leads(entity, evidence_ids, related, correlation_links)

    return InvestigationResult(
        entity=entity,
        events=events,
        evidence_ids=evidence_ids,
        timeline_entries=timeline_entries,
        related_entities=related,
        correlation_links=correlation_links,
        leads=leads,
    )


def _generate_leads(entity, evidence_ids, related_entities, correlation_links):
    leads = []

    if len(evidence_ids) > 1:
        leads.append(
            f"This {entity['entity_type']} appears across {len(evidence_ids)} separate evidence "
            f"items ({', '.join(evidence_ids)}) - worth confirming whether these represent the "
            "same activity or coincidental overlap."
        )

    related_link_count = sum(1 for link in correlation_links if link["relationship_type"] == "related")
    if related_link_count:
        leads.append(
            f"{related_link_count} event pair(s) involving this entity share another entity AND "
            "fall within the correlation time window - review those linked events for a possible "
            "sequence of activity."
        )

    for rel in related_entities[:5]:
        leads.append(
            f"Also review {rel['entity_type']} '{rel['value']}' - co-occurs in "
            f"{rel['shared_event_count']} of this entity's events."
        )

    if entity["entity_type"] == "ip_address":
        leads.append(
            "Consider checking this IP against VirusTotal or another threat intelligence source "
            "(--vt-api or VT_API_KEY) if not already done."
        )
    elif entity["entity_type"] == "hash":
        leads.append(
            "Consider checking this file hash against VirusTotal or another threat intelligence "
            "source for known-malicious matches."
        )

    if not leads:
        leads.append("No additional automated leads - this entity has limited correlated activity in this case.")

    return leads
