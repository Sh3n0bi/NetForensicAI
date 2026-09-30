"""One host, on one screen.

The entity graph answers "what is this connected to"; the dossier answers
"what did this host do" - the question an analyst actually opens a host
with. It is assembled from events, detections and threat intel already in
the case, with no model and no network, so every line traces back to a
packet the same way the narrative does.

Everything here is read-only aggregation over the store. Byte directions
are from the host's point of view: bytes it *sent* are events where it is
the source, bytes it *received* are events where it is the destination.
"""

import ipaddress

# Enough peers/services/domains to characterise a host without turning the
# page into the very packet dump the dossier exists to replace.
TOP_PEERS = 12
TOP_SERVICES = 12
TOP_DOMAINS = 12
SAMPLE_EVENT_IDS = 6


def _on_network(value):
    """True for an address on the local network - the same private/loopback
    test the narrative uses to decide which side of a flow is 'us'."""
    try:
        parsed = ipaddress.ip_address(str(value))
        return parsed.is_private or parsed.is_loopback
    except (ValueError, TypeError):
        return False


def _bytes(event):
    return (event.raw_event_reference or {}).get("byte_count") or 0


def build(store, entity_id):
    """Return the dossier dict for one IP entity, or None if it doesn't
    exist or isn't an IP address (the dossier is host-only)."""
    entity = store.get_entity(entity_id)
    if entity is None or entity["entity_type"] != "ip_address":
        return None

    host = entity["value"]
    events = store.events_for_entity(entity_id)

    # Existing IP and domain entities, so a peer or domain only becomes a
    # link when it has a page of its own - never a dangling link.
    ip_ids = {str(e["value"]).strip().lower(): e["entity_id"] for e in store.list_entities(entity_type="ip_address")}
    domain_ids = {str(e["value"]).strip().lower(): e["entity_id"] for e in store.list_entities(entity_type="domain")}

    def ip_entity(value):
        return ip_ids.get(str(value).strip().lower())

    def domain_entity(value):
        return domain_ids.get(str(value).strip().lower())

    timestamps = [e.timestamp for e in events if e.timestamp]
    evidence_ids = {e.evidence_id for e in events if e.evidence_id}

    bytes_sent = 0
    bytes_received = 0
    peers = {}  # peer value -> {"events", "bytes", "sent", "received"}
    services = {}  # (port, protocol) -> event count
    domains = {}  # domain value -> event count
    files = []  # files seen alongside this host

    for event in events:
        size = _bytes(event)
        is_source = event.src_ip == host
        peer_value = event.dst_ip if is_source else event.src_ip
        if is_source:
            bytes_sent += size
        elif event.dst_ip == host:
            bytes_received += size

        if peer_value and peer_value != host:
            p = peers.setdefault(peer_value, {"events": 0, "bytes": 0, "sent": 0, "received": 0})
            p["events"] += 1
            p["bytes"] += size
            if is_source:
                p["sent"] += size
            else:
                p["received"] += size

        # A service is a destination port the host reached out to; a source
        # port is ephemeral (see entities.py) and names no service.
        if is_source and event.dst_port:
            key = (event.dst_port, event.protocol or "")
            services[key] = services.get(key, 0) + 1

        if event.domain:
            domains[event.domain] = domains.get(event.domain, 0) + 1

        if event.file_name or event.file_hash:
            files.append(
                {
                    "name": event.file_name,
                    "hash": event.file_hash,
                    "direction": "sent" if is_source else ("received" if event.dst_ip == host else "seen"),
                    "event_id": event.event_id,
                }
            )

    # Findings: detections that fired on this host's own events.
    host_event_ids = {e.event_id for e in events}
    grouped = {}
    for detection in store.list_detections():
        if detection.get("event_id") not in host_event_ids:
            continue
        rule_id = detection["rule_id"]
        entry = grouped.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "title": detection["rule_name"],
                "severity": detection["severity"],
                "occurrences": 0,
                "event_ids": [],
            },
        )
        entry["occurrences"] += 1
        if len(entry["event_ids"]) < SAMPLE_EVENT_IDS and detection.get("event_id"):
            entry["event_ids"].append(detection["event_id"])
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings = sorted(grouped.values(), key=lambda f: severity_rank.get(f["severity"], 0), reverse=True)

    peer_list = [
        {
            "value": value,
            "entity_id": ip_entity(value),
            "external": not _on_network(value),
            "events": info["events"],
            "bytes": info["bytes"],
            "bytes_sent": info["sent"],
            "bytes_received": info["received"],
        }
        for value, info in peers.items()
    ]
    peer_list.sort(key=lambda p: (p["bytes"], p["events"]), reverse=True)

    service_list = [
        {"port": port, "protocol": protocol, "events": count} for (port, protocol), count in services.items()
    ]
    service_list.sort(key=lambda s: s["events"], reverse=True)

    domain_list = [
        {"value": value, "entity_id": domain_entity(value), "events": count} for value, count in domains.items()
    ]
    domain_list.sort(key=lambda d: d["events"], reverse=True)

    # Threat intel recorded for this exact host, if any lookup was run.
    threat_intel = [ti for ti in store.list_threat_intel() if ti.get("entity_id") == entity_id]

    return {
        "entity": {"entity_id": entity_id, "value": host, "on_network": _on_network(host)},
        "summary": {
            "events": len(events),
            "evidence_count": len(evidence_ids),
            "first_seen": min(timestamps).isoformat() if timestamps else None,
            "last_seen": max(timestamps).isoformat() if timestamps else None,
            "peer_count": len(peers),
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
        },
        "findings": findings,
        "peers": peer_list[:TOP_PEERS],
        "peer_total": len(peer_list),
        "services": service_list[:TOP_SERVICES],
        "domains": domain_list[:TOP_DOMAINS],
        "files": files,
        "threat_intel": threat_intel,
    }
