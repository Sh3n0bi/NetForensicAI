"""The specialist roles of the investigation team.

Each role is a `Role` from base.py: a mission that scopes its system prompt and
the subset of read-only case tools it may call. Missions tell the model WHAT to
look for in its domain and to prefer the case's own deterministic detections and
entities over anything it might infer - the grounding contract (cite or be
dropped) is enforced by the runner, not by the prose here.

Phase 2 ships the two roles that map to the two evidence domains the tool
normalizes richly today: network (pcap / Suricata) and host (EVTX / Sysmon).
The remaining roles (malware/IOC, threat-intel/correlation, reporter) are added
in a later phase; new roles just register here.
"""

from netforensicai.agents.base import Role

NETWORK = Role(
    name="Network Forensics",
    slug="network",
    mission=(
        "Reconstruct what happened on the wire. Concentrate on: connections to "
        "unusual ports or external hosts; DNS lookups (especially to rare or "
        "cheap-TLD domains); TLS SNI and HTTP hostnames/URLs; regular-interval "
        "beaconing that looks like command-and-control; large or one-way "
        "transfers that look like exfiltration; and any credential seen crossing "
        "the network in the clear. Start from the case's own detections and "
        "entities and confirm them against the events, streams and packets; only "
        "then add what they imply. Do not speculate about host activity you "
        "cannot see in the network evidence."
    ),
    tools=(
        "list_detections",
        "list_entities",
        "search_events",
        "protocol_summary",
        "list_streams",
        "follow_stream",
        "search_packets",
    ),
)

HOST = Role(
    name="Host & Endpoint (DFIR)",
    slug="host",
    mission=(
        "Reconstruct what happened on the endpoint from Windows Event Log / "
        "Sysmon events. Concentrate on: process creation and suspicious "
        "parent-child chains; files written or dropped, especially executables "
        "and script or key material; persistence; account logons and failed-"
        "logon bursts; and signs of credential access or lateral movement. Start "
        "from the case's own detections and host entities (users, hosts, "
        "processes, files) and confirm them against the events; only then add "
        "what they imply. Do not speculate about network activity you cannot see "
        "in the host evidence."
    ),
    tools=(
        "list_detections",
        "list_entities",
        "search_events",
    ),
)

# Registry, in dispatch order. Later phases append their roles here.
ROLES = {role.slug: role for role in (NETWORK, HOST)}


def all_roles():
    """Every registered role, in dispatch order."""
    return list(ROLES.values())


def get_role(slug):
    """Look up a role by slug, or None if there is no such role."""
    return ROLES.get(slug)


def resolve_roles(slugs=None):
    """The roles named by `slugs` (a list/iterable), or all of them when None.

    Raises KeyError naming the first unknown slug, so a CLI can report it.
    """
    if slugs is None:
        return all_roles()
    resolved = []
    for slug in slugs:
        role = ROLES.get(slug)
        if role is None:
            raise KeyError(slug)
        resolved.append(role)
    return resolved
