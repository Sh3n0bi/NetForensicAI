"""Bundled offline detection rules: a small, fixed set of deterministic
pattern matches over normalized events, run automatically as part of
`analyze` - no AI, no external network call, no API key, nothing opt-in.

    Evidence -> Parsing -> Normalization -> Correlation -> Timeline
        -> Detections (this module) -> [optional: ATT&CK mapping,
           threat intel, AI hypothesis] -> Human validation -> Report

This sits alongside correlation as part of the automatic, deterministic
pipeline rather than behind an explicit command like `attack scan` or
`investigate --vt-api`: every rule here is a fixed, local, zero-cost
pattern match (a process name, a port number, a filename shape), with
none of the cost/privacy/rate-limit reasons threat intel and AI have for
staying opt-in. Like everything else in this pipeline, a detection is a
flag pointing at evidence, never a claim that something malicious
happened - the wording on every rule says "commonly associated with" or
"may indicate", not "this is". Nothing here writes a Finding automatically.

Always a full rescan of every event, recomputed the same way correlation
is (CaseStore.replace_detections deletes and reinserts) - a detection has
no investigator-set status to preserve across runs, unlike an ATT&CK
mapping. If a rule stops matching (the offending event was on evidence
that's since been corrected, for example), the next analyze simply drops
it - there's nothing to explicitly reject.

Deliberately a small starting set (four rules) rather than an attempt at
exhaustive coverage - same reasoning as core/attack.py's rule set: each
rule was chosen because the signal is specific enough to be worth an
investigator's attention on its own. Adding more follows the same
pattern - see CONTRIBUTING.md.
"""

import logging

logger = logging.getLogger(__name__)

SEVERITIES = ("low", "medium", "high")

# Dual-use tools with legitimate uses (sysadmin, red team engagements) but
# whose presence is worth an investigator's attention regardless - matched
# on process_name, case-insensitively, exact basename match only (not a
# substring) to avoid flagging unrelated processes that merely contain
# one of these words.
_OFFENSIVE_TOOL_NAMES = {
    "mimikatz.exe",
    "procdump.exe",
    "psexec.exe",
    "psexec64.exe",
    "rubeus.exe",
    "wce.exe",
    "pwdump.exe",
    "pwdump7.exe",
    "nc.exe",
    "ncat.exe",
    "plink.exe",
}

# Ports with a long history of association with specific malware/C2
# frameworks (Metasploit's default 4444, Back Orifice's 31337, NetBus's
# 12345, etc.) - none of these are reserved exclusively for malicious use,
# so the basis text says "commonly associated with", not "is".
_SUSPICIOUS_PORTS = {
    4444: "Metasploit's default handler port",
    1337: "a port conventionally used by malware/C2 tooling ('leet')",
    31337: "Back Orifice's default port ('eleet')",
    12345: "NetBus's default port",
    6666: "a port commonly used by IRC-based botnet C2",
}

_EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"}

# Substrings that appear in the User-Agent of well-known offensive
# security tools. Matched case-insensitively as substrings because these
# tools append version strings ("gobuster/3.6", "sqlmap/1.8.3#stable").
# Every one of these is dual-use - they are standard in authorized
# penetration tests - so the description says "commonly used for", and
# leaves the judgement to the investigator.
_ATTACK_TOOL_USER_AGENTS = {
    "gobuster": "directory/content brute-forcing",
    "sqlmap": "automated SQL injection",
    "nikto": "web vulnerability scanning",
    "dirbuster": "directory brute-forcing",
    "wfuzz": "web fuzzing",
    "ffuf": "web fuzzing",
    "nmap": "network/service scanning",
    "masscan": "high-speed port scanning",
    "nessus": "vulnerability scanning",
    "burp": "web proxy/attack tooling",
    "hydra": "credential brute-forcing",
    "havij": "automated SQL injection",
    "acunetix": "web vulnerability scanning",
    "zgrab": "internet-wide scanning",
}

# An HTTP client requesting this many distinct URL paths from one host is
# doing content discovery, not browsing. Set well above what a real page
# load pulls in (a heavy page is tens of assets, not hundreds) so ordinary
# traffic doesn't trip it.
_SCAN_DISTINCT_PATH_THRESHOLD = 100

_CREDENTIAL_ARTIFACT_PATTERNS = (
    "system32\\config\\sam",
    "system32/config/sam",
    "ntds.dit",
    "lsass.dmp",
    "lsass.exe.dmp",
)


def _looks_like_extension(part):
    """Whether a dot-separated fragment is plausibly a real file extension.

    Guards against dots that aren't extension separators at all. Found via a
    real capture: the pcap parser names carved files after the TCP stream
    ("73.124.22.98_80_to_111.224.250.131_43248.exe"), and the IP octets made
    every one of them look like a disguised double-extension executable.
    """
    return 1 <= len(part) <= 5 and part.isalnum() and not part.isdigit()


def _double_extension_match(file_name):
    """True if file_name has two extensions and the last one is
    executable - e.g. "invoice.pdf.exe". A single ".exe" alone (no
    disguise attempt) does not match; the whole point of this rule is the
    *disguise* pattern, not "is this an executable"."""
    if not file_name:
        return False
    parts = file_name.lower().rsplit(".", 2)
    if len(parts) != 3:
        return False
    _stem, first_ext, second_ext = parts
    # BOTH fragments must look like real extensions. The masquerade this
    # rule targets is "document extension followed by executable one"
    # (invoice.pdf.exe) - if the first fragment isn't a plausible
    # extension, the dots are just part of the name.
    return f".{second_ext}" in _EXECUTABLE_EXTENSIONS and _looks_like_extension(first_ext)


def _rules_for_event(event):
    if event.event_type == "process_start" and event.process_name:
        name = event.process_name.lower()
        if name in _OFFENSIVE_TOOL_NAMES:
            yield (
                "OFFENSIVE-TOOL-NAME",
                "Known offensive-security tool name",
                "high",
                f"Process name matches a tool commonly used for credential access or lateral "
                f"movement: {event.process_name}",
            )

    if event.event_type == "network_connection" and event.dst_port in _SUSPICIOUS_PORTS:
        reason = _SUSPICIOUS_PORTS[event.dst_port]
        yield (
            "SUSPICIOUS-PORT",
            "Connection to a historically suspicious port",
            "medium",
            f"Destination port {event.dst_port} is {reason} - not exclusively malicious, "
            f"worth checking the context.",
        )

    if event.file_name and _double_extension_match(event.file_name):
        yield (
            "DOUBLE-EXTENSION-FILE",
            "Disguised executable (double file extension)",
            "high",
            f"Filename has a double extension ending in an executable type, a common way to "
            f"disguise malware as a document: {event.file_name}",
        )

    combined_path = " ".join(filter(None, [event.file_name, event.file_path])).lower()
    for pattern in _CREDENTIAL_ARTIFACT_PATTERNS:
        if pattern in combined_path:
            yield (
                "CREDENTIAL-ARTIFACT",
                "Credential-store artifact accessed or extracted",
                "high",
                f"File path matches a known credential-store artifact pattern ('{pattern}') - "
                f"commonly seen in credential dumping.",
            )
            break


def _aggregate_rules(events):
    """Rules that only make sense across many events, yielding
    (rule_id, rule_name, severity, description, representative_event).

    Separate from _rules_for_event because emitting one detection per
    matching packet is actively harmful here: a real directory brute-force
    is tens of thousands of requests, and reporting each one individually
    buries the single fact the investigator needs ("this host scanned that
    host") under 40,000 identical rows. These summarize instead, citing one
    representative event plus the totals.
    """
    tool_hits = {}  # (src_ip, tool) -> [count, first_event, sample_ua]
    path_probes = {}  # (src_ip, dst_ip) -> [set_of_paths, first_event, count]

    for event in events:
        if event.event_type != "http_request":
            continue
        raw = event.raw_event_reference or {}
        user_agent = raw.get("user_agent") or ""
        lowered_ua = user_agent.lower()
        for tool, purpose in _ATTACK_TOOL_USER_AGENTS.items():
            if tool in lowered_ua:
                entry = tool_hits.setdefault((event.src_ip, tool), [0, event, user_agent, purpose])
                entry[0] += 1
                break

        if event.url:
            entry = path_probes.setdefault((event.src_ip, event.dst_ip), [set(), event, 0])
            entry[0].add(event.url)
            entry[2] += 1

    for (src_ip, tool), (count, first_event, user_agent, purpose) in sorted(
        tool_hits.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])
    ):
        yield (
            "ATTACK-TOOL-USER-AGENT",
            "Offensive security tool identified by User-Agent",
            "high",
            f"{count} HTTP request(s) from {src_ip} carry a User-Agent identifying '{tool}', a tool "
            f"commonly used for {purpose} ({user_agent}). These tools are also used in authorized "
            f"testing - confirm whether this activity was sanctioned.",
            first_event,
        )

    for (src_ip, dst_ip), (paths, first_event, count) in sorted(
        path_probes.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))
    ):
        if len(paths) < _SCAN_DISTINCT_PATH_THRESHOLD:
            continue
        yield (
            "HTTP-PATH-ENUMERATION",
            "High-volume distinct URL requests (possible content discovery)",
            "high",
            f"{src_ip} requested {len(paths)} distinct URL paths from {dst_ip} across {count} "
            f"request(s) - a volume consistent with automated content discovery or directory "
            f"brute-forcing rather than ordinary browsing.",
            first_event,
        )


def scan_case(store):
    """Recompute every detection for the whole case (all events, not just
    newly parsed ones - same reasoning as correlation) and persist via
    CaseStore.replace_detections. Returns the list of detection dicts."""
    from datetime import datetime, timezone

    detected_at = datetime.now(timezone.utc)
    events = store.all_events()
    detections = []
    for event in events:
        for rule_id, rule_name, severity, description in _rules_for_event(event):
            detections.append(
                {
                    "detection_id": f"DET-{rule_id}-{event.event_id}",
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "severity": severity,
                    "event_id": event.event_id,
                    "evidence_id": event.evidence_id,
                    "description": description,
                    "detected_at": detected_at,
                }
            )

    for rule_id, rule_name, severity, description, event in _aggregate_rules(events):
        detections.append(
            {
                # Keyed by the representative event so re-running analyze on
                # unchanged evidence produces the same detection_id.
                "detection_id": f"DET-{rule_id}-{event.event_id}",
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "event_id": event.event_id,
                "evidence_id": event.evidence_id,
                "description": description,
                "detected_at": detected_at,
            }
        )

    store.replace_detections(detections)
    return detections
