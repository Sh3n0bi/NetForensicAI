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

_CREDENTIAL_ARTIFACT_PATTERNS = (
    "system32\\config\\sam",
    "system32/config/sam",
    "ntds.dit",
    "lsass.dmp",
    "lsass.exe.dmp",
)


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
    return f".{second_ext}" in _EXECUTABLE_EXTENSIONS and first_ext not in ("", None)


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


def scan_case(store):
    """Recompute every detection for the whole case (all events, not just
    newly parsed ones - same reasoning as correlation) and persist via
    CaseStore.replace_detections. Returns the list of detection dicts."""
    from datetime import datetime, timezone

    detected_at = datetime.now(timezone.utc)
    detections = []
    for event in store.all_events():
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

    store.replace_detections(detections)
    return detections
