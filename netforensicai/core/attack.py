"""MITRE ATT&CK technique mapping - a deterministic, rule-based layer that
suggests potential techniques from observed event patterns.

    Observed behavior -> Potential ATT&CK technique -> Evidence -> Analyst validation

Never claims "Event X = Technique Y" as fact. Every mapping is a
"potential" suggestion tied to specific evidence, with a confidence level
and a status the investigator explicitly sets (mirrors the Findings
model: the platform proposes, the investigator confirms or rejects).
Nothing here is AI-generated - these are fixed, auditable rules over the
Common Event Model, run the same deterministic way correlation is.

Deliberately a small starting set (four techniques) rather than an
exhaustive one: each rule below was chosen because the signal is specific
enough to be worth an investigator's attention on its own, not because
ATT&CK has hundreds of techniques to try to cover speculatively. Adding
more follows the same pattern - see CONTRIBUTING.md.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

T1059 = ("T1059", "Command and Scripting Interpreter")
T1059_001 = ("T1059.001", "Command and Scripting Interpreter: PowerShell")
T1027 = ("T1027", "Obfuscated Files or Information")
T1105 = ("T1105", "Ingress Tool Transfer")

# Interpreters other than PowerShell (which gets its own, more specific
# T1059.001 rule below) that count as generic script/command execution.
_GENERIC_INTERPRETERS = {"cmd.exe", "wscript.exe", "cscript.exe", "bash", "sh", "python.exe", "python", "python3"}

# Common PowerShell obfuscation/encoding flags - not exhaustive, just the
# well-known ones worth flagging on their own.
_ENCODING_INDICATORS = ("-enc ", "-encodedcommand", "-e ", "frombase64string")


def _rules_for_event(event):
    """Yield (technique_id, technique_name, confidence, basis) for every
    rule this one event matches. An event can match more than one rule
    (e.g. an encoded PowerShell command line matches both T1059.001 and
    T1027)."""
    if event.event_type == "process_start":
        combined = f"{event.process_name or ''} {event.command_line or ''}".lower()

        if "powershell" in combined:
            yield (
                *T1059_001,
                "medium",
                f"PowerShell process observed: {event.process_name or event.command_line}",
            )
            if event.command_line and any(ind in event.command_line.lower() for ind in _ENCODING_INDICATORS):
                yield (
                    *T1027,
                    "medium",
                    f"PowerShell command line contains an encoding/obfuscation indicator: {event.command_line}",
                )
        elif event.process_name and event.process_name.lower() in _GENERIC_INTERPRETERS:
            yield (*T1059, "low", f"Script/command interpreter process observed: {event.process_name}")

    elif event.event_type == "file_transfer":
        file_name = (event.file_name or "").lower()
        if file_name.endswith(".exe"):
            yield (*T1105, "medium", f"Executable file observed crossing the network: {event.file_name}")


def scan_case(store):
    """Run every rule over every event currently in `store`, upserting
    matches into attack_techniques/attack_technique_events.

    Like correlate_case(), always a full rescan rather than scoped to one
    evidence item, since a technique can be supported by events from more
    than one evidence source. An existing technique's investigator-set
    status is always preserved across rescans; only confidence and event
    links are refreshed. (Every current rule always yields the same fixed
    confidence for a given technique_id, so "last event wins" on refresh
    is equivalent to "only value possible" - a future rule with per-event
    variable confidence would need this upsert revisited to track a max
    rather than just overwrite.)

    Returns the list of (technique_id, technique_name) pairs touched.
    """
    now = datetime.now(timezone.utc)
    touched = {}

    for event in store.all_events():
        for technique_id, technique_name, confidence, basis in _rules_for_event(event):
            store.upsert_technique(technique_id, technique_name, confidence, now)
            store.link_technique_event(technique_id, event.event_id, event.evidence_id, basis)
            touched[technique_id] = technique_name

    return list(touched.items())
