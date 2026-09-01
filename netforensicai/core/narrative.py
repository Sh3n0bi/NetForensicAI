"""The case, told as an account of what happened.

Everything else in this platform produces *evidence*: normalized events,
extracted entities, correlation links, detections. All of it is true and
none of it is a story. An investigator handed 81 events, 63 entities and
15 detections still has to work out the order things happened in, which
of them are the same incident, and which sentence to put in front of a
CISO. That last mile is where the work actually is, and leaving it to the
human is what makes the tool feel like a haystack with better indexing.

This module assembles the account. It is DELIBERATELY DETERMINISTIC - no
model, no network, no scoring that cannot be explained. A narrative that
goes into an incident report has to be reproducible by whoever reads it,
and "the language model said so" is not a chain of custody. The AI
assistant remains available to interpret the narrative; it is not
permitted to write it.

The shape is three layers, each strictly derived from the one below:

  BEATS        one per detection, grouped so that eight identical
               rule matches on one domain are a single beat rather than
               eight lines, and ordered by when they happened.
  PHASES       beats bucketed into the stages of an intrusion, so a
               reader sees "delivery, then credential access, then
               exfiltration" instead of a flat list.
  ASSESSMENT   the highest-severity story the beats support, stated in
               one sentence, with the count of what it rests on.

Every beat carries the event and evidence ids it came from, so every
sentence in the summary can be walked back to a packet. Nothing here
invents a fact that is not in a detection or an event.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# The stages of an intrusion, in the order a reader expects them. Each
# detection rule is mapped to the stage it evidences; the order here is
# the order phases appear in the narrative, NOT a claim that an
# investigation must find all of them or find them in sequence.
PHASES = (
    ("reconnaissance", "Reconnaissance and infrastructure"),
    ("delivery", "Delivery"),
    ("credential-access", "Credential access"),
    ("collection", "Collection and staging"),
    ("exfiltration", "Exfiltration"),
    ("command-and-control", "Command and control"),
    ("other", "Other observations"),
)

RULE_PHASE = {
    "SUSPICIOUS-TLD": "reconnaissance",
    "HTTP-PATH-ENUMERATION": "reconnaissance",
    "SCAN-SUCCESSFUL-PATHS": "reconnaissance",
    "ATTACK-TOOL-USER-AGENT": "reconnaissance",
    "SQL-INJECTION-ATTEMPT": "delivery",
    "EXECUTABLE-DOWNLOAD": "delivery",
    "DOUBLE-EXTENSION-FILE": "delivery",
    "OFFENSIVE-TOOL-NAME": "credential-access",
    "CLEARTEXT-CREDENTIALS": "credential-access",
    "CREDENTIAL-REUSE": "credential-access",
    "CREDENTIAL-ARTIFACT": "credential-access",
    "KEY-MATERIAL-IN-TRANSIT": "collection",
    "OUTBOUND-BULK-TRANSFER": "exfiltration",
    "PERIODIC-BEACON": "command-and-control",
    "SUSPICIOUS-PORT": "command-and-control",
}

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

# An assessment is only as strong as the phases it rests on. These are
# read in order and the first whose condition holds is used, so the
# strongest supported statement wins - and each says what it rests on
# rather than asserting a conclusion the evidence does not carry.
ASSESSMENTS = (
    (
        ("exfiltration", "credential-access"),
        "critical",
        "Evidence is consistent with data leaving this network after a credential was exposed.",
    ),
    (
        ("exfiltration",),
        "high",
        "A substantial volume of data was sent to an external host.",
    ),
    (
        ("credential-access", "command-and-control"),
        "critical",
        "A credential was exposed on a host that is also in regular contact with external "
        "infrastructure.",
    ),
    (
        ("credential-access",),
        "high",
        "One or more credentials crossed the network where they could be read.",
    ),
    (
        ("command-and-control",),
        "high",
        "A host is in machine-regular contact with external infrastructure.",
    ),
    (
        ("delivery",),
        "medium",
        "Something executable or attacker-supplied reached a host on this network.",
    ),
    (
        ("reconnaissance",),
        "low",
        "Activity worth reviewing was observed, but nothing that shows access was gained.",
    ),
)


@dataclass
class Beat:
    """One thing that happened, with the evidence it rests on."""

    rule_id: str
    title: str
    severity: str
    phase: str
    description: str
    first_seen: Optional[object]
    occurrences: int
    event_ids: list = field(default_factory=list)
    evidence_ids: list = field(default_factory=list)
    hosts: list = field(default_factory=list)

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "phase": self.phase,
            "description": self.description,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "occurrences": self.occurrences,
            "event_ids": self.event_ids[:10],
            "evidence_ids": sorted(set(self.evidence_ids)),
            "hosts": self.hosts,
        }


@dataclass
class Narrative:
    assessment: str
    severity: str
    headline: str
    beats: list = field(default_factory=list)
    phases: list = field(default_factory=list)
    subjects: list = field(default_factory=list)
    window: tuple = (None, None)

    def to_dict(self):
        return {
            "assessment": self.assessment,
            "severity": self.severity,
            "headline": self.headline,
            "subjects": self.subjects,
            "window": [t.isoformat() if t else None for t in self.window],
            "phases": [
                {"phase": key, "title": title, "beats": [b.to_dict() for b in beats]}
                for key, title, beats in self.phases
            ],
        }


def _host_of(event):
    """The internal side of a flow, which is the host the story is about.

    Falls back to the source when neither side is private - an
    external-to-external flow is unusual enough that naming the source is
    more useful than naming nothing.
    """
    import ipaddress

    def private(address):
        try:
            parsed = ipaddress.ip_address(str(address))
            return parsed.is_private or parsed.is_loopback
        except (ValueError, TypeError):
            return False

    if private(event.src_ip):
        return event.src_ip
    if private(event.dst_ip):
        return event.dst_ip
    return event.src_ip


def build(store):
    """Assemble the case narrative from its detections and events.

    Returns a Narrative. A case with no detections still produces one -
    saying so plainly is more useful than an empty object, because "we
    looked and found nothing that matched" is itself a finding.
    """
    detections = store.list_detections()
    events = {}
    for detection in detections:
        event_id = detection.get("event_id")
        if event_id and event_id not in events:
            event = store.get_event(event_id)
            if event is not None:
                events[event_id] = event

    # One beat per rule, not per match: eight SUSPICIOUS-TLD rows for the
    # same domain are one thing that happened, and listing them eight
    # times is how a report becomes unreadable.
    grouped = defaultdict(list)
    for detection in detections:
        grouped[detection["rule_id"]].append(detection)

    beats = []
    for rule_id, matches in grouped.items():
        stamped = [events.get(m.get("event_id")) for m in matches]
        stamped = [e for e in stamped if e is not None]
        times = sorted(e.timestamp for e in stamped if e.timestamp)
        hosts = sorted({_host_of(e) for e in stamped if _host_of(e)})
        severity = max((m["severity"] for m in matches), key=lambda s: SEVERITY_RANK.get(s, 0))
        # The longest description is the most specific one - aggregate
        # rules state totals the per-event ones do not.
        description = max((m["description"] for m in matches), key=len)
        beats.append(
            Beat(
                rule_id=rule_id,
                title=matches[0]["rule_name"],
                severity=severity,
                phase=RULE_PHASE.get(rule_id, "other"),
                description=description,
                first_seen=times[0] if times else None,
                occurrences=len(matches),
                event_ids=[m["event_id"] for m in matches if m.get("event_id")],
                evidence_ids=[m["evidence_id"] for m in matches if m.get("evidence_id")],
                hosts=hosts,
            )
        )

    # Chronological, with undated beats last rather than first: a beat
    # with no timestamp is not "the beginning of the story".
    beats.sort(key=lambda b: (b.first_seen is None, b.first_seen))

    phases = []
    for key, title in PHASES:
        in_phase = [b for b in beats if b.phase == key]
        if in_phase:
            phases.append((key, title, in_phase))

    present = {key for key, _title, _beats in phases}
    assessment, severity = _assess(present, beats)

    subjects = sorted({host for beat in beats for host in beat.hosts})
    times = [b.first_seen for b in beats if b.first_seen]

    return Narrative(
        assessment=assessment,
        severity=severity,
        headline=_headline(beats, subjects, severity),
        beats=beats,
        phases=phases,
        subjects=subjects,
        window=(min(times) if times else None, max(times) if times else None),
    )


def _assess(present, beats):
    if not beats:
        return (
            "No bundled detection rule matched this evidence. That is not the same as "
            "'nothing happened' - it means nothing matched the rules that exist.",
            "none",
        )
    for required, severity, statement in ASSESSMENTS:
        if all(phase in present for phase in required):
            return statement, severity
    return "Activity was observed that did not fit a known pattern.", "low"


def _headline(beats, subjects, severity):
    """One sentence naming what happened, to whom, and how much of it.

    Deliberately counts rather than characterizes: "4 high-severity
    findings across 2 hosts" is checkable, where "a serious compromise"
    is an opinion the evidence may not carry.
    """
    if not beats:
        return "No detections."
    high = sum(1 for b in beats if b.severity == "high")
    host_text = (
        f"{len(subjects)} host{'s' if len(subjects) != 1 else ''}" if subjects else "this capture"
    )
    return (
        f"{len(beats)} distinct finding{'s' if len(beats) != 1 else ''} "
        f"({high} high severity) across {host_text}."
    )


def render_text(narrative, width=88):
    """The narrative as plain text, for the CLI and the report."""
    lines = []
    lines.append(narrative.headline)
    lines.append("")
    lines.append(f"Assessment [{narrative.severity}]: {narrative.assessment}")
    start, end = narrative.window
    if start:
        lines.append(f"Window: {start.isoformat()} to {end.isoformat()}")
    if narrative.subjects:
        lines.append(f"Hosts: {', '.join(narrative.subjects)}")
    lines.append("")

    for _key, title, beats in narrative.phases:
        lines.append(f"{title.upper()}")
        for beat in beats:
            when = beat.first_seen.isoformat().replace("T", " ")[:19] if beat.first_seen else "unknown time"
            repeat = f" (x{beat.occurrences})" if beat.occurrences > 1 else ""
            lines.append(f"  [{beat.severity}] {when}  {beat.title}{repeat}")
            for chunk in _wrap(beat.description, width - 6):
                lines.append(f"      {chunk}")
            if beat.event_ids:
                lines.append(f"      evidence: {', '.join(beat.event_ids[:3])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _wrap(text, width):
    words = str(text).split()
    line, out = "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out
