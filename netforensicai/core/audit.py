"""Chain of custody: an append-only, tamper-evident record of every action
taken on a case.

Evidence integrity (core/evidence.py) answers "is this file unchanged?".
This answers the other half a forensic process needs: "who did what to this
case, when, and in what order?" - the question asked when findings are
challenged, and the reason a case can be handed to another investigator or
presented as the basis for a conclusion.

Stored as JSON Lines at cases/<CASE-ID>/audit.log, one entry per line,
appended and never rewritten. JSONL specifically because a partial write
(power loss, killed process) costs at most the final line rather than
corrupting the whole document, and because it can be read incrementally.

Each entry carries the SHA-256 of the previous entry, forming a hash
chain. That makes silent tampering detectable: editing or deleting any
entry breaks every link after it, and verify() reports exactly where. It
is deliberately NOT a security control against an attacker who owns the
machine - such an attacker can recompute the whole chain. It detects
accidental corruption and casual after-the-fact editing, which is what a
local single-investigator tool can honestly claim.

A hash chain alone cannot see its own tail being cut off: deleting the newest
entries leaves a shorter chain that is still internally consistent. Two
things close that gap, both with the same honest limits as above:

* audit.head, a small file rewritten after every append, records the newest
  entry's sequence number and hash. verify() compares the log against it,
  so truncation (or emptying the log) is reported rather than passing as a
  valid shorter chain. Someone who can edit both files can still defeat it.
* `--expect-head` / verify(expected_head=...) checks a hash the investigator
  wrote down OUTSIDE the case (a ticket, a notebook, an email) when they
  last handled it. That is the only check an attacker with disk access
  cannot recompute, because the reference value is not on the disk.

Recording an action must never break the action itself: a failure to
append is logged and swallowed, because losing an audit line is bad but
losing the investigator's actual work is worse.
"""

import getpass
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

AUDIT_FILENAME = "audit.log"
HEAD_FILENAME = "audit.head"

GENESIS_HASH = "0" * 64

# Shortest prefix of a noted hash that --expect-head will accept. Short
# enough to copy by hand, long enough that a chance match is not plausible.
MIN_EXPECTED_HEAD_CHARS = 12

# Returned by read_head() when audit.head exists but cannot be parsed - kept
# distinct from "no head file", which is normal for a case that predates it.
_HEAD_UNREADABLE = object()

# Action names are stable identifiers, not prose - they are what someone
# greps or filters the log by, so they must not drift with wording changes.
CASE_CREATED = "case.created"
EVIDENCE_ADDED = "evidence.added"
EVIDENCE_PARSED = "evidence.parsed"
# A stored evidence file was re-hashed and compared with the SHA-256 recorded
# at ingest. EVIDENCE_VERIFIED is an explicit `evidence verify` run;
# EVIDENCE_INTEGRITY_FAILED is a mismatch found by any command, including the
# automatic check before parsing, so a failure is on the record either way.
EVIDENCE_VERIFIED = "evidence.verified"
EVIDENCE_INTEGRITY_FAILED = "evidence.integrity_failed"
# A capture carved out of another capture by a Wireshark display
# filter. Recorded separately from evidence.added because a derived
# artifact has to name its parent and the exact filter that produced
# it, or it cannot be reproduced from the original.
EVIDENCE_SLICED = "evidence.sliced"
CASE_ANALYZED = "case.analyzed"
FINDING_CREATED = "finding.created"
FINDING_UPDATED = "finding.updated"
ATTACK_SCANNED = "attack.scanned"
ATTACK_UPDATED = "attack.updated"
REPORT_GENERATED = "report.generated"
THREAT_INTEL_CHECKED = "threat_intel.checked"
IOC_IMPORTED = "ioc.imported"
IOC_CLEARED = "ioc.cleared"
AI_HYPOTHESIS_REQUESTED = "ai.hypothesis_requested"
AI_TEAM_RUN = "ai.team_run"
AI_CHAT_REQUESTED = "ai.chat_requested"
ARTIFACT_EXPORTED = "artifact.exported"
STREAM_EXPORTED = "stream.exported"
CAPTURE_STARTED = "capture.started"
CAPTURE_STOPPED = "capture.stopped"
CASE_EXPORTED = "case.exported"
CASE_IMPORTED = "case.imported"


def _entry_hash(entry):
    """Hash of an entry's content, excluding its own hash field. Keys are
    sorted so the digest depends on content rather than dict ordering."""
    payload = {key: value for key, value in entry.items() if key != "entry_hash"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def audit_path(case_dir):
    return Path(case_dir) / AUDIT_FILENAME


def head_path(case_dir):
    return Path(case_dir) / HEAD_FILENAME


def _write_head(case_dir, entry):
    """Record the newest entry's sequence and hash. Written to a temp file and
    renamed into place so a crash never leaves a half-written head."""
    path = head_path(case_dir)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(
        json.dumps({"sequence": entry["sequence"], "entry_hash": entry["entry_hash"]}, sort_keys=True),
        encoding="utf-8",
    )
    os.replace(temp, path)


def read_head(case_dir):
    """The recorded head as {"sequence", "entry_hash"}; None when there is no
    head file (a case that predates it); _HEAD_UNREADABLE when it is damaged."""
    path = head_path(case_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _HEAD_UNREADABLE
    if not isinstance(data, dict) or not isinstance(data.get("sequence"), int) or not isinstance(data.get("entry_hash"), str):
        return _HEAD_UNREADABLE
    return data


def latest(case_dir):
    """(sequence, entry_hash) of the newest entry in the log itself, or None
    for an empty log. This is the value worth noting outside the case."""
    entries = read_entries(case_dir)
    if not entries:
        return None
    return len(entries), entries[-1].get("entry_hash", GENESIS_HASH)


def read_entries(case_dir):
    """Return every audit entry, oldest first. Unreadable lines are skipped
    with a warning rather than raising - a damaged audit log must still
    surface whatever it can, and verify() is what reports the damage."""
    path = audit_path(case_dir)
    if not path.exists():
        return []
    entries = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as e:
            logger.warning(f"Skipping unreadable audit entry at {path}:{line_number}: {e}")
    return entries


def record(case_dir, action, details=None, actor=None):
    """Append one action to the case's chain of custody. Returns the written
    entry, or None if it could not be written."""
    case_dir = Path(case_dir)
    try:
        previous = read_entries(case_dir)
        previous_hash = previous[-1].get("entry_hash", GENESIS_HASH) if previous else GENESIS_HASH

        entry = {
            "sequence": len(previous) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor or _default_actor(),
            "action": action,
            "details": details or {},
            "previous_hash": previous_hash,
        }
        entry["entry_hash"] = _entry_hash(entry)

        case_dir.mkdir(parents=True, exist_ok=True)
        with open(audit_path(case_dir), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception as e:
        # Never let auditing break the operation being audited.
        logger.warning(f"Could not record audit action '{action}' for {case_dir}: {e}")
        return None

    # Separate from the append above: the entry IS recorded at this point, so a
    # failure here must not report it as lost. verify() tolerates a head that
    # lags the log by one or more entries (a crash between the two writes).
    try:
        _write_head(case_dir, entry)
    except Exception as e:
        logger.warning(f"Recorded audit action '{action}' for {case_dir} but could not update {HEAD_FILENAME}: {e}")
    return entry


def _default_actor():
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _check_head(entries, head):
    """Problems found by comparing the log against audit.head."""
    if head is None:
        return []  # a case that predates the head file: nothing to compare against
    if head is _HEAD_UNREADABLE:
        return [f"{HEAD_FILENAME} exists but cannot be read - the tail of the log cannot be checked"]

    recorded = head["sequence"]
    if not entries:
        return [f"the log is empty but {HEAD_FILENAME} records {recorded} entr(ies) - the log was emptied or removed"]
    if recorded > len(entries):
        missing = recorded - len(entries)
        return [
            f"the log is truncated: {HEAD_FILENAME} records {recorded} entries but only {len(entries)} are "
            f"present - the newest {missing} entr(ies) are missing"
        ]
    # recorded <= len(entries): equal is the normal case; a head that lags (a crash
    # between appending and updating it) is fine as long as it still matches.
    anchor = entries[recorded - 1] if recorded >= 1 else None
    if anchor is not None and anchor.get("entry_hash") != head["entry_hash"]:
        return [f"entry {recorded} does not match the hash {HEAD_FILENAME} recorded for it - the log was rewritten"]
    return []


def _check_expected_head(entries, expected_head):
    """Problems found by checking a hash the investigator noted outside the case."""
    expected = expected_head.strip().lower()
    if len(expected) < MIN_EXPECTED_HEAD_CHARS or any(c not in "0123456789abcdef" for c in expected):
        return [f"--expect-head needs at least {MIN_EXPECTED_HEAD_CHARS} hexadecimal characters of a noted hash"]
    if any(str(entry.get("entry_hash", "")).startswith(expected) for entry in entries):
        return []  # that point is still in the chain, so nothing up to it was cut or changed
    return [
        f"the hash you noted ({expected[:16]}...) is not in the log - entries up to that point were "
        f"removed or altered since you noted it"
    ]


def verify(case_dir, expected_head=None):
    """Check the hash chain end to end.

    Returns (ok, problems). `problems` names the first broken link and any
    later ones, so an investigator can say precisely which entries are
    trustworthy and from where the record stops being reliable.

    The chain is also checked against audit.head, which catches the newest
    entries having been deleted. `expected_head` is a hash (or its first 12+
    characters) noted outside the case; when given, it must still appear in
    the chain.
    """
    entries = read_entries(case_dir)
    problems = []
    expected_previous = GENESIS_HASH

    for index, entry in enumerate(entries, start=1):
        recorded_hash = entry.get("entry_hash")
        if _entry_hash(entry) != recorded_hash:
            problems.append(
                f"entry {index} (sequence {entry.get('sequence', '?')}, "
                f"action '{entry.get('action', '?')}') has been modified since it was written"
            )
        if entry.get("previous_hash") != expected_previous:
            problems.append(
                f"entry {index} (sequence {entry.get('sequence', '?')}) does not follow the "
                f"preceding entry - an entry may have been inserted or removed before it"
            )
        expected_previous = recorded_hash or GENESIS_HASH

    problems.extend(_check_head(entries, read_head(case_dir)))
    if expected_head:
        problems.extend(_check_expected_head(entries, expected_head))

    return (not problems), problems
