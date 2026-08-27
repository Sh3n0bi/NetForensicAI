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

Recording an action must never break the action itself: a failure to
append is logged and swallowed, because losing an audit line is bad but
losing the investigator's actual work is worse.
"""

import getpass
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

AUDIT_FILENAME = "audit.log"

GENESIS_HASH = "0" * 64

# Action names are stable identifiers, not prose - they are what someone
# greps or filters the log by, so they must not drift with wording changes.
CASE_CREATED = "case.created"
EVIDENCE_ADDED = "evidence.added"
EVIDENCE_PARSED = "evidence.parsed"
CASE_ANALYZED = "case.analyzed"
FINDING_CREATED = "finding.created"
FINDING_UPDATED = "finding.updated"
ATTACK_SCANNED = "attack.scanned"
ATTACK_UPDATED = "attack.updated"
REPORT_GENERATED = "report.generated"
THREAT_INTEL_CHECKED = "threat_intel.checked"
AI_HYPOTHESIS_REQUESTED = "ai.hypothesis_requested"
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
        return entry
    except Exception as e:
        # Never let auditing break the operation being audited.
        logger.warning(f"Could not record audit action '{action}' for {case_dir}: {e}")
        return None


def _default_actor():
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def verify(case_dir):
    """Check the hash chain end to end.

    Returns (ok, problems). `problems` names the first broken link and any
    later ones, so an investigator can say precisely which entries are
    trustworthy and from where the record stops being reliable.
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

    return (not problems), problems
