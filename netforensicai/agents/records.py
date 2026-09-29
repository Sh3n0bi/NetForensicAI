"""What an investigation-team run leaves in the case: findings and custody.

save_merged_finding() turns a team finding into an investigator-owned Finding.
It is the one place that conversion lives, so `netforensic team --save-findings` and
the web UI's "Accept as finding" produce the same record. A team finding is a
proposal: it is always saved as **Open**, attributed to the person who accepted
it, and says in its assessment that the investigation team proposed it - never
Confirmed, which stays the investigator's call.
"""

from netforensicai.core import audit
from netforensicai.core.finding import FindingManager

# AgentFinding severities -> the investigator Finding scale. "Info" has no
# equivalent there; Low is the closest that still keeps it in view.
SEVERITY_TO_FINDING = {"high": "High", "medium": "Medium", "low": "Low", "info": "Low"}


def _field(citation, name):
    return citation.get(name) if isinstance(citation, dict) else getattr(citation, name)


def save_merged_finding(case_dir, case_id, case_manager, merged, author):
    """Create an Open Finding from one merged team finding and register it.

    `merged` is a MergedFinding or its dict form (as stored for the web UI).
    Event citations become evidence_refs; frame/stream/detection citations,
    which a Finding cannot reference structurally, are named in the
    assessment so nothing the team cited is lost. Raises FindingError.
    """
    if hasattr(merged, "model_dump"):
        merged = merged.model_dump()
    citations = merged.get("citations") or []
    event_refs = [
        {"evidence_id": _field(c, "evidence_id"), "event_id": str(_field(c, "reference"))}
        for c in citations
        if _field(c, "kind") == "event"
    ]
    other = [
        f"{_field(c, 'kind')} {_field(c, 'reference')} ({_field(c, 'evidence_id')})"
        for c in citations
        if _field(c, "kind") != "event"
    ]
    assessment = (
        f"{merged.get('assessment', '')}\n\n"
        f"Proposed by the investigation team ({', '.join(merged.get('reported_by') or [])}; "
        f"confidence {merged.get('confidence', 'unknown')}). Review before confirming."
        + (f"\nAlso cites: {'; '.join(other)}." if other else "")
    )
    finding = FindingManager(case_dir).create(
        case_id=case_id,
        title=merged.get("title") or "Investigation team finding",
        created_by=author,
        severity=SEVERITY_TO_FINDING.get(str(merged.get("severity", "")).lower(), "Medium"),
        status="Open",
        assessment=assessment,
        evidence_refs=event_refs,
    )
    case_manager.register_finding(case_id, finding.finding_id)
    return finding


def record_team_run(case_dir, result, provider, model, actor=None, error=None):
    """Append the run to the case's chain of custody.

    A team run sends case content to an AI provider, so - like `investigate
    --ai` - the request and its outcome belong in the custody record, failures
    included: they show an attempt was made. `result` is a TeamResult or its
    dict form; None when the run failed before producing one.
    """
    if result is not None and hasattr(result, "to_dict"):
        result = result.to_dict()
    roles = (result or {}).get("role_results") or []
    details = {
        "provider": provider,
        "model": model or "(provider default)",
        "roles_run": [r["slug"] for r in roles if not (r.get("note") or "").startswith("skipped")],
        "roles_skipped": [r["slug"] for r in roles if (r.get("note") or "").startswith("skipped")],
        "findings": len((result or {}).get("findings") or []),
        "outcome": "failed" if error else "completed",
    }
    if error:
        details["error"] = str(error)
    return audit.record(case_dir, audit.AI_TEAM_RUN, details, actor=actor)
