"""The Lead Investigator: run the specialist roles over one case and merge
their cited findings into a single, ranked investigation.

The coordinator does no analysis of its own - that would be an ungrounded
opinion on top of grounded findings. It only:
  1. dispatches the requested roles (each already grounded, see base.run_role),
  2. merges findings that rest on the same evidence (two roles flagging the same
     event become one, corroborated finding), and
  3. ranks the result by severity and corroboration.

Every merged finding keeps the union of its citations and the list of roles that
reported it, so nothing loses its evidence trail.
"""

from dataclasses import dataclass, field
from typing import List

from pydantic import BaseModel

from netforensicai.agents.base import RoleResult, run_role
from netforensicai.agents.roles import all_roles

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _sev_rank(severity):
    return _SEVERITY_RANK.get(str(severity).lower(), 0)


class MergedFinding(BaseModel):
    """A finding after merging: the strongest statement of it, the union of the
    evidence it rests on, and every role that reported it."""

    title: str
    severity: str
    confidence: str
    assessment: str
    citations: list  # list[Citation], but kept loose to avoid a re-import cycle
    reported_by: List[str]


@dataclass
class TeamResult:
    """The whole team's output: each role's raw result, and the merged, ranked
    findings across all of them."""

    role_results: List[RoleResult] = field(default_factory=list)
    findings: List[MergedFinding] = field(default_factory=list)

    def to_dict(self):
        return {
            "role_results": [r.to_dict() for r in self.role_results],
            "findings": [f.model_dump() for f in self.findings],
        }


def _cite_keys(finding):
    return {(c.kind, c.evidence_id, str(c.reference)) for c in finding.citations}


def _merge_group(members):
    """One merged finding from a group of (role_slug, finding) that share
    evidence. The lead is the highest-severity member; severity/confidence take
    the strongest across the group; citations are unioned."""
    members = sorted(members, key=lambda m: _sev_rank(m[1].severity), reverse=True)
    lead_slug, lead = members[0]
    severity = max((m[1].severity for m in members), key=_sev_rank)
    confidence = max((m[1].confidence for m in members), key=lambda c: _SEVERITY_RANK.get(str(c).lower(), 0))

    reported_by = []
    for slug, _ in members:
        if slug not in reported_by:
            reported_by.append(slug)

    # Union the citations, de-duplicated on the (kind, evidence_id, reference) key.
    citations, seen = [], set()
    for _, finding in members:
        for c in finding.citations:
            key = (c.kind, c.evidence_id, str(c.reference))
            if key not in seen:
                seen.add(key)
                citations.append(c)

    if len(members) == 1:
        assessment = lead.assessment
    else:
        # Attribute each distinct assessment to the role(s) that made it.
        parts, seen_text = [], set()
        for slug, finding in members:
            text = finding.assessment.strip()
            if text and text not in seen_text:
                seen_text.add(text)
                parts.append(f"[{slug}] {text}")
        assessment = "  ".join(parts)

    return MergedFinding(
        title=lead.title,
        severity=severity,
        confidence=confidence,
        assessment=assessment,
        citations=citations,
        reported_by=reported_by,
    )


def merge_findings(role_results):
    """Group findings that share any citation, merge each group, and rank the
    result: most severe first, then most-corroborated (reported by more roles),
    then most evidence."""
    items = [(r.slug, f) for r in role_results for f in r.findings]

    groups = []  # each: [keys_set, [(slug, finding), ...]]
    for slug, finding in items:
        keys = _cite_keys(finding)
        target = next((g for g in groups if g[0] & keys), None)
        if target is not None:
            target[0] |= keys
            target[1].append((slug, finding))
        else:
            groups.append([set(keys), [(slug, finding)]])

    merged = [_merge_group(members) for _keys, members in groups]
    merged.sort(key=lambda f: (_sev_rank(f.severity), len(f.reported_by), len(f.citations)), reverse=True)
    return merged


def investigate(
    case_dir,
    roles=None,
    provider="anthropic",
    api_key=None,
    model=None,
    base_url=None,
    call_for=None,
):
    """Run `roles` (default: all registered roles) over `case_dir` and return a
    TeamResult with each role's findings and the merged, ranked set.

    `call_for(role) -> call` overrides the provider call per role, so the team
    can be tested against scripted model behaviour. In production it is None and
    each role uses the shared provider settings.
    """
    roles = roles if roles is not None else all_roles()
    role_results = []
    for role in roles:
        call = call_for(role) if call_for is not None else None
        role_results.append(
            run_role(role, case_dir, provider=provider, api_key=api_key, model=model, base_url=base_url, call=call)
        )
    return TeamResult(role_results=role_results, findings=merge_findings(role_results))
