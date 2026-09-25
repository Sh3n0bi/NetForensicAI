"""Foundation for the investigation-team agents.

An agent is one *role*: a mission, a scoped subset of the read-only case tools
(core/chat.py's CaseTools), and a step budget. It runs over the same grounded
tool-loop the chat assistant uses, and produces **structured findings** instead
of free text. The grounding contract is unchanged and non-negotiable: every
finding must cite a tool result, and a finding that cites something no tool
returned is dropped - the citation ledger from core/chat.py enforces that
mechanically, so a role cannot invent a finding.

This module is the reusable substrate. The concrete roles (Network Forensics,
Host/DFIR, ...) live in roles.py; the coordinator that runs several and merges
their findings lives in coordinator.py.
"""

import json
from dataclasses import dataclass, field
from typing import List, Optional

from pydantic import BaseModel, ValidationError

from netforensicai.core import ai_assistant
from netforensicai.core.chat import (
    TOOL_SPECS,
    CaseTools,
    Citation,
    Ledger,
    _render,
    _run_tool,
)

DEFAULT_ROLE_STEPS = 6

SEVERITIES = ("High", "Medium", "Low", "Info")


class AgentError(Exception):
    """Raised when a role cannot be run at all (bad configuration)."""


class AgentFinding(BaseModel):
    """One structured, evidence-cited finding from a role. Shaped to drop
    straight onto the investigator-owned Finding model for one-click
    acceptance."""

    title: str
    severity: str = "Medium"
    assessment: str
    confidence: str = "medium"  # high | medium | low
    citations: List[Citation] = []


@dataclass
class Role:
    """A specialist analyst: a name, the mission that scopes its prompt, the
    tool names it may call (a subset of TOOL_SPECS), and a step budget."""

    name: str
    slug: str
    mission: str
    tools: tuple
    max_steps: int = DEFAULT_ROLE_STEPS

    def __post_init__(self):
        unknown = [t for t in self.tools if t not in TOOL_SPECS]
        if unknown:
            raise AgentError(f"Role {self.slug!r} lists unknown tools: {unknown}")

    def catalogue(self):
        return "\n".join(f"- {name}: {TOOL_SPECS[name]}" for name in self.tools)


@dataclass
class RoleResult:
    """What a role hands back: its cited findings, the tool calls it made, and
    a note when it found nothing or could not run."""

    role: str
    slug: str
    findings: List[AgentFinding] = field(default_factory=list)
    tool_calls: list = field(default_factory=list)
    note: Optional[str] = None

    def to_dict(self):
        return {
            "role": self.role,
            "slug": self.slug,
            "findings": [f.model_dump() for f in self.findings],
            "tool_calls": self.tool_calls,
            "note": self.note,
        }


# The protocol the model must speak. Identical grounding rules and citation
# shape to core/chat.py's SYSTEM_PROMPT - the only difference is the answer
# form, which here is a list of findings instead of one free-text answer.
_PROTOCOL = """Reply with a single JSON object and nothing else. Two forms are allowed.

To call a tool:
{"action": "tool", "tool": "<tool name>", "arguments": {...}}

To report your findings (your final reply):
{"action": "findings", "findings": [
  {"title": "<short>", "severity": "High|Medium|Low|Info", "confidence": "high|medium|low",
   "assessment": "<what the evidence shows and what you infer, kept separate>",
   "citations": [{"kind": "event|frame|stream|detection", "evidence_id": "EV-0001", "reference": "..."}]}
]}

Rules that decide whether a finding is usable:
- Cite ONLY facts a tool returned in this conversation. A finding citing an event, frame, stream or
  detection that no tool returned is DROPPED. A finding with no citations is dropped.
- "reference" is the exact identifier from the tool output: an event_id for kind=event, a frame
  number for kind=frame, a stream index for kind=stream, a rule id for kind=detection.
- Separate what the evidence shows from what you infer. Phrase inference as possibility
  ("may indicate", "is consistent with"), never as certainty.
- Prefer the case's own detections and entities; interpret them, do not invent new ones.
- If you find nothing in your scope, return {"action": "findings", "findings": []}. That is a
  correct result, not a failure. Do not guess to fill the list.
- Retrieve before you report. You have a limited number of tool calls."""


def _system_prompt(role):
    return (
        f"You are the {role.name} analyst on a digital forensics and incident response (DFIR) "
        f"investigation team examining ONE case. You cannot see the evidence directly; you retrieve "
        f"it with tools and may only claim what those tools return.\n\n"
        f"Your focus: {role.mission}\n\n"
        f"{_PROTOCOL}\n\n"
        f"You are not the investigator. Your findings are a starting point for their review."
    )


def _validate_findings(raw_findings, ledger):
    """Keep only well-formed findings whose citations were all actually
    retrieved (checked against the ledger, exactly as chat.py checks an
    answer). Returns (kept_findings, dropped_count)."""
    kept, dropped = [], 0
    for item in raw_findings or []:
        try:
            finding = AgentFinding.model_validate(item)
        except ValidationError:
            dropped += 1
            continue
        if not finding.citations:
            dropped += 1
            continue
        if all(ledger.contains(c) for c in finding.citations):
            kept.append(finding)
        else:
            dropped += 1
    return kept, dropped


def run_role(role, case_dir, provider="anthropic", api_key=None, model=None, base_url=None, call=None):
    """Run one role over `case_dir` and return its cited findings.

    `call(system_prompt, user_prompt) -> dict` overrides the provider call, so
    the loop can be tested against scripted model behaviour - including a model
    that cites evidence no tool returned, which must be dropped.
    """
    if call is None:

        def call(system_prompt, user_prompt):
            return ai_assistant.call_model(
                system_prompt, user_prompt, provider=provider, api_key=api_key, model=model, base_url=base_url
            )

    ledger = Ledger()
    tools = CaseTools(case_dir, ledger)
    system_prompt = _system_prompt(role)
    transcript = [f"Case directory: {case_dir}", f"Tools available to you:\n{role.catalogue()}"]
    tool_calls = []

    for step in range(role.max_steps):
        remaining = role.max_steps - step
        prompt = "\n\n".join(transcript) + (
            f"\n\nYou have {remaining} tool call(s) left before you must report findings."
            if remaining > 1
            else "\n\nThis is your LAST turn. Report findings now from what you already retrieved."
        )

        try:
            raw = call(system_prompt, prompt)
        except Exception as e:
            return RoleResult(role.name, role.slug, note=f"provider failed: {e}")

        if not isinstance(raw, dict):
            transcript.append('Your reply was not a JSON object. Reply with one JSON object.')
            continue

        action = raw.get("action")

        if action == "tool":
            name = raw.get("tool")
            arguments = raw.get("arguments") or {}
            if name not in role.tools:
                transcript.append(
                    f"Tool {name!r} is outside your scope. You may only call: {', '.join(role.tools)}."
                )
                continue
            try:
                result = _run_tool(tools, name, arguments)
                rows = len(result) if isinstance(result, list) else 1
                tool_calls.append({"tool": name, "arguments": arguments, "rows": rows})
                transcript.append(
                    f"You called {name}({json.dumps(arguments, default=str)}).\nResult:\n{_render(result)}"
                )
            except Exception as e:
                tool_calls.append({"tool": str(name), "arguments": arguments, "error": str(e)})
                transcript.append(f"You called {name}({json.dumps(arguments, default=str)}).\nError: {e}")
            continue

        if action == "findings":
            kept, dropped = _validate_findings(raw.get("findings"), ledger)
            note = None
            if not kept:
                note = "no findings in scope" if not dropped else "all proposed findings were unciteable and dropped"
            elif dropped:
                note = f"{dropped} proposed finding(s) dropped as unciteable"
            return RoleResult(role.name, role.slug, findings=kept, tool_calls=tool_calls, note=note)

        transcript.append(
            'Your reply had no valid "action". Reply with {"action":"tool",...} or {"action":"findings",...}.'
        )

    return RoleResult(role.name, role.slug, tool_calls=tool_calls, note="no findings within the step budget")
