"""Conversational investigation: ask a question about a case, and get an
answer in which every claim is checked against evidence the model
actually retrieved.

The single-shot assistant (core/ai_assistant.py) is handed a fixed set of
events and returns one hedged hypothesis about them. That is the right
shape for "interpret this selection", and the wrong shape for "what
happened here" - a question whose answer depends on evidence nobody has
selected yet. Chat closes that gap by letting the model RETRIEVE, through
a fixed set of read-only tools, and then holds the retrieved results as
the only thing it is allowed to claim anything about.

THE CITATION LEDGER IS THE SAFETY PROPERTY.

Every tool call appends the facts it returned - event ids, frame numbers,
stream indexes, detection rule ids - to a ledger. The final answer must
cite from that ledger and nothing else. A citation that is not in it means
the model produced a reference no tool ever returned, which is the
signature of an invented fact; the answer is sent back once with that
citation named, and if it comes back unverifiable again the whole answer
is REFUSED rather than shown with a warning. A forensics tool that
displays an unverifiable claim has already failed, however it is labelled.

This is the same contract the single-shot assistant enforces, moved to
where a retrieving model needs it: there, citations are checked against
the events the investigator supplied; here, against the results the tools
produced.

WHY A JSON LOOP RATHER THAN NATIVE TOOL-CALLING.

Four providers are supported (Anthropic, OpenAI, Ollama, Gemini) and each
expresses tool use differently. Implementing four native integrations
would put the safety-critical path in four places and make Ollama - the
fully local option, and the only one that keeps an investigation entirely
off the network - the worst-supported. So the loop is expressed in JSON
the model returns, through the one provider call every feature shares.
The transport is not what makes this safe; the ledger is.

Nothing here writes to the case. Every tool is read-only, no tool creates
a finding, and answering a question is not an action taken on evidence.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import List, Literal, Optional

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

# How many tool calls one question may make before the model is required
# to answer with what it has. Bounds cost and wall time, and stops a model
# that cannot find something from searching forever.
MAX_STEPS = 8

# Per-tool result caps. The whole transcript is resent on every step, so
# an unbounded result would grow the prompt quadratically.
MAX_ROWS = 25
MAX_CHARS_PER_RESULT = 6000

SYSTEM_PROMPT = """You are helping a digital forensics and incident response (DFIR) investigator
examine ONE case. You cannot see the evidence directly. You retrieve it by calling tools, and you may
only make claims about what those tools actually returned to you.

Reply with a single JSON object and nothing else. Two forms are allowed.

To call a tool:
{"action": "tool", "tool": "<tool name>", "arguments": {...}}

To answer:
{"action": "answer", "evidence_sufficient": true|false, "answer": "<your answer>",
 "citations": [{"kind": "event|frame|stream|detection", "evidence_id": "EV-0001", "reference": "..."}]}

Rules that decide whether your answer is usable:
- Cite ONLY facts a tool returned in this conversation. A citation naming an event, frame, stream or
  detection that no tool returned makes the entire answer unusable and it will be discarded.
- "reference" is the exact identifier from the tool output: an event_id for kind=event, a frame number
  for kind=frame, a stream index for kind=stream, a rule id for kind=detection.
- Separate what the evidence shows from what you infer from it. Phrase inference as possibility
  ("may indicate", "is consistent with"), never as certainty.
- If the tools do not give you enough to answer, set evidence_sufficient to false and say what is
  missing. That is a correct answer, not a failure. Do not guess.
- Prefer retrieving before answering. You have a limited number of tool calls; use them.

You are not the investigator. Your answer is a starting point for their own review."""


class ChatError(Exception):
    """Raised when a question cannot be answered safely: a provider
    failure, a malformed response, or an answer whose citations could not
    be verified against retrieved evidence."""


class Citation(BaseModel):
    kind: Literal["event", "frame", "stream", "detection"]
    evidence_id: str
    reference: str


class Answer(BaseModel):
    evidence_sufficient: bool
    answer: str
    citations: List[Citation] = []


@dataclass
class ToolCall:
    tool: str
    arguments: dict
    summary: str
    rows: int = 0
    error: Optional[str] = None

    def to_dict(self):
        return {
            "tool": self.tool,
            "arguments": self.arguments,
            "summary": self.summary,
            "rows": self.rows,
            "error": self.error,
        }


@dataclass
class ChatResult:
    question: str
    answer: str
    evidence_sufficient: bool
    citations: list = field(default_factory=list)
    steps: list = field(default_factory=list)

    def to_dict(self):
        return {
            "question": self.question,
            "answer": self.answer,
            "evidence_sufficient": self.evidence_sufficient,
            "citations": [c.model_dump() for c in self.citations],
            "steps": [s.to_dict() for s in self.steps],
        }


class Ledger:
    """What the tools actually returned, and therefore what may be cited.

    Kept as sets of (evidence_id, reference) pairs rather than as free
    text so verification is an exact membership test. Anything fuzzier -
    "does this identifier appear somewhere in the transcript" - would
    accept a model quoting an id back out of its own earlier reasoning,
    which is exactly the failure being guarded against.
    """

    def __init__(self):
        self._facts = {"event": set(), "frame": set(), "stream": set(), "detection": set()}

    def record(self, kind, evidence_id, reference):
        if reference is None or evidence_id is None:
            return
        self._facts[kind].add((str(evidence_id), str(reference)))

    def contains(self, citation):
        return (citation.evidence_id, citation.reference) in self._facts[citation.kind]

    def is_empty(self):
        return not any(self._facts.values())

    def counts(self):
        return {kind: len(values) for kind, values in self._facts.items()}


class CaseTools:
    """The read-only surface a chat session may use.

    Deliberately small and explicit. Each method returns rows AND records
    what it returned in the ledger, so there is no way to surface a fact
    to the model without simultaneously making it citable - the two cannot
    drift apart because they happen in the same place.
    """

    def __init__(self, case_dir, ledger, max_rows=MAX_ROWS):
        self.case_dir = case_dir
        self.ledger = ledger
        self.max_rows = max_rows

    # -- helpers --

    def _captures(self):
        from netforensicai.core.evidence import EvidenceManager

        manager = EvidenceManager(self.case_dir)
        return manager, [item for item in manager.list() if item.evidence_type == "pcap"]

    def _resolve_capture(self, evidence_id=None):
        manager, captures = self._captures()
        if not captures:
            raise ChatError("This case has no capture evidence.")
        if evidence_id:
            for item in captures:
                if item.evidence_id == evidence_id:
                    return item, manager.stored_file_path(item.evidence_id)
            raise ChatError(f"No capture evidence {evidence_id} in this case.")
        return captures[0], manager.stored_file_path(captures[0].evidence_id)

    # -- tools --

    def list_evidence(self):
        manager, _ = self._captures()
        rows = [
            {
                "evidence_id": item.evidence_id,
                "filename": item.filename,
                "type": item.evidence_type,
                "size_bytes": item.size_bytes,
            }
            for item in manager.list()
        ]
        return rows

    def search_events(
        self, event_type=None, ip=None, user=None, hostname=None, process=None, file=None, limit=MAX_ROWS
    ):
        """Normalized events from the case store, optionally filtered.

        The filters mirror filter_timeline's exactly. Offering the model a
        filter the timeline does not implement would mean silently
        returning unfiltered results, which it would then reason about as
        though they were filtered.
        """
        from netforensicai.core.store import CaseStore
        from netforensicai.core.timeline import build_timeline, filter_timeline

        with CaseStore(self.case_dir) as store:
            entries = build_timeline(store)
        entries = filter_timeline(
            entries,
            event_type=event_type,
            ip=ip,
            user=user,
            hostname=hostname,
            process=process,
            file=file,
        )

        rows = []
        for entry in entries[: min(int(limit or self.max_rows), self.max_rows)]:
            data = entry.to_dict()
            self.ledger.record("event", data.get("evidence_id"), data.get("event_id"))
            rows.append(
                {
                    "event_id": data.get("event_id"),
                    "evidence_id": data.get("evidence_id"),
                    "timestamp": data.get("timestamp"),
                    "event_type": data.get("event_type"),
                    "src_ip": data.get("src_ip"),
                    "dst_ip": data.get("dst_ip"),
                    "message": data.get("message"),
                }
            )
        return rows

    def list_detections(self):
        from netforensicai.core.store import CaseStore

        with CaseStore(self.case_dir) as store:
            detections = store.list_detections()

        rows = []
        for detection in detections[: self.max_rows]:
            self.ledger.record("detection", detection.get("evidence_id"), detection.get("rule_id"))
            rows.append(
                {
                    "rule_id": detection.get("rule_id"),
                    "evidence_id": detection.get("evidence_id"),
                    "severity": detection.get("severity"),
                    "description": detection.get("description"),
                }
            )
        return rows

    def list_entities(self, entity_type=None, limit=MAX_ROWS):
        from netforensicai.core.store import CaseStore

        with CaseStore(self.case_dir) as store:
            entities = store.list_entities(entity_type=entity_type)
        return [
            {"entity_id": e["entity_id"], "type": e["entity_type"], "value": e["value"]}
            for e in entities[: min(int(limit or self.max_rows), self.max_rows)]
        ]

    def search_packets(self, pattern, mode="text", evidence_id=None, display_filter=None, limit=MAX_ROWS):
        """Content search over a capture's raw bytes."""
        from netforensicai.core import search as search_module

        evidence, path = self._resolve_capture(evidence_id)
        result = search_module.search_capture(
            path,
            pattern,
            mode=mode,
            max_hits=min(int(limit or self.max_rows), self.max_rows),
            display_filter=display_filter,
        )
        rows = []
        for hit in result.hits:
            self.ledger.record("frame", evidence.evidence_id, hit.frame_number)
            if hit.stream is not None:
                self.ledger.record("stream", evidence.evidence_id, hit.stream)
            rows.append(
                {
                    "evidence_id": evidence.evidence_id,
                    "frame": hit.frame_number,
                    "stream": hit.stream,
                    "protocol": hit.protocol,
                    "src": hit.src,
                    "dst": hit.dst,
                    "matched": hit.matched,
                    "excerpt": (hit.excerpt or "")[:400],
                }
            )
        return rows

    def list_streams(self, evidence_id=None, protocol="tcp", limit=10):
        from netforensicai.core import streams as streams_module

        evidence, path = self._resolve_capture(evidence_id)
        found = streams_module.list_streams(
            path, protocol=protocol, limit=min(int(limit or 10), self.max_rows)
        )
        rows = []
        for summary in found:
            self.ledger.record("stream", evidence.evidence_id, summary.stream)
            rows.append(
                {
                    "evidence_id": evidence.evidence_id,
                    "stream": summary.stream,
                    "endpoints": f"{summary.endpoint_a} -> {summary.endpoint_b}",
                    "packets": summary.packets,
                    "bytes": summary.bytes,
                    "protocols": summary.applications,
                }
            )
        return rows

    def follow_stream(self, stream, evidence_id=None, protocol="tcp"):
        from netforensicai.core import streams as streams_module

        evidence, path = self._resolve_capture(evidence_id)
        followed = streams_module.follow_stream(path, protocol=protocol, index=stream)
        self.ledger.record("stream", evidence.evidence_id, followed.stream)
        return {
            "evidence_id": evidence.evidence_id,
            "stream": followed.stream,
            "node_a": followed.node_a,
            "node_b": followed.node_b,
            "turns": [
                {"sender": turn.sender, "text": turn.text[:2000]} for turn in followed.turns[:10]
            ],
        }

    def protocol_summary(self, evidence_id=None):
        from netforensicai.core import ctf as ctf_module

        _evidence, path = self._resolve_capture(evidence_id)
        return [
            {"protocol": p.protocol, "frames": p.frames, "bytes": p.bytes, "note": p.note}
            for p in ctf_module.protocol_summary(path)
        ]


TOOL_SPECS = {
    "list_evidence": "List the evidence items in this case. No arguments.",
    "search_events": (
        "Search normalized events. Arguments: event_type, ip, user, hostname, process, file, "
        "limit - all optional."
    ),
    "list_detections": "List detection-rule matches for this case. No arguments.",
    "list_entities": "List extracted entities. Arguments: entity_type, limit - both optional.",
    "search_packets": (
        "Search raw packet bytes of a capture. Arguments: pattern (required), "
        "mode ('text'|'regex'|'hex'), evidence_id, display_filter, limit."
    ),
    "list_streams": (
        "List conversations in a capture, largest first. Arguments: evidence_id, protocol, limit."
    ),
    "follow_stream": (
        "Reassemble one conversation. Arguments: stream (required), evidence_id, protocol."
    ),
    "protocol_summary": "Protocol hierarchy of a capture. Arguments: evidence_id.",
}


def _tool_catalogue():
    return "\n".join(f"- {name}: {description}" for name, description in TOOL_SPECS.items())


def _render(value):
    text = json.dumps(value, default=str, indent=None)
    if len(text) > MAX_CHARS_PER_RESULT:
        return text[:MAX_CHARS_PER_RESULT] + f"... [truncated at {MAX_CHARS_PER_RESULT} chars]"
    return text


def _run_tool(tools, name, arguments):
    if name not in TOOL_SPECS:
        raise ChatError(f"Unknown tool '{name}'.")
    method = getattr(tools, name)
    if not isinstance(arguments, dict):
        raise ChatError(f"Arguments for '{name}' must be an object.")
    # Unexpected keys are dropped rather than raising: a model that invents
    # a plausible-looking argument should get the tool's real behaviour and
    # a chance to correct itself, not a hard failure that burns a step.
    import inspect

    accepted = set(inspect.signature(method).parameters)
    filtered = {key: value for key, value in arguments.items() if key in accepted}
    return method(**filtered)


def ask(
    question,
    case_dir,
    provider="anthropic",
    api_key=None,
    model=None,
    base_url=None,
    max_steps=MAX_STEPS,
    call=None,
):
    """Answer one question about a case, retrieving evidence as needed.

    `call` overrides the provider call, taking (system_prompt, user_prompt)
    and returning a parsed dict. Present so the loop can be tested against
    scripted model behaviour - including the behaviour that matters most,
    a model citing something no tool returned.

    Raises ChatError if the answer cannot be verified against retrieved
    evidence.
    """
    if not question or not question.strip():
        raise ChatError("Question is empty.")

    from netforensicai.core import ai_assistant

    if call is None:

        def call(system_prompt, user_prompt):
            return ai_assistant.call_model(
                system_prompt,
                user_prompt,
                provider=provider,
                api_key=api_key,
                model=model,
                base_url=base_url,
            )

    ledger = Ledger()
    tools = CaseTools(case_dir, ledger)
    steps = []

    transcript = [
        f"Case directory: {case_dir}",
        f"Tools available:\n{_tool_catalogue()}",
        f"Investigator's question: {question}",
    ]

    for step in range(max_steps):
        remaining = max_steps - step
        prompt = "\n\n".join(transcript) + (
            f"\n\nYou have {remaining} tool call(s) left before you must answer."
            if remaining > 1
            else "\n\nThis is your LAST turn. You must answer now, using what you already retrieved."
        )

        try:
            raw = call(SYSTEM_PROMPT, prompt)
        except Exception as e:
            raise ChatError(f"AI provider failed: {e}") from e

        if not isinstance(raw, dict):
            raise ChatError("AI response was not a JSON object.")

        action = raw.get("action")
        if action == "tool":
            name = raw.get("tool")
            arguments = raw.get("arguments") or {}
            try:
                result = _run_tool(tools, name, arguments)
                rows = len(result) if isinstance(result, list) else 1
                steps.append(
                    ToolCall(tool=name, arguments=arguments, summary=f"{rows} result(s)", rows=rows)
                )
                transcript.append(
                    f"You called {name}({json.dumps(arguments, default=str)}).\n"
                    f"Result:\n{_render(result)}"
                )
            except Exception as e:
                # Tool failures are fed back rather than raised: a bad
                # argument is something the model can fix on the next step,
                # and killing the question over it would be worse than
                # letting it retry.
                steps.append(ToolCall(tool=str(name), arguments=arguments, summary="failed", error=str(e)))
                transcript.append(f"You called {name}({json.dumps(arguments, default=str)}).\nError: {e}")
            continue

        if action == "answer":
            return _finalize(raw, question, ledger, steps, transcript, call)

        transcript.append(
            'Your reply had no valid "action". Reply with {"action":"tool",...} or {"action":"answer",...}.'
        )

    raise ChatError(
        f"No answer after {max_steps} tool calls. Ask a narrower question, or raise --max-steps."
    )


def _finalize(raw, question, ledger, steps, transcript, call):
    """Validate an answer's citations against the ledger, with one retry."""
    for attempt in (1, 2):
        try:
            answer = Answer.model_validate(raw)
        except ValidationError as e:
            raise ChatError(f"AI answer did not match the expected format: {e}") from e

        unverifiable = [c for c in answer.citations if not ledger.contains(c)]
        if not unverifiable:
            return ChatResult(
                question=question,
                answer=answer.answer,
                evidence_sufficient=answer.evidence_sufficient,
                citations=answer.citations,
                steps=steps,
            )

        if attempt == 2:
            break

        # One correction pass, naming exactly what could not be verified.
        # A model that cited something adjacent to a real result usually
        # fixes it; one that invented a finding does not, and that is the
        # distinction worth spending a round trip to draw.
        listed = ", ".join(f"{c.kind} {c.evidence_id}/{c.reference}" for c in unverifiable)
        logger.warning(f"Chat answer cited unretrieved evidence ({listed}); asking for a correction.")
        transcript.append(
            f"Your answer cited evidence that no tool returned: {listed}. "
            f"You retrieved {ledger.counts()}. Answer again, citing only what tools actually returned, "
            "or set evidence_sufficient to false."
        )
        try:
            raw = call(SYSTEM_PROMPT, "\n\n".join(transcript))
        except Exception as e:
            raise ChatError(f"AI provider failed during citation correction: {e}") from e
        if not isinstance(raw, dict):
            raise ChatError("AI correction response was not a JSON object.")

    listed = ", ".join(f"{c.kind} {c.evidence_id}/{c.reference}" for c in unverifiable)
    raise ChatError(
        "Answer refused: it cited evidence no tool returned "
        f"({listed}), and the citation could not be corrected. Nothing is shown rather than showing "
        "a claim that cannot be traced to evidence."
    )
