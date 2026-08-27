"""AI investigation assistant: an optional, explicitly-invoked layer that
proposes AT MOST ONE hedged hypothesis from a set of investigator-selected
events, via the Anthropic API.

This sits downstream of the deterministic pipeline (parsing ->
normalization -> correlation -> timeline -> entity extraction) and never
replaces it:

    Evidence -> Parsing -> Normalization -> Correlation -> Timeline
        -> Evidence selection -> AI analysis -> Hypothesis
        -> Human validation

Safety rules, enforced in code here rather than left to the prompt alone:
  - never runs automatically during parse/analyze/investigate - only on an
    explicit investigator action (`netforensic investigate --ai`)
  - only normalized Event data is sent to the API - never raw evidence
    file contents, and only the events the investigator's query selected
  - the model's structured output is validated by pydantic (output_format)
    AND every cited (evidence_id, event_id) pair is checked against the
    events actually given to it after the response comes back; a
    hypothesis citing anything not present is REJECTED outright, never
    silently trusted or displayed
  - output always distinguishes observed evidence from interpretation,
    always carries a confidence level, and always includes an alternative
    explanation - the schema makes omitting any of these impossible
  - nothing here writes a Finding; the investigator decides whether to
    act on a hypothesis via `netforensic finding create`
"""

import logging
from typing import List, Literal

from pydantic import BaseModel

logger = logging.getLogger(__name__)

MODEL = "claude-opus-5"
MAX_TOKENS = 4096
MAX_EVENTS = 50

SYSTEM_PROMPT = """You are assisting a digital forensics and incident response (DFIR) investigator.
You will be given a set of normalized forensic events, already parsed and extracted from real evidence.

Your job is to propose AT MOST ONE hypothesis about what these events might represent. You must:
- Base every claim ONLY on the events provided below. Never reference an evidence_id or event_id that
  was not given to you - doing so makes your entire response unusable and it will be discarded.
- Clearly separate observed fact (what literally happened, per the events) from your interpretation.
- Phrase the hypothesis as a possibility ("may represent", "could indicate"), never as a certainty.
- Always provide at least one plausible alternative, non-malicious explanation for the same evidence.
- Assign a confidence level (low/medium/high) that reflects how strong the evidence actually is, not
  how interesting the hypothesis is.
- If the provided events do not support any reasonable hypothesis, say so explicitly by setting
  evidence_sufficient to false rather than inventing one.

You are not the investigator. Your output is a starting point for the investigator's own review, never
a conclusion they should accept without checking it themselves."""


class EvidenceCitation(BaseModel):
    evidence_id: str
    event_id: str


class Hypothesis(BaseModel):
    evidence_sufficient: bool
    claim: str
    assessment: str
    observed_evidence: List[str]
    confidence: Literal["low", "medium", "high"]
    alternative_explanation: str
    recommended_validation: str
    evidence: List[EvidenceCitation]


class AssistantError(Exception):
    """Raised when the assistant can't produce a usable hypothesis: no
    credentials, an API failure, or a response citing evidence not
    actually present in the given events. The last case is a hard
    rejection, not a warning - this module never returns a hypothesis it
    can't verify."""


def _event_summary(event):
    """A compact, plain-text line for one event - the only thing that
    actually gets sent to the model. Normalized fields only, never the
    raw evidence file."""
    fields = [event.event_type]
    if event.timestamp:
        fields.insert(0, str(event.timestamp))
    for label, value in (
        ("user", event.user),
        ("hostname", event.hostname),
        ("src_ip", event.src_ip),
        ("dst_ip", event.dst_ip),
        ("dst_port", event.dst_port),
        ("process", event.process_name),
        ("command_line", event.command_line),
        ("file", event.file_name),
        ("file_hash", event.file_hash),
        ("domain", event.domain),
        ("message", event.message),
    ):
        if value:
            fields.append(f"{label}={value}")
    return f"[{event.evidence_id}/{event.event_id}] " + " ".join(fields)


def generate_hypothesis(events, api_key=None):
    """Ask Claude for one hedged hypothesis about `events`.

    api_key is optional: if omitted, the Anthropic SDK resolves
    credentials itself (ANTHROPIC_API_KEY, or an `ant auth login`
    profile) rather than this module assuming no key means no
    credentials.

    Raises AssistantError on any failure, including a response citing
    evidence not present in `events`.
    """
    if not events:
        raise AssistantError("No events provided.")

    events = events[:MAX_EVENTS]

    import anthropic

    event_lines = "\n".join(_event_summary(e) for e in events)
    prompt = (
        "Here are the normalized events available for this hypothesis. Each line starts with "
        "[evidence_id/event_id]. Cite only these evidence_id/event_id pairs.\n\n" + event_lines
    )

    no_credentials_message = (
        "No Anthropic credentials found. Use --api-key, set ANTHROPIC_API_KEY, or run `ant auth login`."
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.parse(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            output_format=Hypothesis,
        )
    except TypeError as e:
        # The SDK raises a plain TypeError - not an API exception, since no
        # request was ever sent - when it can't resolve any credential
        # source at all (no api_key, no env var, no `ant auth login`
        # profile). Observed at client construction in some SDK versions
        # and lazily inside messages.parse() in others, so both calls are
        # covered by this one try block. Recognized by message text rather
        # than a dedicated exception class - the SDK doesn't document one
        # for this case.
        if "authentication" in str(e).lower():
            raise AssistantError(no_credentials_message) from e
        raise
    except anthropic.AuthenticationError as e:
        raise AssistantError(no_credentials_message) from e
    except anthropic.APIStatusError as e:
        raise AssistantError(f"AI request failed: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise AssistantError(f"AI request failed: network error - {e}") from e

    hypothesis = response.parsed_output
    if hypothesis is None:
        raise AssistantError("AI response could not be parsed into the expected format.")

    valid_pairs = {(e.evidence_id, e.event_id) for e in events}
    for citation in hypothesis.evidence:
        if (citation.evidence_id, citation.event_id) not in valid_pairs:
            raise AssistantError(
                f"AI response cited evidence not present in the given events "
                f"({citation.evidence_id}/{citation.event_id}) - rejected."
            )

    return hypothesis
