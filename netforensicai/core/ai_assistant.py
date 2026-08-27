"""AI investigation assistant: an optional, explicitly-invoked layer that
proposes AT MOST ONE hedged hypothesis from a set of investigator-selected
events, via a choice of AI providers (Anthropic, OpenAI, a local Ollama
server, or Google Gemini).

This sits downstream of the deterministic pipeline (parsing ->
normalization -> correlation -> timeline -> entity extraction) and never
replaces it:

    Evidence -> Parsing -> Normalization -> Correlation -> Timeline
        -> Evidence selection -> AI analysis -> Hypothesis
        -> Human validation

Safety rules, enforced in code here rather than left to the prompt alone -
identically, regardless of which provider answered:
  - never runs automatically during parse/analyze/investigate - only on an
    explicit investigator action (`netforensic investigate --ai`)
  - only normalized Event data is sent to the provider - never raw
    evidence file contents, and only the events the investigator's query
    selected
  - every provider is asked for the same Hypothesis JSON schema; the
    response is validated by pydantic AND every cited (evidence_id,
    event_id) pair is checked against the events actually given to it
    after the response comes back - in one central code path each
    provider's raw response dict passes through, not duplicated per
    provider. A hypothesis citing anything not present is REJECTED
    outright, never silently trusted or displayed, no matter which
    provider produced it.
  - output always distinguishes observed evidence from interpretation,
    always carries a confidence level, and always includes an alternative
    explanation - the schema makes omitting any of these impossible
  - nothing here writes a Finding; the investigator decides whether to
    act on a hypothesis via `netforensic finding create`

Each provider is optional and independently installable (see pyproject.toml's
ai/ai-openai/ai-gemini extras); Ollama needs no extra package at all since
it's a local HTTP call via `requests` (already required by the base `ai`
extra). Picking a provider that isn't installed raises AssistantError with
a clear message rather than an ImportError leaking out of this module.
"""

import logging
from typing import List, Literal

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = ("anthropic", "openai", "ollama", "gemini")

# Sane defaults, not the only option - every entry point (CLI --model,
# the web API's "model" field) lets the investigator override these, so a
# provider renaming/retiring a model doesn't require a code change here.
DEFAULT_MODELS = {
    "anthropic": "claude-opus-5",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.1",
    "gemini": "gemini-2.0-flash",
}

MAX_TOKENS = 4096
MAX_EVENTS = 50
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"

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


def generate_hypothesis(events, provider="anthropic", api_key=None, model=None, base_url=None):
    """Ask an AI provider for one hedged hypothesis about `events`.

    provider: one of SUPPORTED_PROVIDERS. api_key is optional for every
    provider except Ollama (which needs none) - if omitted, each
    provider's own SDK resolves credentials itself from its usual
    environment variable (or, for Anthropic, an `ant auth login` profile)
    rather than this module assuming no key means no credentials.
    model overrides that provider's default (DEFAULT_MODELS). base_url
    only applies to Ollama (default DEFAULT_OLLAMA_BASE_URL).

    Raises AssistantError on any failure - unknown provider, missing
    credentials, a request/network error, or a response citing evidence
    not present in `events`. That last check runs identically regardless
    of which provider answered - see the module docstring.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise AssistantError(f"Unknown AI provider '{provider}'. Choose from: {', '.join(SUPPORTED_PROVIDERS)}")
    if not events:
        raise AssistantError("No events provided.")

    events = events[:MAX_EVENTS]
    model = model or DEFAULT_MODELS[provider]

    event_lines = "\n".join(_event_summary(e) for e in events)
    prompt = (
        "Here are the normalized events available for this hypothesis. Each line starts with "
        "[evidence_id/event_id]. Cite only these evidence_id/event_id pairs.\n\n" + event_lines
    )

    if provider == "anthropic":
        raw = _call_anthropic(SYSTEM_PROMPT, prompt, api_key, model)
    elif provider == "openai":
        raw = _call_openai(SYSTEM_PROMPT, prompt, api_key, model)
    elif provider == "ollama":
        raw = _call_ollama(SYSTEM_PROMPT, prompt, model, base_url or DEFAULT_OLLAMA_BASE_URL)
    elif provider == "gemini":
        raw = _call_gemini(SYSTEM_PROMPT, prompt, api_key, model)

    try:
        hypothesis = Hypothesis.model_validate(raw)
    except ValidationError as e:
        raise AssistantError(f"AI response could not be parsed into the expected format: {e}") from e

    valid_pairs = {(e.evidence_id, e.event_id) for e in events}
    for citation in hypothesis.evidence:
        if (citation.evidence_id, citation.event_id) not in valid_pairs:
            raise AssistantError(
                f"AI response cited evidence not present in the given events "
                f"({citation.evidence_id}/{citation.event_id}) - rejected."
            )

    return hypothesis


def _call_anthropic(system_prompt, user_prompt, api_key, model):
    try:
        import anthropic
    except ImportError as e:
        raise AssistantError("The 'anthropic' package isn't installed. Install with: pip install 'netforensicai[ai]'") from e

    no_credentials_message = (
        "No Anthropic credentials found. Use --api-key, set ANTHROPIC_API_KEY, or run `ant auth login`."
    )
    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.parse(
            model=model,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
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
    return hypothesis.model_dump()


def _call_openai(system_prompt, user_prompt, api_key, model):
    try:
        import openai
    except ImportError as e:
        raise AssistantError(
            "The 'openai' package isn't installed. Install with: pip install 'netforensicai[ai-openai]'"
        ) from e

    no_credentials_message = "No OpenAI credentials found. Use --api-key or set OPENAI_API_KEY."
    try:
        client = openai.OpenAI(api_key=api_key)
        # .beta.chat.completions.parse rather than the newer non-beta
        # alias, deliberately: it's been stable since openai>=1.40, giving
        # a much wider compatible version range than pinning to whatever
        # SDK version first promoted it out of beta.
        response = client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format=Hypothesis,
            max_completion_tokens=MAX_TOKENS,
        )
    except openai.AuthenticationError as e:
        raise AssistantError(no_credentials_message) from e
    except openai.OpenAIError as e:
        # Covers both "no credentials resolvable at all" (raised at client
        # construction, before any request) and any other SDK-level setup
        # failure that isn't a plain network/API-status error.
        if "credentials" in str(e).lower() or "api_key" in str(e).lower():
            raise AssistantError(no_credentials_message) from e
        raise AssistantError(f"AI request failed: {e}") from e
    except openai.APIConnectionError as e:
        raise AssistantError(f"AI request failed: network error - {e}") from e
    except openai.APIStatusError as e:
        raise AssistantError(f"AI request failed: {e.message}") from e

    message = response.choices[0].message
    if message.parsed is None:
        refusal = f" ({message.refusal})" if getattr(message, "refusal", None) else ""
        raise AssistantError(f"AI response could not be parsed into the expected format.{refusal}")
    return message.parsed.model_dump()


def _call_gemini(system_prompt, user_prompt, api_key, model):
    try:
        from google import genai
        from google.genai import errors as genai_errors
        from google.genai import types as genai_types
    except ImportError as e:
        raise AssistantError(
            "The 'google-genai' package isn't installed. Install with: pip install 'netforensicai[ai-gemini]'"
        ) from e

    no_credentials_message = "No Gemini credentials found. Use --api-key or set GEMINI_API_KEY."
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model,
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=Hypothesis,
            ),
        )
    except ValueError as e:
        # The SDK raises a plain ValueError at client construction - before
        # any request - when it can't resolve an API key from either the
        # argument or GEMINI_API_KEY/GOOGLE_API_KEY.
        if "api key" in str(e).lower():
            raise AssistantError(no_credentials_message) from e
        raise
    except genai_errors.ClientError as e:
        if e.code in (401, 403):
            raise AssistantError(no_credentials_message) from e
        raise AssistantError(f"AI request failed: {e.message or e}") from e
    except genai_errors.ServerError as e:
        raise AssistantError(f"AI request failed: {e.message or e}") from e

    if response.parsed is None:
        raise AssistantError("AI response could not be parsed into the expected format.")
    return response.parsed.model_dump()


def _call_ollama(system_prompt, user_prompt, model, base_url):
    """Ollama runs locally, needs no API key, and needs no dedicated SDK -
    just its documented /api/chat HTTP endpoint with a JSON schema in
    `format` for structured output (Ollama >=0.5). Uses `requests`, which
    the base `ai` extra already depends on for exactly this provider.

    Not verified against a live Ollama server in this environment (none
    was available to test against) - implemented directly from Ollama's
    documented /api/chat contract. Report an issue if a real server's
    behavior differs from what's assumed here.
    """
    try:
        import requests
    except ImportError as e:
        raise AssistantError("The 'requests' package isn't installed. Install with: pip install 'netforensicai[ai]'") from e

    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "format": Hypothesis.model_json_schema(),
                "stream": False,
            },
            timeout=120,
        )
        response.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        raise AssistantError(
            f"Could not reach Ollama at {base_url} - is `ollama serve` running? ({e})"
        ) from e
    except requests.exceptions.HTTPError as e:
        raise AssistantError(f"AI request failed: {e}") from e
    except requests.exceptions.RequestException as e:
        raise AssistantError(f"AI request failed: network error - {e}") from e

    content = response.json().get("message", {}).get("content")
    if not content:
        raise AssistantError("AI response could not be parsed into the expected format.")
    try:
        import json

        return json.loads(content)
    except json.JSONDecodeError as e:
        raise AssistantError(f"AI response could not be parsed into the expected format: {e}") from e
