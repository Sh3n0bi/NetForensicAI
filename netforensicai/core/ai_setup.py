"""Choosing how the AI assistant runs: on this computer, or through a service.

Every AI feature - Ask (cited), the AI hypothesis and the investigation team -
works with any of four providers. Three are cloud services that need an API
key; the fourth, Ollama, runs a model on this machine, so evidence never leaves
it. This module answers the questions a first-run screen has to ask before
offering that choice: is Ollama running here, which models does it have, which
cloud providers already have a key, and which one is selected now.

Detection only reads. Saving a choice goes through the existing settings path
(core/config.py), and checking a choice works through the existing provider
test. No API key is ever returned from here - only whether one is set.

The detections, the story and file recovery need no AI at all; the assistant is
the optional layer on top.
"""

from netforensicai.core import ai_assistant, config

# Local models known to follow the JSON protocol the assistant and the team
# speak. Suggestions, not requirements: any installed model can be chosen.
RECOMMENDED_LOCAL_MODELS = (
    {"name": "llama3.1:8b", "why": "Good all-rounder. About a 5 GB download; runs with 8 GB of RAM."},
    {"name": "qwen2.5:7b", "why": "Follows structured instructions well. About a 5 GB download; 8 GB of RAM."},
    {"name": "mistral-nemo", "why": "Larger and more capable. About a 7 GB download; 16 GB of RAM recommended."},
)

CLOUD_PROVIDERS = {
    "anthropic": {"name": "Anthropic (Claude)", "key": "anthropic_api_key", "get_key": "https://console.anthropic.com/"},
    "openai": {"name": "OpenAI", "key": "openai_api_key", "get_key": "https://platform.openai.com/api-keys"},
    "gemini": {"name": "Google Gemini", "key": "gemini_api_key", "get_key": "https://aistudio.google.com/apikey"},
}

OLLAMA_PROBE_TIMEOUT_SECONDS = 2
# The status bar asks on every page. The web server is single-threaded, so an
# uncached probe of a missing Ollama (a full timeout) stalled every request
# behind it. A short cache keeps navigation instant; "Check again" refreshes.
LOCAL_STATUS_TTL_SECONDS = 20
_local_cache = {}  # base_url -> (monotonic time, status)


def local_status(base_url=None, refresh=False):
    """Cached wrapper over _probe_local (see LOCAL_STATUS_TTL_SECONDS)."""
    import time

    base_url = base_url or config.get_plain("ollama_base_url") or ai_assistant.DEFAULT_OLLAMA_BASE_URL
    cached = _local_cache.get(base_url)
    if cached and not refresh and time.monotonic() - cached[0] < LOCAL_STATUS_TTL_SECONDS:
        return dict(cached[1])
    result = _probe_local(base_url)
    _local_cache[base_url] = (time.monotonic(), result)
    return dict(result)


def _probe_local(base_url):
    """Whether Ollama answers at `base_url` (default: saved setting, then
    localhost), and the models it has installed.

    `base_url` can come from a web request, so it goes through the same
    guard as every Ollama call: loopback only, unless the operator opted in.
    """
    status = {"base_url": base_url, "reachable": False, "models": [], "error": None}
    try:
        ai_assistant._validate_ollama_base_url(base_url)
    except ai_assistant.AssistantError as e:
        status["error"] = str(e)
        return status
    try:
        import requests
    except ImportError:
        status["error"] = "The 'requests' package is not installed. Install it with: pip install 'netforensicai[ai]'"
        return status
    try:
        response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=OLLAMA_PROBE_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
    except Exception as e:  # not running, wrong port, not Ollama - all mean "not available here"
        status["error"] = f"Ollama is not answering at {base_url}. Is it installed and running? ({type(e).__name__})"
        return status
    status["reachable"] = True
    for model in payload.get("models") or []:
        details = model.get("details") or {}
        status["models"].append({
            "name": model.get("name") or model.get("model"),
            "size_gb": round((model.get("size") or 0) / 1e9, 1),
            "parameters": details.get("parameter_size"),
            "family": details.get("family"),
        })
    return status


def status(base_url=None, refresh=False):
    """Everything the setup screen shows: the current choice, whether it is
    ready to use, local AI detection, and which cloud providers have a key."""
    provider = config.get_plain("ai_provider")
    model = config.get_plain("ai_model") or ai_assistant.DEFAULT_MODELS.get(provider)
    secrets = config.masked_settings()["secrets"]
    cloud = {
        slug: {
            "name": info["name"],
            "key_set": bool(secrets.get(info["key"], {}).get("set")),
            "key_hint": secrets.get(info["key"], {}).get("hint"),
            "get_key_url": info["get_key"],
            "default_model": ai_assistant.DEFAULT_MODELS.get(slug),
        }
        for slug, info in CLOUD_PROVIDERS.items()
    }
    local = local_status(base_url, refresh=refresh)

    if provider == "ollama":
        installed = {m["name"] for m in local["models"]}
        # Ollama names carry a tag ("llama3.1:latest"); a bare name matches its :latest.
        has_model = model in installed or f"{model}:latest" in installed
        ready = local["reachable"] and has_model
        why = None if ready else (
            local["error"] if not local["reachable"] else f"The model '{model}' is not installed. Run: ollama pull {model}"
        )
    else:
        ready = bool(cloud.get(provider, {}).get("key_set"))
        why = None if ready else f"No API key is set for {cloud.get(provider, {}).get('name', provider)}."

    return {
        "provider": provider,
        "model": model,
        "mode": "local" if provider == "ollama" else "cloud",
        "ready": ready,
        "not_ready_reason": why,
        "local": local,
        "cloud": cloud,
        "recommended_local_models": list(RECOMMENDED_LOCAL_MODELS),
    }
