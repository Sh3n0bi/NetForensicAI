# Contributing to NetForensicAI

Thank you for your interest in improving NetForensicAI! Contributions are welcome.

## How to Contribute
1. Fork the repository: https://github.com/Sh3n0bi/NetForensicAI
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Install with the extras you need and run the tests: `pip install -e ".[dev,pcap,intel,evtx,ai,web]"` then `pytest`.
4. Make your changes and commit (`git commit -m "Add your feature"`).
5. Push to your fork (`git push origin feature/your-feature`).
6. Open a pull request on GitHub.

## Design Principles

Before adding a feature, it's worth understanding the shape the rest of the codebase already follows - PRs that match it are much easier to review:

- **One core module does the work; CLI and web are thin callers.** Business logic lives under `netforensicai/core/`; `cli.py` and `web/app.py` should only ever call into it, never reimplement it. If you find yourself writing the same logic in both places, factor it into `core/` instead (see `core/pipeline.py` for an example of exactly that refactor).
- **A new evidence format is a new parser, not a new pipeline.** Implement `parsers/base.BaseParser`, register it, and everything downstream (entities, correlation, timeline, reporting) works without modification. Map into the existing Common Event Model (`core/event.py`) rather than inventing new fields when you can.
- **Never claim more certainty than the evidence supports.** Correlation labels things `related`/`possible_relationship`, never implies causality. The AI assistant only ever states a hedged hypothesis with cited evidence, never a conclusion. Keep that discipline in any new feature that produces investigator-facing output.
- **Local-first, no unnecessary infrastructure.** No new required external services, no message queues, no graph database - if a relational join or a local file answers the question, prefer that over a new dependency.

## Ideas for Contributions

- Additional Sysmon EVTX event types (`parsers/evtx.py`'s `SYSMON_EVENT_TYPES`/`SYSMON_FIELD_MAP` - registry-shell, remote thread, image load, etc.)
- More ATT&CK technique rules (`core/attack.py`'s `_rules_for_event` - currently a small starting set of four techniques; each new rule should be tied to a specific, unambiguous event pattern rather than a speculative guess)
- More bundled detection rules (`core/detections.py`'s `_rules_for_event` - currently four rules; same standard as ATT&CK rules above, plus keep the wording hedged ("commonly associated with", not "is malicious") since these run automatically with no investigator confirmation step)
- Additional threat intelligence providers alongside VirusTotal (`core/threat_intel.py`'s provider dispatch is built to add more)
- Additional AI providers alongside Anthropic/OpenAI/Ollama/Gemini (`core/ai_assistant.py`'s `_call_*` functions - each just needs to return a dict matching the `Hypothesis` schema; citation validation is centralized and provider-agnostic)

## Code Style
- Follow PEP 8 for Python code.
- Prefer clear naming over comments; only comment where the *why* isn't obvious from the code itself.
- Add tests under `tests/` for new behavior - see the existing test files for the patterns used (mocking external calls like VirusTotal/Anthropic/live capture, building synthetic evidence with scapy for pcap tests, `tmp_path`-scoped case fixtures for everything else).

## Releasing (maintainers)

Publishing to PyPI is triggered by a GitHub Release, via `.github/workflows/publish.yml` - it never happens on a normal push.

One-time setup (only needed once, before the first release):
1. Create the `netforensicai` project on PyPI - reserve the name with an empty first upload (`build` + `twine upload dist/*`), or use PyPI's "pending publisher" flow to reserve it without uploading anything.
2. On the PyPI project's *Publishing* settings, add a Trusted Publisher: owner `Sh3n0bi`, repository `NetForensicAI`, workflow `publish.yml`, environment `pypi`. This lets the GitHub Actions workflow authenticate via OIDC with no long-lived API token stored anywhere.

To cut a release:
1. Bump `version` in `pyproject.toml`.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. On GitHub, draft a Release from that tag and publish it - this triggers `publish.yml`, which builds the sdist/wheel and uploads them to PyPI.

Before tagging, build and sanity-check locally: `pip install ".[build]"`, then `python -m build && twine check dist/*`, and (optional but recommended) install the built wheel into a throwaway venv and confirm `netforensic web` still serves its static assets - `package-data` regressions here are easy to miss since the dev install (`pip install -e .`) never exercises them.

## Issues
Found a bug? Have a feature request? Open an issue at https://github.com/Sh3n0bi/NetForensicAI/issues.

Happy hacking!
