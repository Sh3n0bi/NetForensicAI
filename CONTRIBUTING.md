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
- MITRE ATT&CK technique mapping (currently a documented placeholder - see the Limitations section in `README.md`)
- Additional threat intelligence providers alongside VirusTotal (`core/threat_intel.py`'s provider dispatch is built to add more)
- Web UI write parity for findings (currently CLI-only - `netforensic finding create/update`)
- A GitHub Actions workflow that runs `pytest` on PRs

## Code Style
- Follow PEP 8 for Python code.
- Prefer clear naming over comments; only comment where the *why* isn't obvious from the code itself.
- Add tests under `tests/` for new behavior - see the existing test files for the patterns used (mocking external calls like VirusTotal/Anthropic/live capture, building synthetic evidence with scapy for pcap tests, `tmp_path`-scoped case fixtures for everything else).

## Issues
Found a bug? Have a feature request? Open an issue at https://github.com/Sh3n0bi/NetForensicAI/issues.

Happy hacking!
