# Security Policy

NetForensicAI is a digital-forensics and incident-response tool. It ingests
untrusted evidence (packet captures, Windows Event Logs, arbitrary JSON/CSV)
and, optionally, talks to third-party services (VirusTotal, LLM providers). We
take security reports seriously and appreciate the time it takes to make one.

## Supported versions

This project is pre-1.0 (see `Development Status :: 3 - Alpha` in
`pyproject.toml`). Only the latest released version and `main` receive security
fixes. There are no long-term-support branches yet.

| Version | Supported |
|---------|-----------|
| `main` / latest release | ✅ |
| Older tagged releases | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report privately through **GitHub Security Advisories** (preferred): open a report
at <https://github.com/Sh3n0bi/NetForensicAI/security/advisories/new>. This keeps
the discussion private until a fix is ready and lets us collaborate on the patch.

> Maintainers: to add an email fallback, put a monitored address here and, if you
> want encrypted reports, publish a PGP fingerprint alongside it.

Please include, as far as you can:

- the version or commit SHA you tested,
- the component affected (CLI, web UI, a specific parser, an integration),
- a description of the impact and a realistic attack scenario,
- steps or a proof-of-concept to reproduce (a minimal malformed evidence file,
  a request, or a script),
- any suggested remediation.

## What to expect

This is a small project, so response times are best-effort, but the intent is:

- **Acknowledgement** within **3 business days**.
- **Initial assessment** (severity, whether we can reproduce) within **10 business days**.
- **Fix or documented mitigation** targeted within **90 days** of confirmation,
  sooner for actively exploited or high-severity issues.
- **Coordinated disclosure:** we will agree a disclosure date with you and credit
  you in the advisory and release notes unless you prefer to remain anonymous.

## Scope

In scope — vulnerabilities in this repository's code, for example:

- memory-exhaustion, crashes, or code execution triggered by a **malformed or
  malicious evidence file** reaching a parser (`netforensicai/parsers/*`),
- injection, path traversal, SSRF, or XSS in the **local web UI**
  (`netforensicai/web/`) or report renderers (`netforensicai/core/report.py`),
- leakage of stored **API keys or case data** beyond the boundaries described in
  the docs (e.g. credentials riding along in a `case export`),
- flaws in the **chain-of-custody / audit** integrity checks
  (`netforensicai/core/audit.py`).

Known and documented design decisions — **not** vulnerabilities on their own:

- The web UI has **no authentication** and is intended to bind to `127.0.0.1`
  only. Exposing it with `--host` to other machines is explicitly warned against
  (`cli.py`) and is outside the intended threat model. A report that it is
  reachable *after* an operator deliberately exposes it is not in scope; a way to
  reach it **without** that step (e.g. a cross-origin bypass of the CSRF-header
  check) is.
- Findings that require the attacker to already have local filesystem or account
  access equivalent to the investigator running the tool.

If you are unsure whether something is in scope, report it privately and ask.

## Safe-harbour

We will not pursue or support legal action against researchers who:

- make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption,
- test only against their own installation and their own evidence,
- give us a reasonable window to remediate before public disclosure.

Thank you for helping keep NetForensicAI and its users safe.
