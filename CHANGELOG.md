# Changelog

All notable changes to NetForensicAI are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Windows host detection rules** (`core/host_detections.py`), driven from the same
  streaming pass as the existing rules: `LOG-CLEARED`, `OFFICE-SPAWNED-SHELL`,
  `ENCODED-POWERSHELL`, `SUSPICIOUS-POWERSHELL` (script-block content), `LOLBIN-*`,
  `LSASS-DUMP`, `CREDENTIAL-HIVE-EXPORT`, `INHIBIT-RECOVERY`, `SUSPICIOUS-SERVICE`,
  `SUSPICIOUS-SCHEDULED-TASK`, `PRIVILEGED-GROUP-CHANGE`, `EXTERNAL-RDP-LOGON`,
  `NEW-CREDENTIALS-LOGON`, and aggregate `BRUTE-FORCE`/`BRUTE-FORCE-SUCCESS`,
  `PASSWORD-SPRAY`, `KERBEROASTING`. Each names its ATT&CK technique. No false
  positives on a real Windows 11 System/PowerShell log.
- **Narrative stages for host activity**: initial access, execution, persistence,
  privilege escalation, defense evasion, lateral movement and impact, with matching
  assessments (shadow-copy deletion leads as likely ransomware preparation) and
  stage chips in the web UI.
- **Windows Security / System / PowerShell EVTX mapping** (`parsers/windows_events.py`).
  Previously only five Sysmon event IDs were understood and a Security log arrived
  as opaque `windows_event:*` records. Now ~25 event IDs map to named event types
  (`logon_success`, `logon_failure`, `process_start`, `service_installed`,
  `audit_log_cleared`, `kerberos_service_ticket`, `group_member_added`, …) with the
  account, source IP/port (IPv4-mapped IPv6 unwrapped so it joins with pcap IPs),
  process fields and a readable message (logon type, failure reason, Kerberos
  encryption type). `-` placeholders never become entities. `<UserData>` records
  (1102/104) are read. EVTX ingestion now streams instead of building a list.

### Fixed
- **`OFFENSIVE-TOOL-NAME` never fired on real Windows evidence.** It compared the whole
  `process_name` against bare names like `mimikatz.exe`, but Sysmon `Image` and
  Security 4688 `NewProcessName` are full paths. It now matches the basename.
- **One unreadable EVTX record no longer discards the whole log.** python-evtx
  cannot render some record types written by current Windows (e.g. substitution
  type 132 in a stock Windows 11 System log); that used to fail the entire file,
  so the evidence produced zero events. Such records are now skipped and counted
  in a warning. On a real 20 MB System log: 0 → 37,601 events (636 skipped).

- **CI coverage gate** — a `coverage` job runs the full suite with tshark and all
  extras and fails under 85% line coverage (baseline ~89%), so coverage can't
  silently erode. `RELEASING.md` documents the PyPI/Docker release process.
- **`netforensic doctor`** — a read-only environment check: Python, the DuckDB
  case store, the cases/config directories, each optional evidence engine (scapy,
  scikit-learn, python-evtx, Flask, tshark, dumpcap), the active pcap engine, and
  whether an AI provider or VirusTotal key is configured. A missing *optional*
  capability is reported with its documented fallback, not as a failure; the
  command exits non-zero only when a core dependency is broken. `--json` emits a
  machine-readable report. Logic lives in `core/diagnostics.py` so it is testable
  and reusable; the command is a thin renderer over it.
- **`netforensic version` / `--version`** — print the installed package version.
- **Investigation-team agents** — `netforensicai/agents/`: a role is a mission +
  a scoped subset of the read-only case tools, run over the same grounded loop
  the chat assistant uses, producing structured findings that must cite a tool
  result or be dropped. Ships the **Network Forensics** and **Host/DFIR** roles
  and a **Lead Investigator** coordinator that merges corroborating findings
  (two roles on the same evidence become one) and ranks them by severity and
  corroboration. Opt-in, provider-agnostic, findings *proposed* not auto-written.
  Design: `docs/design/agent-team.md`.
- **Suricata `eve.json` parser** — detected by content (JSON Lines with a
  Suricata `event_type`) and mapped from its own schema (`alert`, `dns`,
  `http`, `tls`, `flow`, `fileinfo`, `anomaly`) into the Common Event Model.
  Point NetForensicAI at the NSM log you already have.
- **Docker image** bundling tshark (fast pcap engine by default), published to
  the GitHub Container Registry; `docker run` the web UI in one command.

### Changed
- Faster scapy pcap parsing (layers resolved once per packet) and a one-time
  hint to install Wireshark for the ~10x tshark engine when on the slow path.

### Fixed
- Recovered FTP/Telnet/POP3 usernames are now attached to the cleartext-credential
  event (the `USER` line precedes `PASS` in a separate packet), so the account
  reaches the entity graph. Found while validating against real captures.

## [0.3.0] — 2026-09-24

First public release: a local-first DFIR investigation platform that turns
packet captures and endpoint logs into one correlated, evidence-cited
investigation, entirely on your own machine.

### Added
- **Investigation core** — normalized events, deterministic entity extraction
  and correlation, a unified timeline, an entity relationship graph, bundled
  detection rules, ATT&CK technique mapping, and investigator-owned findings.
- **Evidence ingestion** — `.pcap`/`.pcapng` (scapy or tshark engine),
  JSON/CSV logs, Windows Event Logs including Sysmon (`.evtx`), and live
  network capture; each file hashed and stored read-only with a tamper-evident
  chain of custody.
- **Case narrative** — an assembled, deterministic "what happened" story that
  cites the events it rests on, surfaced in both the CLI and the web UI.
- **Threat intelligence** — import STIX 2.1 / MISP / CSV / plain-text feeds and
  match them against a case; optional VirusTotal lookups.
- **AI assistant (optional, opt-in)** — a grounded "Ask (cited)" chat and a
  hedged hypothesis generator, backed by Anthropic, OpenAI, Gemini, or local
  Ollama; every claim is checked against retrieved evidence and refused if
  unsupported.
- **Web UI** — a refined, accessible dark interface with a first-run onboarding
  flow, in-browser case creation with evidence upload and analysis in one step,
  a case list that shows each case's state, and configurable DuckDB
  memory/threads under Settings.

### Security & hardening
- Web UI **requires a shared token** to bind off loopback and serves through a
  production WSGI server (waitress) when exposed.
- **SSRF guard** on the Ollama `base_url`; parsers **fail safely** on malformed
  and non-UTF-8 evidence; **path-traversal** validation on all case / evidence /
  finding IDs; **ReDoS** and **log-injection** hardening.
- Structured **pcap/EVTX fuzzing** across both dissection engines.
- Supply chain: **CodeQL**, **pip-audit**, and **Dependabot**, with every
  GitHub Action pinned to a commit SHA; known dependency CVEs patched.

### Accessibility
- WCAG 2.1 AA pass: accessible names on controls, decorative icons hidden from
  assistive tech, a visible keyboard-focus ring, and AA-compliant contrast.

### Known limitations
See the README's *Limitations* section. In brief: this is Beta software, not
accredited against any forensic standard; correlation is not causality;
ingestion is the scaling bottleneck on very large captures; and the AI paths
have not been exercised against a live provider in CI.

[0.3.0]: https://github.com/Sh3n0bi/NetForensicAI/releases/tag/v0.3.0
