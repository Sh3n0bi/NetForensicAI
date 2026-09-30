# Changelog

All notable changes to NetForensicAI are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Recovered files you can open.** A new *Recovered files* view lists every file pulled
  from traffic with what it really is (by content, not name - a disguised program is
  called out), where it came from ("Sent from A to B over FTP", the URL, a link to the
  conversation), how risky it is to open and why, and hints such as "contains email
  addresses". **Look inside** safely (text, CSV table, raster image, or hex - never
  HTML, never run) and **download a copy** (attachment + nosniff + sandbox CSP; a second
  confirmation for programs). Downloads are recorded in the chain of custody
  (`artifact.exported`). Overview and Triage now link here instead of pointing at the CLI.
- **FTP files are recovered even when Wireshark cannot.** Without a PASV/PORT exchange in
  the capture, Wireshark's exporter recovers nothing from an FTP data connection. The
  tshark engine now pairs each `STOR`/`RETR` with its data connection and recovers the
  file byte-exact (the demo incident's stolen `customers-export.csv` now appears).
- **Save any conversation's data** - *Save what … sent* on Streams downloads one side's
  exact bytes (audited as `stream.exported`), for files in protocols the automatic
  recovery does not cover. Backed by a byte-exact raw-mode stream reader.

### Fixed
- **Chat and the investigation team could not work with any real AI provider.** Every
  provider call (Anthropic, OpenAI, Gemini and local Ollama) was forced into the
  AI-hypothesis response schema, so a real model could only answer with a hypothesis -
  never the tool calls and answers chat and the team need. Chat always ended "No answer
  after N tool calls" and every team role "no findings within the step budget"; only the
  single-shot hypothesis worked. `call_model()` now takes the schema from its caller: the
  hypothesis keeps its exact schema, chat and the team use each provider's plain JSON
  mode (Ollama `format: "json"`, OpenAI `json_object`, Gemini JSON MIME type, Anthropic
  text parsed as JSON), and the callers validate the reply as before. The tests had
  replaced `call_model()` itself; new tests go through each provider's request code.
- **A capture with emailed files could fail to analyze at all.** Wireshark names an
  exported email after its subject, percent-escaped and MIME-encoded; on a real HawkEye
  keylogger capture that name ran to ~200 characters, the write failed on Windows'
  path limit, and the all-or-nothing pipeline discarded the whole capture (0 events).
  Exported names are now decoded, made safe and bounded (64 characters, extension
  kept; the full original is kept and shown), long paths use Windows' `\\?\` form, and
  a single file that still cannot be written is skipped with a warning instead of
  failing the capture. The same capture now yields 585 events, the malware, and 7
  exfiltration emails.
- Exported object names are readable: a site's root page is `index` (not `%5c`), an SMB
  file keeps its name, an email is named after its subject.
- **Recovered files view: emails are shown decoded** (From / To / Date / Subject, the
  message text, attachments) - stealers mail their loot out base64-encoded - with hints
  and risk judged on the decoded body and attachments.
- The recovered-files list was quadratic in the number of files (273 s for a real case
  with 12,327); it is now linear with cached hashes (about 3 s warm), and the view
  pages 200 at a time with a name and risk filter.
- Files named as an archive, document or image whose content is not that format are
  flagged ("may be encrypted, corrupted, or disguised"); TAR archives are recognised.
- Stream rows could only be opened with a mouse; they are now keyboard-operable.

## [0.5.0] — 2026-09-30

The investigation team comes to the web UI, with one-click acceptance of its
findings, and every AI request now reaches the chain of custody. Also fixes the
saved "Default AI provider" setting, which had been ignored everywhere.

### Added
- **Investigation team in the web UI** — *Investigation team* under Assistant runs the
  AI analysts in the background (the page polls, like live capture), shows each
  analyst's progress, and offers **Accept as finding** on each merged result, which
  records it as an Open finding. The latest result persists in
  `cases/<id>/team/latest.json` (never the API key); a re-run keeps already-accepted
  findings marked by the evidence they cite. New endpoints: `GET/POST
  /api/cases/<id>/team`, `POST /api/cases/<id>/team/findings/<n>/accept`.
- **Team runs are recorded in the chain of custody** (`ai.team_run`), from the CLI
  and the web UI, as `investigate --ai` already was.
- **Chat requests are recorded in the chain of custody** (`ai.chat_requested`): the
  provider, model, question, tools the assistant called, what it cited, and whether
  it answered, was refused by the citation check, or failed. CLI and web alike.

### Fixed
- **Not every AI request reached the chain of custody**, although the docs said it
  did: `chat` (CLI and web) and the web UI's AI-hypothesis button sent case content
  to a provider without an audit entry. Both now record one, including refusals and
  failures; the web hypothesis entry matches `investigate --ai`'s exactly.
- **The saved "Default AI provider" (and model / Ollama URL) was ignored.** Every
  AI path - `chat`, `team`, `investigate --ai` and the web chat and hypothesis
  routes - defaulted to anthropic regardless of Settings. They now use an explicit
  choice, then the saved Settings, then the default.
- **The chat assistant's tools read the case store without the shared lock**, so
  asking a question during a live capture could collide with the capture's writes.
  They now go through `locked_store()`.
- The test suite read the developer's real `~/.netforensicai` settings; it now
  runs against an isolated config directory.

## [0.4.0] — 2026-09-29

Windows host forensics and the AI investigation team: Security/System/PowerShell
event logs are now understood and have their own detection rules, `netforensic
team` runs the specialist AI analysts, and `netforensic demo` shows the whole tool
on a fabricated incident in one command.

### Security
- **Web UI: DNS-rebinding protection.** In the default tokenless loopback mode the
  UI accepted any `Host` header, so a malicious web page that rebound its domain to
  `127.0.0.1` could read every case and create, modify or delete cases and evidence
  as same-origin (the `X-Requested-With` CSRF check does not stop a same-origin
  request). Tokenless mode now refuses any request not addressed to
  `localhost`/`127.0.0.1`/`[::1]` with `403`. New `netforensic web --allow-host
  <name>` (repeatable) admits a trusted reverse-proxy name. Token-protected
  deployments (including the Docker image) are unaffected.

### Added
- **`netforensic demo`** — builds the synthetic incident capture, creates a case,
  analyzes it and prints the story in one command; `--open` then opens it in the web
  UI. The generator moved into the package (`netforensicai/demo.py`) so this works
  from a PyPI install; `samples/generate_incident.py` remains as a thin wrapper.
- **README screenshots** of the web UI (story, overview, detections, timeline),
  captured from the demo case. `samples/capture_screenshots.py` regenerates them.
- **`netforensic team`** — runs the AI investigation team over a case: the network and
  host analysts investigate with scoped read-only tools, their evidence-cited findings
  are merged and ranked, and unciteable findings are dropped. Roles with no evidence in
  the case are skipped before any model call. `--roles`, `--max-steps`, `--json`, the
  same provider options as `chat`, and `--save-findings` to record results as **Open**
  findings (with their event citations) for the investigator to confirm. Exits non-zero
  when every role fails to reach the provider.
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
- **`OFFENSIVE-TOOL-NAME` never fired on real Windows evidence.** It compared the whole
  `process_name` against bare names like `mimikatz.exe`, but Sysmon `Image` and
  Security 4688 `NewProcessName` are full paths. It now matches the basename.
- **One unreadable EVTX record no longer discards the whole log.** python-evtx
  cannot render some record types written by current Windows (e.g. substitution
  type 132 in a stock Windows 11 System log); that used to fail the entire file,
  so the evidence produced zero events. Such records are now skipped and counted
  in a warning. On a real 20 MB System log: 0 → 37,601 events (636 skipped).
- Recovered FTP/Telnet/POP3 usernames are now attached to the cleartext-credential
  event (the `USER` line precedes `PASS` in a separate packet), so the account
  reaches the entity graph. Found while validating against real captures.
- `netforensicai.__version__` reported `0.1.0` regardless of the installed version;
  it is now read from the package metadata.

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

[Unreleased]: https://github.com/Sh3n0bi/NetForensicAI/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Sh3n0bi/NetForensicAI/releases/tag/v0.5.0
[0.4.0]: https://github.com/Sh3n0bi/NetForensicAI/releases/tag/v0.4.0
[0.3.0]: https://github.com/Sh3n0bi/NetForensicAI/releases/tag/v0.3.0
