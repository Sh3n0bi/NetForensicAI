<div align="center">

# NetForensicAI

**A local-first DFIR investigation platform that correlates network and endpoint evidence into one traceable timeline, entity graph, and evidence-cited findings.**

[![Tests](https://github.com/Sh3n0bi/NetForensicAI/actions/workflows/tests.yml/badge.svg)](https://github.com/Sh3n0bi/NetForensicAI/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[Quick Start](#quick-start) · [Architecture](#architecture) · [Capabilities](#capabilities) · [Commands](#command-reference) · [AI Safety](#ai-safety-model) · [Limitations](#limitations)

</div>

---

## Contents

- [What it is](#what-it-is) · [The problem](#the-problem) · [Design principles](#design-principles)
- [Installation](#installation) · [Quick start](#quick-start)
- [Architecture](#architecture)
- [Capabilities](#capabilities)
- [Command reference](#command-reference) · [Configuration](#configuration)
- [AI safety model](#ai-safety-model) · [Performance](#performance) · [Limitations](#limitations)
- [Testing](#testing) · [Contributing](#contributing) · [Security policy](#security-policy) · [License](#license)

---

## What it is

NetForensicAI takes raw digital evidence — packet captures, JSON/CSV logs, Windows Event Logs including Sysmon — and turns it into a single correlated investigation: normalized events, extracted entities, a unified timeline, an entity relationship graph, deterministic detections, and investigator-owned findings you can export as a report.

It runs entirely on your machine. No cloud backend, no mandatory external service, and no step that touches the network unless you explicitly opt into one.

## The problem

Real investigations span evidence formats that share no schema, no identifiers, and no notion of which events relate to which. Answering *"is the IP in this pcap the same host as the one in that log line?"* by hand is slow and error-prone, and the reasoning usually lives in someone's head rather than in the case.

NetForensicAI does that stitching mechanically and keeps every resulting claim traceable to the specific evidence file and event it came from.

## Design principles

| Principle | What it means in practice |
|---|---|
| **Deterministic first** | Parsing, correlation, timeline, and detections involve no AI and no network. Identical input produces identical output. |
| **Everything cites evidence** | No claim appears without the `evidence_id` / `event_id` it rests on. |
| **Never overstate certainty** | Correlation says `related` or `possible_relationship`, never "caused". Detections are flags, not verdicts. |
| **The investigator decides** | Nothing auto-creates a finding. AI proposes; a human confirms. |
| **Local-first, no infrastructure** | One DuckDB file plus a directory per case. No queue, no graph DB, no daemon. |
| **Honest about limits** | Known weaknesses are documented here and in code, not hidden. |

---

## Installation

**From PyPI** *(once a release is published — see [CONTRIBUTING.md](CONTRIBUTING.md))*

```bash
pip install "netforensicai[pcap,intel,web]"
```

**From source**

```bash
git clone https://github.com/Sh3n0bi/NetForensicAI.git
cd NetForensicAI
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[pcap,intel,web]"
```

### Extras

Everything beyond case management and the CLI core is optional.

| Extra | Pulls in | Needed for |
|---|---|---|
| `pcap` | scapy, pandas, scikit-learn | pcap/pcapng parsing, live capture |
| `evtx` | python-evtx | Windows Event Log / Sysmon parsing |
| `intel` | requests | VirusTotal lookups |
| `ai` | anthropic, requests | AI assistant — Anthropic and Ollama providers |
| `ai-openai` | openai | AI assistant — OpenAI provider |
| `ai-gemini` | google-genai | AI assistant — Google Gemini provider |
| `web` | flask | Local web UI |
| `dashboard` | dash, plotly | Legacy `netforensic scan` visualization |
| `dev` | pytest | Test suite |
| `build` | build, twine | Packaging a release (maintainers) |

Only `intel`, `ai`, `ai-openai`, and `ai-gemini` can reach the network, and only when you explicitly invoke the feature that uses them. Ollama's traffic stays on your machine.

---

## Quick start

### Command line

```bash
netforensic case create --name "Test Incident"
netforensic evidence add ./capture.pcap --case INC-0001
netforensic analyze --case INC-0001
netforensic detections list --case INC-0001
netforensic investigate --case INC-0001 --ip 192.168.1.10
netforensic finding create --case INC-0001 --title "..." --event EVT-...
netforensic report generate --case INC-0001 --format html
```

### Browser

```bash
netforensic web --cases-dir cases      # then open http://127.0.0.1:8000
```

1. **Settings** *(top right)* — optionally add VirusTotal / AI keys and press **Test**. Everything except threat intel and the AI assistant works with no keys at all.
2. **Cases** — create or open a case, then **Evidence → Choose File → Upload Evidence**.
3. **Run Analyze** — parses, correlates, and runs detection rules in one step.
4. Review **Timeline**, **Entities**, **Detections**, **ATT&CK**, **Custody**; record **Findings**; export a **Report**.

---

## Architecture

```
                        ┌──────────────┐          ┌──────────────┐
                        │    Web UI    │          │     CLI      │
                        └──────┬───────┘          └──────┬───────┘
                               └────────────┬────────────┘
                                            │  both call the same core
                ┌───────────────────────────▼───────────────────────────┐
                │                     Case Manager                      │
                │   INC-####  ·  chain of custody  ·  export / import    │
                └───────────────────────────┬───────────────────────────┘
                                            │
                ┌───────────────────────────▼───────────────────────────┐
                │   Evidence Store    SHA-256 · read-only · provenance   │
                └───────────────────────────┬───────────────────────────┘
                                            │
          ┌──────────────┬──────────────────┼──────────────────┬──────────────┐
          ▼              ▼                  ▼                  ▼              ▼
     PCAP/PCAPNG       JSON                CSV            EVTX/Sysmon    Live Capture
          │              │                  │                  │              │
          └──────────────┴──────────────────┼──────────────────┴──────────────┘
                                            │
                ┌───────────────────────────▼───────────────────────────┐
                │        Normalization  ·  Common Event Model           │
                │  flows · DNS · HTTP · TLS · files · processes · logs   │
                └───────────────────────────┬───────────────────────────┘
                                            │  streamed in batches
                ┌───────────────────────────▼───────────────────────────┐
                │              DuckDB  ·  one file per case             │
                │ events · entities · links · detections · ATT&CK · TI   │
                └───────────────────────────┬───────────────────────────┘
                                            │
          ┌──────────────┬──────────────────┼──────────────────┬──────────────┐
          ▼              ▼                  ▼                  ▼              ▼
      Entities      Correlation          Timeline          Detections    Artifacts
    (11 types)   related / possible    chronological     deterministic  carved files
          └──────────────┴──────────────────┼──────────────────┴──────────────┘
                                            │
                    ┌───────────────────────▼───────────────────────┐
                    │   Investigation  ·  1-hop graph  ·  leads      │
                    └───────────────────────┬───────────────────────┘
                                            │
                    ┌───────────────┬───────┴───────┬───────────────┐
                    ▼               ▼               ▼               ▼
              Threat Intel      ATT&CK        Optional AI      (all opt-in)
               VirusTotal       mapping    hedged hypothesis
                    └───────────────┴───────┬───────┴───────────────┘
                                            │
                    ┌───────────────────────▼───────────────────────┐
                    │       Human Validation  ·  Findings           │
                    └───────────────────────┬───────────────────────┘
                                            │
                    ┌───────────────────────▼───────────────────────┐
                    │      Report  ·  Markdown / JSON / HTML        │
                    └───────────────────────────────────────────────┘
```

**No message queue, no microservices, no graph database.** A case is one DuckDB file plus a directory of JSON manifests and evidence copies. The "graph" is a SQL join.

### Module layout

```
netforensicai/
├── core/
│   ├── case.py          Case lifecycle, INC-#### IDs, on-disk layout
│   ├── evidence.py      Ingest, SHA-256, read-only copies, provenance
│   ├── audit.py         Chain of custody (append-only, hash-chained)
│   ├── event.py         Common Event Model
│   ├── store.py         DuckDB access, bulk insert, streaming cursors
│   ├── pipeline.py      Shared evidence → events → entities ingestion
│   ├── entities.py      Entity extraction and deterministic IDs
│   ├── correlation.py   Sliding-window pairing, shared-entity links
│   ├── timeline.py      Chronological view and filters
│   ├── detections.py    Bundled offline rules (per-event + aggregate)
│   ├── attack.py        MITRE ATT&CK technique mapping
│   ├── investigate.py   Entity-scoped investigation and leads
│   ├── threat_intel.py  Opt-in enrichment with caching
│   ├── ai_assistant.py  Multi-provider AI with evidence contract
│   ├── finding.py       Investigator-owned findings
│   ├── report.py        Markdown / JSON / HTML rendering
│   ├── capture.py       Live capture with rotating windows
│   ├── export.py        Portable case archives
│   └── config.py        API keys and preferences (outside cases/)
├── parsers/             base · pcap · generic (JSON/CSV) · evtx
├── web/                 Flask API + dependency-free frontend
└── cli.py               Typer command surface
```

### On-disk layout

```
cases/INC-0001/
├── case.json            Case metadata and indexes
├── audit.log            Chain of custody (JSONL, hash-chained)
├── case.duckdb          Events, entities, correlation, detections, ATT&CK, TI
├── evidence/EV-0001/
│   ├── manifest.json    Hash, size, provenance
│   └── original/        Read-only copy of the source file
├── artifacts/           Files carved out of evidence
├── timeline/            Materialized timeline
├── findings/            One JSON per finding
└── reports/             Generated reports
```

---

## Capabilities

### Case management
`INC-####` cases with a predictable layout. Every case is self-contained and portable.

### Evidence integrity
On ingest the source file is **copied** (never opened for writing), SHA-256 hashed from that copy, and made read-only. `report generate` re-verifies every hash each time it runs — a report cannot be produced without re-checking that nothing was tampered with, and a mismatch is stated plainly in the report rather than silently ignored.

### Chain of custody
An **append-only, hash-chained** record of every action taken on a case, stored as JSON Lines. Each entry carries actor, UTC timestamp, and the SHA-256 of the previous entry.

Recorded: case created · evidence added *(full hash + original source path)* · evidence parsed · findings created and changed *(with from → to)* · ATT&CK scanned and validated · threat-intel lookups · AI hypotheses *(including failures)* · reports written · capture start/stop · export · import.

```bash
netforensic case audit --case INC-0001            # full record
netforensic case audit --case INC-0001 --verify   # exit 0 intact, 1 if altered
```

Editing or deleting an entry breaks every link after it, and `--verify` names exactly which. The chain **continues across an export/import handover** rather than restarting, so custody spans the transfer.

> **Scope, honestly:** this detects accidental corruption and casual after-the-fact editing. It is *not* a defence against an attacker who controls the machine — they could recompute the whole chain. That is the accurate claim for a local single-investigator tool.

### Evidence parsers
All parsers normalize into one **Common Event Model**: `event_id`, `evidence_id`, `source`, `event_type`, `timestamp`, plus optional user/host/device, network (src/dst IP + port, protocol), process (name, PID, parent, command line), file (name, path, hash), domain/URL, severity/message, and `raw_event_reference` pointing back to the exact original record.

| Format | Notes |
|---|---|
| `.pcap` / `.pcapng` | scapy-based, pure Python — no tshark required. Single streaming pass. |
| `.json` | Array, `{"events": [...]}`-wrapped, or single object. Case/separator-insensitive field aliasing (`src_ip` / `SourceIP` / `source_ip` all match). |
| `.csv` | Same aliasing, one event per row. |
| `.evtx` | Sysmon (ProcessCreate, NetworkConnection, ProcessTerminate, FileCreate, DNSQuery) gets rich field mapping; every other provider gets universal System fields plus full raw EventData. Pure Python, so Windows logs can be analyzed from any OS. |

Adding a fifth format means one `BaseParser` subclass — entity extraction, correlation, timeline, detections, and reporting need no changes.

### Network protocol analysis
The pcap parser produces **eight event types**, over both **IPv4 and IPv6**:

| Event type | What it captures |
|---|---|
| `network_connection` | One per distinct flow — TCP, UDP **and ICMP** — with packet and byte counts. Includes flows with no payload at all (handshakes, ACKs), which are most of real traffic. |
| `dns_query` | Queried name → `domain`. Detected **by payload, not port**, so DNS tunnelling off port 53 is caught. |
| `dns_response` | What the name actually resolved to — the mapping that links a domain in one evidence item to an IP in another. |
| `http_request` | Host → `domain`, full URL → `url`, User-Agent retained. Matched on the request line, so it works on **any** port. |
| `http_response` | Status code, paired back to the URL it answered — what separates a failed scan from a successful one. |
| `tls_handshake` | SNI hostname → `domain`, usually the only identifying detail recoverable from encrypted traffic. |
| `file_transfer` | Files carved from TCP streams by magic bytes (PDF, PNG, JPG, ZIP, EXE, GIF), optionally written to `artifacts/`. |
| `anomaly` | IsolationForest outliers over size / inter-arrival / ports. Small captures only — see [Limitations](#limitations). |

Also handled: VLAN (802.1Q) tags, IP fragments, pcapng containers, truncated captures *(keeps what was read)*, and malformed payloads *(never aborts the parse)*.

### Entity extraction & correlation
Eleven entity types — user, hostname, device, IP address, domain, URL, file, hash, process, port, network connection — each linked to the events it appears in. Entity IDs derive deterministically from type + normalized value, so the same real-world entity resolves to the same ID across every evidence source. **That is the mechanism that makes cross-source correlation work.**

Correlation links events within a time window and is explicit about strength:

- **`related`** — shares an entity *and* is time-proximate
- **`possible_relationship`** — time-proximate only

Neither implies causality, and the reports say so.

### Timeline
One chronological view across all evidence, filterable by time range, user, IP, hostname, process, file, event type, or evidence source.

### Detection rules
Local, deterministic, zero-cost pattern matches. **No AI, no network call.** They run automatically on every `analyze` — unlike ATT&CK mapping, which is opt-in.

**Per-event rules**

| Rule | Fires on |
|---|---|
| `OFFENSIVE-TOOL-NAME` | Process names of credential-access / lateral-movement tooling |
| `SUSPICIOUS-PORT` | Ports historically associated with C2 frameworks |
| `DOUBLE-EXTENSION-FILE` | Executables disguised as documents (`invoice.pdf.exe`) |
| `CREDENTIAL-ARTIFACT` | SAM hive, `ntds.dit`, lsass dumps |

**Aggregate rules** — these summarize across many events, because emitting one detection per packet would bury a 41,000-request scan under 41,000 identical rows.

| Rule | Fires on |
|---|---|
| `ATTACK-TOOL-USER-AGENT` | Scanner / exploitation tooling by User-Agent (gobuster, sqlmap, nikto, ffuf, nmap, hydra…) |
| `HTTP-PATH-ENUMERATION` | One source requesting many distinct paths from one host |
| `SQL-INJECTION-ATTEMPT` | Injection payloads, **URL-decoded** first. Rated *high* only when the server actually returned success — intent and impact are different findings. |
| `SCAN-SUCCESSFUL-PATHS` | The paths that returned success amid a 404-heavy scan — *what the scan actually found* |

### MITRE ATT&CK mapping
Deterministic, rule-based, evidence-cited suggestions — never an automated "this happened" claim. Currently T1059, T1059.001, T1027, T1105. Each carries an investigator-settable status (`potential` / `confirmed` / `rejected`) that survives re-scans.

### Investigation
`netforensic investigate <entity>` returns everything the case knows about one IP, user, hash, host, domain, process, file, or device: related evidence, a scoped timeline, ranked related entities, a 1-hop relationship graph, and deterministic leads — plus optional threat-intel and AI enrichment.

### Threat intelligence
Optional, explicit, cached VirusTotal lookups for IPs and file hashes. Never automatic, never sent evidence content, cached in the case so repeat runs don't re-query. Values are validated as a real IP or MD5/SHA-1/SHA-256 before anything is sent.

### AI assistant
Optional, never on the critical path. Four interchangeable providers — **Anthropic, OpenAI, Ollama (fully local), Google Gemini** — selected per request. See [AI safety model](#ai-safety-model).

### Findings & reporting
Investigator-owned findings (`Open` / `Investigating` / `Confirmed` / `Rejected` / `False Positive` / `Resolved`), each citing specific evidence + event pairs, creatable from CLI or web UI. Reports render to **Markdown, JSON, and HTML**, every section traceable to evidence, with a stated limitations section.

### Web UI
A dependency-free frontend (no CDN, no build step — works offline) over the same core modules the CLI uses:

Overview · Evidence *(upload + analyze)* · Timeline · Entities *(graph + investigate)* · Findings *(create/update)* · Detections · ATT&CK · Custody · Reports · Live Capture · Settings

### Live capture
Rotating pcap capture that auto-ingests each finished window through the **exact same pipeline** as a manually added file — including detection rules, so a match surfaces as an alert within one poll. That makes it a lightweight live-alerting mode with no separate "watch" step.

> Requires a packet-capture driver (Npcap / libpcap) and elevated privileges. This tool installs neither and grants neither.

### Case portability
Export a whole case to one zip archive with a SHA-256 manifest of every file. Import verifies **every** file against that manifest before writing anything, so a tampered or corrupted archive is rejected outright rather than partially extracted.

---

## Command reference

Every command supports `--help` and `--cases-dir` (env `NETFORENSIC_CASES_DIR`, default `cases`).

**Cases**
```bash
netforensic case create --name "Incident" [--description "..."] [--investigator "..."]
netforensic case list
netforensic case audit  --case INC-0001 [--verify]
netforensic case export --case INC-0001 [--output INC-0001.zip]
netforensic case import ./INC-0001.zip [--cases-dir other_cases]
```

**Evidence**
```bash
netforensic evidence add ./file --case INC-0001     # .pcap/.pcapng/.json/.csv/.evtx
netforensic evidence list --case INC-0001
netforensic parse --case INC-0001 --evidence EV-0001
```

**Analysis**
```bash
netforensic analyze --case INC-0001                 # parse + correlate + detect
netforensic timeline build --case INC-0001
netforensic timeline show  --case INC-0001 [--user ...] [--ip ...] [--type ...] [--evidence EV-0001]
netforensic detections list --case INC-0001 [--severity high]
```

**Investigation**
```bash
netforensic investigate --case INC-0001 --ip 192.168.1.10
#   or --user / --hash / --host / --domain / --process / --file / --device
netforensic investigate --case INC-0001 --ip 1.2.3.4 --vt-api YOUR_KEY
netforensic investigate --case INC-0001 --ip 1.2.3.4 --ai --ai-provider ollama
netforensic investigate --case INC-0001 --ip 1.2.3.4 --ai --ai-provider gemini --model gemini-3.6-flash
```

**Findings**
```bash
netforensic finding create --case INC-0001 --title "..." --severity High --event EVT-...
netforensic finding list   --case INC-0001
netforensic finding update --case INC-0001 --finding F-0001 --status Confirmed --note "..."
```

**MITRE ATT&CK**
```bash
netforensic attack scan   --case INC-0001
netforensic attack list   --case INC-0001
netforensic attack update --case INC-0001 --technique T1059.001 --status confirmed
```

**Reports · Capture · Web**
```bash
netforensic report generate --case INC-0001 --format markdown|json|html [--output PATH]
netforensic capture --list-interfaces
netforensic capture --case INC-0001 --interface "\Device\NPF_{...}" --filter "tcp port 443" --rotate-seconds 30
netforensic web --cases-dir cases [--host 127.0.0.1] [--port 8000]
netforensic scan ./capture.pcap [--vt-api KEY] [--save-files] [--no-dashboard]   # legacy standalone
```

---

## Configuration

API keys can be saved once via the web UI's **Settings** page instead of passed per command.

Resolution order: **explicit flag → provider environment variable → saved config**.

| Setting | Environment variable |
|---|---|
| VirusTotal | `VT_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Gemini | `GEMINI_API_KEY` |

Saved keys live in `~/.netforensicai/config.json` (owner read/write where the OS enforces it) — deliberately **outside** the cases directory, so they can never be included in an exported case archive. The web API never returns a saved key to the browser; only whether it is set, and its last four characters.

---

## AI safety model

The AI assistant is the **last, optional** step in the pipeline — never a replacement for any step before it. Providers are interchangeable: Anthropic, OpenAI, a local Ollama server, or Google Gemini.

Every property below is enforced **in code**, identically regardless of which provider answered:

- It only ever sees already-normalized `Event` data for the entity you investigated — **never raw evidence file contents**, and nothing outside that scope.
- Its response is a fixed schema, not free text: `evidence_sufficient`, `claim` (phrased as a possibility), `observed_evidence` (fact, kept separate from interpretation), `confidence`, `alternative_explanation`, `recommended_validation`, `evidence` (the exact evidence/event pairs cited).
- **Every citation is checked against the events actually sent.** A hypothesis citing anything not in that set is rejected outright and never shown. This is code, not a prompt instruction.
- **It never writes a finding.** Turning a hypothesis into one is always an explicit investigator action.
- Every request and its outcome — including failures — is recorded in the chain of custody.

Verified against a live API, not only mocks: a real Gemini response returned citations that passed the contract check, with all safety properties intact.

Transient provider failures (overload, rate limiting) are retried with backoff. Credential errors and retired-model errors are **not** retried — they fail identically every time, so retrying only delays a clear message.

---

## Performance

Measured on a real 30 MB / 88,862-packet capture producing 84,712 events:

| Stage | Result |
|---|---|
| Full `analyze` | **~85 seconds** |
| Ingest peak memory | 166 MB |
| Correlation peak | 387 MB |
| Detections peak | 166 MB |

Parsing is a **single streaming pass** — scapy's fully-dissected packets measure ~18× file size in RAM, so a 1 GB capture would need ~18 GB if loaded up front. Events stream from parser to database in batches, and correlation and detections read back through a cursor, so peak memory tracks working set rather than capture size.

---

## Limitations

Stated plainly, because a forensics tool that hides its weaknesses is worse than one that has them.

- **Correlation is noisy at scale.** It caps at 50,000 pairs and warns when it hits that ceiling. On a capture dominated by one high-volume activity those links are mostly time-proximity noise — detections and the timeline are the better entry points there.
- **Anomaly detection is disabled above ~20,000 packets.** IsolationForest's `contamination` is a *proportion*, so on a large capture it flags a fixed percentage of everything by construction — a quantile, not a finding. It stays on for smaller captures where an outlier means something.
- **HTTP request/response pairing is FIFO per flow.** Correct for ordinary keep-alive traffic; genuinely pipelined requests could mis-pair, so a response's URL is a reference rather than a certainty.
- **Correlation memory is reduced but not constant** — it still holds one entity-link map proportional to the case.
- **ATT&CK coverage is deliberately small** (four techniques). Each was chosen because the signal is specific, not to pad a matrix.
- **EVTX covers five Sysmon event types richly**, everything else generically.
- **The custody hash chain** detects corruption and casual editing, not an attacker who owns the machine.
- **Live capture needs Npcap/libpcap and elevated privileges**, which this tool does not install or grant.

---

## Testing

```bash
pip install -e ".[dev,pcap,intel,evtx,ai,ai-openai,ai-gemini,web]"
pytest
```

**433 tests**, run in CI against Python 3.9 and 3.12, plus a packaging check that installs the built wheel into a clean environment and confirms the web UI's assets are actually bundled.

The suite favours real fixtures over mocks: pcaps built with scapy, EVTX from hand-crafted XML matching the real schema, cases from `tmp_path`. Mocks are reserved for what genuinely cannot be exercised — external APIs and live packet capture.

Several classes of bug were found only by running against real captures rather than synthetic ones — silently-dropped IPv6, HTTPS payloads skipped because scapy re-dissects them, DNS missed off port 53, a quadratic insert that made a 30 MB file take over 15 minutes. Each is now pinned by a regression test.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New features should follow the existing shape: one core module does the work, CLI and web are thin callers, and nothing claims more certainty than the evidence supports.

## Security policy

- Files carved from evidence are **never executed** — they are written as inert bytes.
- Uploaded filenames are sanitized; evidence copies are read-only after hashing.
- No API key is ever hardcoded. Saved keys live outside the cases directory and are never returned to the browser.
- Case and finding IDs are pattern-validated everywhere they are used to build a path, so a crafted ID cannot escape the cases directory.
- VirusTotal values are validated as a real IP or hash before being sent.
- The web UI has no authentication and binds to `127.0.0.1`. Every state-changing request requires a custom header, blocking cross-site request forgery from another open tab — which for a chain-of-custody tool matters more than most.

Found a security issue? Open an issue at [github.com/Sh3n0bi/NetForensicAI/issues](https://github.com/Sh3n0bi/NetForensicAI/issues). This is a community project without a dedicated security contact, so please avoid including real sensitive evidence in a public report.

## License

MIT — see [LICENSE](LICENSE).
