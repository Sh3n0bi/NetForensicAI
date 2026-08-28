<div align="center">

# NetForensicAI

**A local-first DFIR investigation platform that correlates network and endpoint evidence into one traceable timeline, entity graph, and evidence-cited findings.**

[![Tests](https://github.com/Sh3n0bi/NetForensicAI/actions/workflows/tests.yml/badge.svg)](https://github.com/Sh3n0bi/NetForensicAI/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[Quick Start](#quick-start) · [Worked Example](#a-worked-investigation) · [Architecture](#architecture) · [Capabilities](#capabilities) · [Commands](#command-reference) · [AI Safety](#ai-safety-model) · [Limitations](#limitations)

</div>

---

## Contents

- [What it is](#what-it-is) · [The problem](#the-problem) · [Design principles](#design-principles)
- [Installation](#installation) · [Quick start](#quick-start) · [A worked investigation](#a-worked-investigation)
- [Architecture](#architecture)
- [Capabilities](#capabilities) · [Wireshark integration](#wireshark-integration)
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

### Wireshark (optional, external)

Wireshark is **not** a pip extra — it is a separate program, and NetForensicAI uses three binaries from it. All are optional; install none and the pure-Python path handles everything.

| Binary | Used for | Without it |
|---|---|---|
| **`tshark`** | Dissection, display filters, slices, object export | Falls back to the built-in scapy engine |
| **`dumpcap`** | Live capture | Falls back to the scapy sniffer |
| **`Wireshark`** *(GUI)* | The `wireshark open` pivot only | `--print` still gives you the command to run elsewhere |

**`tshark` is the one that matters.** It carries the whole analysis path, so a server, container, or CI runner only needs that — no GUI, no Qt, no desktop stack:

```bash
sudo apt install tshark          # Debian / Ubuntu
sudo dnf install wireshark-cli   # Fedora / RHEL
brew install wireshark           # macOS (CLI tools; add --cask for the GUI)
```

On a Windows analyst workstation the [standard Wireshark installer](https://www.wireshark.org/download.html) provides all three. It does not add itself to `PATH`, which is fine — NetForensicAI checks `C:\Program Files\Wireshark` directly.

Check what was found and which engines are live:

```bash
netforensic wireshark status
```

```
Wireshark: 4.6.8
  tshark:  C:\Program Files\Wireshark\tshark.exe
  dumpcap: C:\Program Files\Wireshark\dumpcap.exe
  GUI:     C:\Program Files\Wireshark\wireshark.exe
Parse engine:   tshark (requested: auto)
Capture engine: dumpcap
```

See [Wireshark integration](#wireshark-integration) for what each one changes.

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

## A worked investigation

One capture, start to finish. Output below is real, from a small capture containing an HTTP download and a TLS handshake.

**1. Open a case and register the evidence.** The file is copied, hashed, and never modified again:

```bash
netforensic case create --name "Suspicious outbound activity" --investigator analyst
netforensic evidence add ./capture.pcap --case INC-0001
```

```
Ingested EV-0001: capture.pcap
  Type:      pcap
  SHA256:    555291419e0fc99d9c080adb4ca0d86c2fc55e78ff653ced3f066e3a421c93f6
```

**2. Analyze** — parse, extract entities, correlate, and run detection rules in one step:

```bash
netforensic analyze --case INC-0001
```

```
  EV-0001 (pcap): 8 events, 15 entities
Analysis complete for INC-0001: 8 events, 15 distinct entities
Correlation: 21 related, 0 possible_relationship (time-proximity only)
Detections: none.
```

**3. Read the timeline.** One chronological view, filterable by entity, type, or evidence item:

```bash
netforensic timeline show --case INC-0001
```

```
2023-11-14T22:13:20.300000+00:00  http_request     EV-0001  HTTP GET http://evil.example.com/malware.exe (User-Agent: curl/8.0)
2023-11-14T22:13:20.400000+00:00  http_response    EV-0001  HTTP 200 OK for http://evil.example.com/malware.exe
2023-11-14T22:13:20.500000+00:00  tls_handshake    EV-0001  TLS ClientHello for c2.badguy.net
unknown                           file_transfer    EV-0001  Recovered 45-byte file 'malware.exe' from HTTP traffic via Wireshark object export
```

The download was **recovered as a real file**, not guessed at from magic bytes — that is tshark's object export. It is written to the case's `artifacts/` directory and hashed.

**4. Pivot on an entity** to see everything the case knows about it:

```bash
netforensic investigate --case INC-0001 --domain evil.example.com
```

```
Entity: domain 'evil.example.com' (ENT-domain-2dbe0e7fa5fb)
  Events:     1
Related Entities:
  ip_address        93.184.216.34                       (1 shared events)
  url               http://evil.example.com/malware.exe (1 shared events)
```

**5. Narrow the evidence.** A display filter carves a new, hashed capture recorded against its parent and the exact filter that produced it:

```bash
netforensic wireshark slice --case INC-0001 --evidence EV-0001 --display-filter 'http'
```

```
Wrote 2 packet(s) to cases/INC-0001/slices/EV-0001-slice.pcap
Added as EV-0002 - parse it with:
  netforensic parse --case INC-0001 --evidence EV-0002
```

**6. Look at the actual packets** behind any event, pre-filtered to that event's own frames:

```bash
netforensic wireshark open --case INC-0001 --event EVT-EV-0001-000001
```

**7. Record a finding and export.** Nothing above created a finding — that stays an explicit human act:

```bash
netforensic finding create --case INC-0001 --title "Executable retrieved from evil.example.com" \
    --severity High --event EVT-EV-0001-000001
netforensic report generate --case INC-0001 --format html
netforensic case audit --case INC-0001 --verify     # chain of custody intact?
```

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
│   ├── capture.py       Live capture with rotating windows (dumpcap · scapy)
│   ├── export.py        Portable case archives
│   └── config.py        API keys and preferences (outside cases/)
├── integrations/
│   └── wireshark.py     Tool discovery, display filters, slices, GUI pivot
├── parsers/             base · pcap_engine (dispatch) · pcap (scapy) ·
│                        pcap_tshark · generic (JSON/CSV) · evtx
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
| `.pcap` / `.pcapng` | Two interchangeable engines — **tshark** when Wireshark is installed, **scapy** (pure Python, no external binary) otherwise. Single streaming pass either way. See [Wireshark integration](#wireshark-integration). |
| `.json` | Array, `{"events": [...]}`-wrapped, or single object. Case/separator-insensitive field aliasing (`src_ip` / `SourceIP` / `source_ip` all match). |
| `.csv` | Same aliasing, one event per row. |
| `.evtx` | Sysmon (ProcessCreate, NetworkConnection, ProcessTerminate, FileCreate, DNSQuery) gets rich field mapping; every other provider gets universal System fields plus full raw EventData. Pure Python, so Windows logs can be analyzed from any OS. |

Adding a fifth format means one `BaseParser` subclass — entity extraction, correlation, timeline, detections, and reporting need no changes.

### Network protocol analysis
The pcap parser has two engines. Neither is a superset of the other, so neither is hardcoded — `auto` picks tshark when Wireshark is installed and scapy when it is not, and `--engine` pins either one.

**scapy engine** — pure Python, works from a plain `pip install`, and produces **eight event types**, over both **IPv4 and IPv6**:

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

**tshark engine** — Wireshark's ~3000 dissectors instead of eight hand-written analyses. Same Common Event Model, same streaming, and it adds what the scapy engine structurally cannot see:

| Event type | What the tshark engine adds |
|---|---|
| `authentication` | **Kerberos and NTLM attempts** — principal, realm, workstation. Lateral movement *is* authentication traffic; to the scapy engine a Kerberoasting run is an unremarkable TCP flow to port 88. |
| `file_access` | SMB file opens, reads and writes, naming the share path touched. |
| `file_transfer` | **Real object export** (HTTP, SMB, FTP-DATA, TFTP, IMF) — the dissector knows where each object begins and ends, rather than inferring it from magic bytes. |
| `network_connection` | Wireshark's own protocol stack per flow (`eth:ethertype:ip:tcp:tls:http2`), so an unfamiliar flow is identifiable without reopening the capture. |

Everything else — DNS, HTTP request/response pairing, TLS SNI, flow aggregation, anomaly scoring — is produced by both engines, **under the same event-type names**, so a timeline filter or a detection rule behaves identically whichever engine ran. Every event also records which engine produced it in `raw_event_reference.engine`, because *"which dissector found this"* is a question a report has to answer months later.

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

Two backends, selected the same way the parser selects an engine:

| Backend | Notes |
|---|---|
| `dumpcap` | Wireshark's capture engine, preferred when installed. Does the packet copying and the rotation itself, in C, using its own ring buffer — so no packet is lost at a window boundary the way a Python-side rotation can lose one. It is also the one small program Wireshark isolates capture privileges into. |
| `scapy` | Pure-Python fallback. Every packet crosses into Python to be written, which is what limits it on a busy link. |

With dumpcap present, `--list-interfaces` also shows Wireshark's human-readable interface descriptions — which is what makes a Windows `\Device\NPF_{GUID}` identifiable as a particular NIC.

> Requires a packet-capture driver (Npcap / libpcap) and elevated privileges. This tool installs neither and grants neither.

### Case portability
Export a whole case to one zip archive with a SHA-256 manifest of every file. Import verifies **every** file against that manifest before writing anything, so a tampered or corrupted archive is rejected outright rather than partially extracted.

---

## Wireshark integration

Optional and auto-detected. Install Wireshark and NetForensicAI starts using it; don't, and every feature below simply isn't offered while the rest of the platform works unchanged. Nothing here installs, downloads, or elevates anything.

### tshark, not the GUI

The integration is built on **`tshark`** — Wireshark's command-line engine — plus **`dumpcap`** for capture. The desktop GUI is used for exactly one thing: opening a capture for you to look at, when you ask it to. Everything else runs headless.

That matters in practice: a server, container, or CI runner installs `tshark` alone and gets the entire analysis path. See [Installation](#wireshark-optional-external) for per-platform commands, and run `netforensic wireshark status` to see what was detected.

### What it adds

| | |
|---|---|
| **Dissection** | tshark's ~3000 protocol dissectors replace eight hand-written analyses — see [Network protocol analysis](#network-protocol-analysis). |
| **Live capture** | dumpcap replaces the scapy sniffer — see [Live capture](#live-capture). |
| **Display filters** | Wireshark's filter language, validated by tshark itself, both to narrow a parse and to carve evidentiary slices. |
| **GUI pivot** | Open the capture behind any finding in Wireshark, pre-filtered to the exact packets that finding was drawn from. |

### Display filters

Filters can narrow ingestion, which is how a focused subset of a very large capture gets analyzed without carving it first:

```bash
netforensic parse --case INC-0001 --evidence EV-0001 --display-filter 'ip.addr == 10.0.0.5 && tcp.port == 445'
```

Or carve a slice, which is the *evidentiary* form. The slice is a real capture file, so it goes back through the normal evidence path — hashed, recorded against its parent and the exact filter that produced it, and analyzable on its own. That is what makes "I filtered the capture down to this" reproducible by someone else later, which a screenshot of a filtered GUI is not:

```bash
netforensic wireshark slice --case INC-0001 --evidence EV-0001 --display-filter 'dns.qry.name contains "evil"'
```

A filter that matches nothing writes nothing: an empty capture in the chain of custody would imply something was found. Asking for a display filter while the scapy engine is in use is an **error**, not a silent no-op — being handed every packet while believing you filtered is the worst possible outcome.

### GUI pivot

```bash
netforensic wireshark open --case INC-0001 --event EVT-EV-0001-000042
```

The filter is derived from the event's own recorded frame numbers, so what opens is exactly the traffic behind the finding rather than something that merely resembles it. `--print` emits the command instead of launching, for use over SSH or in a report.

The web UI deliberately **does not** launch the GUI. It returns the filter and the command for you to run: a browser page must not be able to spawn a desktop application on the machine running the server, and "it's bound to localhost" is a deployment detail, not a guarantee.

### Discovery

PATH first, then the standard install directories (including `C:\Program Files\Wireshark`, which the Windows installer does not add to PATH). Override with `NETFORENSIC_WIRESHARK_DIR`, or point at individual binaries with `NETFORENSIC_TSHARK` / `NETFORENSIC_DUMPCAP` / `NETFORENSIC_WIRESHARK`.

Requesting a specific engine that isn't installed is an error rather than a silent fallback — an analyst who passed `--engine tshark` is asking for a reproducible dissection, and quietly substituting a different one would put results in a report that the command printed beside them cannot reproduce.

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
netforensic parse --case INC-0001 --evidence EV-0001 [--engine auto|tshark|scapy] [--display-filter '...']
```

**Analysis**
```bash
netforensic analyze --case INC-0001                 # parse + correlate + detect
netforensic analyze --case INC-0001 --engine tshark # pin the dissection engine
netforensic timeline build --case INC-0001
netforensic timeline show  --case INC-0001 [--user ...] [--ip ...] [--type ...] [--evidence EV-0001]
netforensic detections list --case INC-0001 [--severity high]
```

**Wireshark** *(only available when Wireshark is installed — see [Wireshark integration](#wireshark-integration))*
```bash
netforensic wireshark status                        # what was found, which engines are live
netforensic wireshark check-filter 'tls.handshake.extensions_server_name contains "c2"'
netforensic wireshark open  --case INC-0001 --event EVT-EV-0001-000042   # or --evidence EV-0001, + --print
netforensic wireshark slice --case INC-0001 --evidence EV-0001 --display-filter 'dns'
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
netforensic capture --case INC-0001 --engine dumpcap|scapy   # default: auto
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

Engine selection is a saved setting rather than a key, and follows **explicit flag → environment variable → saved config → `auto`**:

| Setting | Environment variable | Values |
|---|---|---|
| pcap dissection engine | `NETFORENSIC_PCAP_ENGINE` | `auto`, `tshark`, `scapy` |
| Live capture backend | `NETFORENSIC_CAPTURE_ENGINE` | `auto`, `dumpcap`, `scapy` |
| Wireshark install directory | `NETFORENSIC_WIRESHARK_DIR` | a path |

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
- **The two pcap engines do not produce identical output.** That is the point — tshark sees protocols the scapy engine cannot — but it means a case re-analyzed under a different engine will not have identical events. Each event records the engine that produced it, and `--engine` pins one when reproducibility matters.
- **tshark object export runs as a second pass** over the capture. It keeps the streaming parse's memory profile intact, at the cost of reading the file twice when an output directory is given.
- **Exported objects carry no timestamp.** tshark's object export reports the recovered file but not the frame it completed on, so `file_transfer` events from it sort at the end of the timeline as `unknown` rather than in position. A wrong timestamp on forensic evidence is worse than an absent one, so none is invented — the parent flow's events carry the timing.

---

## Testing

```bash
pip install -e ".[dev,pcap,intel,evtx,ai,ai-openai,ai-gemini,web]"
pytest
```

**486 tests**, run in CI against Python 3.9 and 3.12, plus a dedicated job that installs tshark so the Wireshark integration is genuinely exercised rather than skipped, and a packaging check that installs the built wheel into a clean environment and confirms the web UI's assets are actually bundled.

The suite favours real fixtures over mocks: pcaps built with scapy, EVTX from hand-crafted XML matching the real schema, cases from `tmp_path`, and real tshark invocations wherever Wireshark is present. Mocks are reserved for what genuinely cannot be exercised in CI — external APIs, and opening a live network interface.

Several classes of bug were found only by running against real evidence and real tooling rather than synthetic fixtures — silently-dropped IPv6, HTTPS payloads skipped because scapy re-dissects them, DNS missed off port 53, a quadratic insert that made a 30 MB file take over 15 minutes, and a live-capture counter that reported the session total in the per-window field. Each is now pinned by a regression test.

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
