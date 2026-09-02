<div align="center">

# NetForensicAI

**Turn packet captures and endpoint logs into one correlated, evidence-cited investigation — entirely on your own machine.**

[![Tests](https://github.com/Sh3n0bi/NetForensicAI/actions/workflows/tests.yml/badge.svg)](https://github.com/Sh3n0bi/NetForensicAI/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Wireshark: optional](https://img.shields.io/badge/wireshark-optional-informational.svg)](docs/wireshark.md)

[Use cases](#use-cases) · [Install](#installation) · [How it works](docs/architecture.md) · [Worked example](docs/walkthrough.md) · [Commands](docs/commands.md) · [Limitations](#limitations)

</div>

---

## Contents

- [Overview](#overview) · [Use cases](#use-cases) · [Why it exists](#why-it-exists)
- [Installation](#installation) · [Quick start](#quick-start)
- [Limitations](#limitations) · [Testing](#testing) · [Contributing](#contributing)

**Reference:** [Capabilities](docs/capabilities.md) · [Commands](docs/commands.md) · [HTTP API](docs/api.md) · [Wireshark](docs/wireshark.md) · [Architecture & performance](docs/architecture.md) · [Worked example](docs/walkthrough.md)

---

## Overview

NetForensicAI takes raw digital evidence — packet captures, JSON/CSV logs, Windows Event Logs including Sysmon — and turns it into a single correlated investigation: normalized events, extracted entities, a unified timeline, an entity relationship graph, deterministic detections, and investigator-owned findings you can export as a report.

It runs entirely on your machine. **No cloud backend, no daemon, no database server, and no step that touches the network unless you explicitly opt into one.** A case is one DuckDB file plus a directory of JSON manifests and read-only evidence copies.

| | |
|---|---|
| **Input** | `.pcap` / `.pcapng` · `.json` · `.csv` · `.evtx` · live network capture |
| **Output** | Timeline · entity graph · detections · ATT&CK mapping · findings · Markdown / JSON / HTML reports |
| **Interfaces** | CLI (`netforensic`) and a local web UI — both over the same core |
| **Requires** | Python 3.9+. Wireshark optional but recommended. |

---


## Use cases

**Triage a suspicious capture from an alert.** Point it at the pcap, run one command, and read the timeline. Protocol-level events — DNS lookups, HTTP requests and their status codes, TLS SNI, recovered file transfers — come out already normalized, so you start at "what happened" rather than at packet 1.

```bash
netforensic evidence add ./alert-2026-08-28.pcap --case INC-0001 && netforensic analyze --case INC-0001
```

**Tie network activity to what happened on the host.** Add a pcap *and* a Sysmon EVTX export to the same case. Because entity IDs are derived deterministically from normalized values, the same IP or hostname in both sources resolves to the same ID and joins automatically — which is the whole reason the two are worth having in one case.

**Investigate one indicator across everything you hold.** Given an IP, domain, hash, user, host, process, or file, get its first/last seen, a scoped timeline, ranked related entities, a one-hop relationship graph, and deterministic next-step leads.

```bash
netforensic investigate --case INC-0001 --domain suspicious.example.com
```

**Run lightweight live monitoring on a segment.** Rotating capture auto-ingests each finished window through the same pipeline, detection rules included — so a match surfaces as an alert without any separate "watch" mode.

**Analyse a web attack from server-side capture.** Aggregate rules are built for this: they summarize a 41,000-request scan into a handful of findings rather than 41,000 rows, and separately surface *the paths that actually returned success* — what the scan found, not just that it happened.

**Produce a defensible report.** Every claim cites the `evidence_id` and `event_id` it rests on. Evidence is hashed on ingest and never modified; every action is recorded in a hash-chained custody log you can verify. Export the whole case to a zip with a per-file manifest and hand it to someone else.

> **Not a NIDS, not a SIEM.** There is no rule marketplace, no alert queue, no multi-user server, no retention tier. It is an investigator's workbench for evidence you already have.

---


## Why it exists

Real investigations span evidence formats that share no schema, no identifiers, and no notion of which events relate to which. Answering *"is the IP in this pcap the same host as the one in that log line?"* by hand is slow and error-prone, and the reasoning usually lives in someone's head rather than in the case.

NetForensicAI does that stitching mechanically and keeps every resulting claim traceable to the specific evidence file and event it came from.

### Design principles

| Principle | What it means in practice |
|---|---|
| **Deterministic first** | Parsing, correlation, timeline, and detections involve no AI and no network. Identical input produces identical output. |
| **Everything cites evidence** | No claim appears without the `evidence_id` / `event_id` it rests on. |
| **Never overstate certainty** | Correlation says `related` or `possible_relationship`, never "caused". Detections are flags, not verdicts. |
| **The investigator decides** | Nothing auto-creates a finding. AI proposes; a human confirms. |
| **Local-first, no infrastructure** | One DuckDB file plus a directory per case. No queue, no graph DB, no daemon. |
| **Honest about limits** | Known weaknesses are documented [here](#limitations) and in code, not hidden. |

---


## Installation

**From source**

```bash
git clone https://github.com/Sh3n0bi/NetForensicAI.git
cd NetForensicAI
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[pcap,intel,web]"
```

**From PyPI** *(once a release is published — see [CONTRIBUTING.md](CONTRIBUTING.md))*

```bash
pip install "netforensicai[pcap,intel,web]"
```

### Python extras

Everything beyond case management and the CLI core is optional.

| Extra | Pulls in | Needed for |
|---|---|---|
| `pcap` | scapy, pandas, scikit-learn | pcap/pcapng parsing, live capture, anomaly scoring |
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

See [Wireshark integration](docs/wireshark.md) for what each one changes.

---


## Quick start

### Command line

```bash
netforensic case create --name "Test Incident"
netforensic evidence add ./capture.pcap --case INC-0001
netforensic analyze --case INC-0001
netforensic detections list --case INC-0001
netforensic investigate --case INC-0001 --ip 192.168.1.10
netforensic report generate --case INC-0001 --format html
```

### Try it without evidence of your own

`samples/generate_incident.py` builds a synthetic capture containing a complete incident — a lookup of a cheap-TLD domain, an executable pulled over cleartext HTTP, a credential posted in the clear, a private key retrieved, the same password reused on FTP, a customer CSV uploaded in chunks, then eight beacons — plus ordinary browsing, so the capture is not made entirely of findings.

```bash
python samples/generate_incident.py -o incident.pcap
netforensic case create --name "Demo incident"
netforensic evidence add ./incident.pcap --case INC-0001
netforensic analyze --case INC-0001
netforensic story --case INC-0001
```

```
7 distinct findings (5 high severity) across 2 hosts.

Assessment [critical]: Evidence is consistent with data leaving this network
after a credential was exposed.

CREDENTIAL ACCESS
  [high] 22:14:19  One credential used across several protocols
      The same password was observed on FTP, HTTP. Reuse turns a single
      cleartext disclosure into access everywhere that credential is accepted.
      evidence: EVT-EV-0001-000009, EVT-EV-0001-000013
```

A generator rather than a checked-in `.pcap`, deliberately: a binary in a repository is something you take on trust, and this is the same capture expressed as something you can read and diff. The traffic is fabricated end to end — no real host is contacted and nothing is captured from a real network. The credential rules need `tshark`; everything else works without it.


### Browser

```bash
netforensic web --cases-dir cases      # then open http://127.0.0.1:8000
```

1. **Settings** *(top right)* — optionally add VirusTotal / AI keys and press **Test**. Everything except threat intel and the AI assistant works with no keys at all.
2. **Cases** — create or open a case, then **Evidence → Choose File → Upload Evidence**.
3. **Run Analyze** — parses, correlates, and runs detection rules in one step.
4. **What happened** — read the account of the case before the counts: the assessment, the stages
   it passed through, and each finding with the events it rests on.
5. Review **Timeline**, **Entities**, **Detections**, **ATT&CK**, **Custody**; record **Findings**; export a **Report**.

---


## What it does

Each of these is covered properly in [the capability reference](docs/capabilities.md); this is the map.

| | |
|---|---|
| **Evidence integrity** | Copied in, SHA-256 hashed from the stored copy, set read-only, recorded in a manifest. |
| **Chain of custody** | Every action appended to a hash-chained log. `case audit --verify` reports whether it has been altered. |
| **Parsers** | `.pcap`/`.pcapng` (tshark or scapy), `.json`, `.csv`, `.evtx` — all normalized into one Common Event Model. |
| **Search** | Content search over a capture's raw bytes: text, regex, or hex. ~6s across 1,000,000 packets. |
| **Streams** | Conversations reassembled by Wireshark, ranked by volume. |
| **Triage** | The first questions worth asking an unfamiliar capture: protocols, flags, credentials, secrets, recoverable files. |
| **Entities & correlation** | Deterministic IDs join the same real-world thing across evidence sources. Links are `related` or `possible_relationship`, never "caused". |
| **Detections** | Eight offline rules — no AI, no network — run automatically on every `analyze`. |
| **ATT&CK** | Deterministic, evidence-cited technique suggestions with an investigator-settable status. |
| **Assistant** | Retrieves evidence through read-only tools; every claim is checked against what it retrieved, and an answer citing anything else is refused. |
| **Findings & reports** | Investigator-owned findings citing evidence/event pairs; Markdown, JSON and HTML output. |
| **Web UI** | A dashboard over the same core the CLI uses. No build step, no CDN, works offline. |
| **Live capture** | Rotating windows auto-ingested through the same pipeline, detection rules included. |
| **Portability** | Export a case to one zip with a per-file SHA-256 manifest; import verifies every file first. |

---

## Limitations

Stated plainly, because a forensics tool that hides its weaknesses is worse than one that has them.

- **The correlation link count is a ceiling, not a total.** It caps at 50,000 pairs, and on a dense capture it will reach that: tens of thousands of shared-host pairs inside a five-minute window genuinely exist. The budget is now spent on signal first — ports are not correlated on, no entity may take more than a tenth of it, and `related` is never displaced by `possible_relationship` — and both the CLI and the API say when the number is a ceiling. Shorten `--time-window` on a dense case; detections and the timeline are the better entry points either way.
- **Anomaly detection is disabled above ~20,000 packets.** IsolationForest's `contamination` is a *proportion*, so on a large capture it flags a fixed percentage of everything by construction — a quantile, not a finding. It stays on for smaller captures where an outlier means something.
- **HTTP request/response pairing is FIFO per flow.** Correct for ordinary keep-alive traffic; genuinely pipelined requests could mis-pair, so a response's URL is a reference rather than a certainty.
- **Correlation memory is reduced but not constant** — it still holds one entity-link map proportional to the case.
- **ATT&CK coverage is deliberately small** (four techniques). Each was chosen because the signal is specific, not to pad a matrix.
- **EVTX covers five Sysmon event types richly**, everything else generically.
- **The custody hash chain** detects corruption and casual editing, not an attacker who owns the machine.
- **Live capture needs Npcap/libpcap and elevated privileges**, which this tool does not install or grant.
- **Ingest is the scaling limit, not dissection.** tshark reads a 1M-packet capture in 46 seconds; putting those events and their entity links into the store takes about fourteen minutes, and throughput degrades with case size (4,497 events/s at 100k against 1,907/s at 1M) because every entity-link insert probes a growing index. For very large captures the workflow is to **search and slice first, then ingest the slice** — search and `wireshark slice` read the capture file and scale to gigabytes.
- **The assistant has not been exercised against a live provider in this repository's testing.** Its rendering, its tool loop and its refusal path are covered against a scripted model; the HTTP round trip to Anthropic, OpenAI, Gemini or Ollama is not.
- **Exported objects carry no timestamp.** tshark reports the recovered file but not the frame it completed on, so those `file_transfer` events sort at the end of a timeline as `unknown`. A wrong timestamp on forensic evidence is worse than an absent one, so none is invented.
- **The two pcap engines do not produce identical output.** That is the point — tshark sees protocols the scapy engine cannot — but it means a case re-analyzed under a different engine will not have identical events. Each event records the engine that produced it, and `--engine` pins one when reproducibility matters.
- **tshark object export runs as a second pass** over the capture. It keeps the streaming parse's memory profile intact, at the cost of reading the file twice when an output directory is given.
- **Exported objects carry no timestamp.** tshark's object export reports the recovered file but not the frame it completed on, so `file_transfer` events from it sort at the end of the timeline as `unknown` rather than in position. A wrong timestamp on forensic evidence is worse than an absent one, so none is invented — the parent flow's events carry the timing.
- **The web UI has no authentication.** It is a local single-user tool bound to `127.0.0.1` by default; binding it elsewhere exposes every case on the machine.

---


## Testing

```bash
pip install -e ".[dev,pcap,intel,evtx,ai,ai-openai,ai-gemini,web]"
pytest
```

**612 tests**, run in CI against Python 3.9 and 3.12, plus a dedicated job that installs tshark so the Wireshark integration is genuinely exercised rather than skipped, and a packaging check that installs the built wheel into a clean environment and confirms the web UI's assets are actually bundled.

The suite favours real fixtures over mocks: pcaps built with scapy, EVTX from hand-crafted XML matching the real schema, cases from `tmp_path`, and real tshark invocations wherever Wireshark is present. Mocks are reserved for what genuinely cannot be exercised in CI — external APIs, and opening a live network interface.

Several classes of bug were found only by running against real evidence and real tooling rather than synthetic fixtures — silently-dropped IPv6, HTTPS payloads skipped because scapy re-dissects them, DNS missed off port 53, a quadratic insert that made a 30 MB file take over 15 minutes, and a live-capture counter that reported the session total in the per-window field. Each is now pinned by a regression test.

---


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, the parser plugin interface, and the release process.

The shape of a good contribution here: a new `BaseParser` subclass for a format, a detection rule with a specific and defensible signal, or a regression test for a bug found against real evidence.


## Security policy

This is defensive tooling for evidence you are authorized to analyze. It does not exploit, attack, or scan anything.

Nothing leaves your machine unless you explicitly invoke threat intel or a hosted AI provider. Live capture requires privileges the tool does not grant itself. If you find a security issue in NetForensicAI, please open an issue or contact the maintainer rather than disclosing it publicly first.


## License

[MIT](LICENSE).


