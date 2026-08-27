# NetForensicAI

**A local-first, open-source DFIR investigation platform that correlates network and endpoint evidence into a traceable investigation timeline and evidence graph.**

## What is NetForensicAI?

NetForensicAI takes raw digital evidence — pcap captures, JSON/CSV logs, Windows Event Logs (including Sysmon) — and turns it into a single, correlated, evidence-traceable investigation: normalized events, extracted entities (IPs, users, hosts, hashes, processes...), a unified timeline, an entity relationship graph, and investigator-owned findings you can export as a report.

It runs entirely on your own machine. There's no cloud backend, no mandatory external service, and no step that requires network access unless you explicitly opt into one (VirusTotal lookups, the AI assistant).

## The Problem

Real investigations touch multiple evidence formats that don't share a schema, don't share IDs, and don't tell you on their own which events are related. Stitching that together by hand — "does this IP in the pcap match the IP in this log line from a different tool?" — is slow and error-prone. NetForensicAI does that stitching mechanically and keeps every resulting claim traceable back to the specific evidence file and event it came from.

## Core Idea

```
Evidence -> Parsing -> Normalization -> Correlation -> Timeline
    -> Investigation Graph -> Evidence-backed Leads -> Human Validation -> Report
```

The differentiator is not "AI." It's that every step above is deterministic and every output cites the evidence it came from. AI is one optional layer near the end of that pipeline, not a replacement for it — see [AI Safety Model](#ai-safety-model) below.

## Features

- **Case management** — `INC-####` cases with a predictable on-disk layout (`cases/<ID>/evidence,artifacts,timeline,findings,reports/`)
- **Evidence integrity** — every evidence item is SHA-256 hashed on ingest, copied read-only, and re-verifiable at any time (report generation re-checks every hash automatically)
- **Four evidence parsers**, all normalizing into one [Common Event Model](#supported-evidence): pcap, JSON, CSV, and Windows Event Log (EVTX) with dedicated Sysmon field mapping
- **Entity extraction** — users, hostnames, devices, IPs, domains, URLs, files, hashes, processes, ports, and network connections, each linked to the events they appear in
- **Correlation engine** — links events by shared entity + time window, explicit about the difference between `related` (shared entity, time-proximate) and `possible_relationship` (time-proximate only) — never implies causality from either
- **Unified timeline**, filterable by time range, user, IP, hostname, process, file, event type, or evidence source
- **`investigate <entity>`** — everything the case knows about one IP/user/hash/host/domain/process/file/device: related evidence, a scoped timeline, ranked related entities, and deterministic investigation leads
- **Investigator-owned findings** — Open/Investigating/Confirmed/Rejected/False Positive/Resolved, each citing specific evidence+event pairs; create/update from the CLI or the web UI, both calling the same `FindingManager`
- **MITRE ATT&CK technique mapping** — deterministic, rule-based, evidence-cited suggestions (never an automated "this happened" claim), each with an investigator-settable status: potential/confirmed/rejected
- **Threat intelligence** — optional, explicit, cached VirusTotal lookups for IPs and file hashes (never automatic, never sent evidence content)
- **AI investigation assistant** *(optional)* — a hedged hypothesis from Claude, constrained to an evidence contract that makes fabricated citations structurally impossible (see below)
- **Reports** in Markdown, JSON, and HTML, every section traceable to evidence
- **Local web UI** *(optional)* — case overview, evidence (including upload), timeline, entity graph, investigate panel, findings, reports, and live capture, all read from the same case data the CLI uses
- **Live capture** *(optional)* — rotating pcap capture that auto-ingests each finished window through the exact same evidence pipeline as a manually added file

## Architecture

```
                    NetForensicAI
                          |
                    Case Manager
                          |
                     Evidence (SHA-256, read-only, provenance)
                          |
       +------------------+------------------+------------------+
       |                  |                  |                  |
      PCAP               JSON               CSV          EVTX/Sysmon
       |                  |                  |                  |
       +------------------+------------------+------------------+
                          |
                  Normalization Layer  (Common Event Model)
                          |
              Local Database  (DuckDB - events, entities, correlation)
                          |
             +------------+-------------+
             |            |             |
        Artifacts     Correlation    Timeline
             |            |             |
             +------------+-------------+
                          |
                  Investigation Graph  (entity 1-hop neighborhoods)
                          |
                  Investigation Leads  (deterministic, rule-based)
                          |
                   Optional AI  (hedged hypothesis, evidence-contract-checked)
                          |
                   Human Validation  (Findings - investigator-owned)
                          |
                     Case Report  (Markdown / JSON / HTML)
```

No message queue, no microservices, no graph database — a case's data is one DuckDB file plus a directory of JSON manifests and evidence copies. Correlation's 1-hop entity neighborhood is a single SQL join, not a graph engine.

## Installation

From PyPI, once a release is published (see [CONTRIBUTING.md](CONTRIBUTING.md)'s Releasing section):

```bash
pip install "netforensicai[pcap,intel,web]"   # add ,ai and/or ,evtx as you need them
```

Or from source:

```bash
git clone https://github.com/Sh3n0bi/NetForensicAI.git
cd NetForensicAI
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[pcap,intel,web]"   # add ,ai and/or ,evtx as you need them
```

Extras, all optional beyond the CLI/case-management core:

| Extra | Adds | Needed for |
|---|---|---|
| `pcap` | scapy, pandas, scikit-learn | pcap parsing, live capture |
| `intel` | requests | VirusTotal lookups |
| `evtx` | python-evtx | Windows Event Log / Sysmon parsing |
| `ai` | anthropic | The AI investigation assistant |
| `web` | flask | The local web dashboard |
| `dashboard` | dash, plotly | The legacy `netforensic scan` visualization |
| `dev` | pytest | Running the test suite |
| `build` | build, twine | Building/checking a release package (maintainers) |

Nothing outside `pcap`/`evtx`/`intel`/`ai` reaches the network, and none of those do so unless you explicitly invoke the feature that needs them (pcap/EVTX parsing itself is fully offline; only VT lookups and the AI assistant make real network calls, and only when asked).

## Quick Start

```bash
netforensic case create --name "Test Incident"
netforensic evidence add ./attack.pcap --case INC-0001
netforensic evidence add ./events.json --case INC-0001
netforensic analyze --case INC-0001
netforensic timeline show --case INC-0001
netforensic investigate --case INC-0001 --ip 192.168.1.10
netforensic finding create --case INC-0001 --title "..." --event EVT-...
netforensic report generate --case INC-0001 --format markdown
```

Or the same thing from a browser: `netforensic web --cases-dir cases`, then create a case and upload files from the Evidence tab.

## Example Investigation

```
$ netforensic investigate --case INC-0001 --ip 192.168.1.10

Entity: ip_address '192.168.1.10' (ENT-ip_address-a1aab0750bf9)
  First seen: 2026-08-27T09:00:00+00:00
  Last seen:  2026-08-27T09:01:10+00:00
  Events:     2

Related Evidence:
  EV-0001

Timeline:
  2026-08-27T09:00:00+00:00  authentication       user=jdoe hostname=workstation01
  2026-08-27T09:01:10+00:00  network_connection   src_ip=192.168.1.10 dst_ip=203.0.113.7

Related Entities:
  hostname         workstation01        (1 shared events)
  user             jdoe                 (1 shared events)

Potential Investigation Leads:
  - 1 event pair(s) involving this entity share another entity AND fall within
    the correlation time window - review those linked events for a possible
    sequence of activity.
  - Consider checking this IP against VirusTotal or another threat intelligence
    source (--vt-api or VT_API_KEY) if not already done.

Threat Intelligence:
  VirusTotal: not checked (no API key - use --vt-api or set VT_API_KEY)
```

Every line above traces back to a specific evidence file and event — nothing here is inferred without a citation.

## Supported Evidence

All four parsers map into the same **Common Event Model**: `event_id`, `evidence_id`, `source`, `event_type`, `timestamp`, plus optional user/host/device, network (src/dst IP+port, protocol), process (name, PID, parent, command line), file (name, path, hash), domain/URL, severity/message, and `raw_event_reference` pointing back to the exact original record. No parser is forced to populate every field.

| Format | Parser | Notes |
|---|---|---|
| `.pcap` / `.pcapng` | `parsers/pcap.py` | scapy-based (pure Python, no tshark needed): DPI, embedded-file extraction, IsolationForest anomaly detection |
| `.json` | `parsers/generic.py` | Array, `{"events": [...]}`-wrapped, or single-object; case/separator-insensitive field aliasing (`src_ip`/`SourceIP`/`source_ip` all match) |
| `.csv` | `parsers/generic.py` | Same field-aliasing as JSON, one Event per row |
| `.evtx` | `parsers/evtx.py` | Sysmon (ProcessCreate/NetworkConnection/ProcessTerminate/FileCreate/DNSQuery) gets rich field mapping; every other provider/channel gets the universal System fields plus full raw EventData preserved |

Adding a fifth format means implementing one `BaseParser` subclass and registering it — the ingestion pipeline, entity extraction, correlation, timeline, and reporting don't change.

## Evidence Integrity

On ingest, the original file is copied (never opened for writing) into `cases/<ID>/evidence/<EV-ID>/original/`, SHA-256 hashed from that copy, and made read-only. `netforensic report generate` re-verifies every evidence item's hash against its stored copy every time a report is built — a report literally cannot be generated without re-checking that nothing was tampered with, and a mismatch is stated plainly in the report itself rather than silently ignored.

## AI Safety Model

The AI assistant (`netforensic investigate --ai`, optional, requires your own Anthropic API key) is deliberately the last, optional step in the pipeline, not a replacement for any step before it:

- It only ever sees already-normalized `Event` data for the events you selected by investigating an entity — never raw evidence file contents, and never anything outside that entity's scope
- Its response is a structured schema, not free text: `evidence_sufficient`, `claim` (phrased as a possibility, never a certainty), `observed_evidence` (fact, kept separate from interpretation), `confidence`, `alternative_explanation`, `recommended_validation`, and `evidence` (the specific evidence_id/event_id pairs it's citing)
- **Every citation is checked against the events actually sent, after the response comes back.** A hypothesis citing anything not present in that set is rejected outright and never shown — this is enforced in code, not left to the prompt
- It never writes a Finding. Turning a hypothesis into a Finding is always an explicit `netforensic finding create` by the investigator

## Limitations

- Correlation (`related` / `possible_relationship`) means shared entity and/or time proximity — it is never evidence of causality
- ATT&CK technique mapping (`netforensic attack scan`) covers a deliberately small starting set of four techniques (PowerShell execution, generic script/interpreter execution, obfuscated PowerShell command lines, executables transferred over the network) — not an exhaustive ATT&CK matrix; each mapping is a rule match over normalized events, always "potential" until an investigator confirms it
- Threat intelligence results are only ever gathered when you explicitly ask (`--vt-api`, `--ai`) — reports never trigger a new lookup themselves
- The entity relationship view is a 1-hop neighborhood via SQL join, not a full graph traversal
- EVTX support covers the five most common Sysmon event types plus generic System-field fallback for everything else; deeper per-provider mapping (Windows Security auditing event IDs, for example) is a natural future extension of the same pattern, not yet built
- Live capture needs a real packet-capture driver (Npcap/libpcap) and elevated privileges on the machine running it — this tool does not install or grant either

## Roadmap

Roughly in priority order, not committed dates: more ATT&CK rules, deeper EVTX/Sysmon event coverage, and whatever real usage surfaces as actually missing rather than speculatively planned.

## Contributing

Fork the repo, make changes, and submit a pull request — see [CONTRIBUTING.md](CONTRIBUTING.md). Add tests under `tests/`; the suite (`pytest`) should stay green, and new parsers/features should follow the existing pattern of one core module doing the work, thin CLI/web layers calling into it, and no logic duplicated between the two.

## Security Policy

- Extracted files from evidence (embedded files pulled from a pcap, for example) are never executed automatically — they're written to disk as inert bytes
- Uploaded/ingested filenames are sanitized before touching the filesystem; evidence copies are made read-only after hashing
- No API key is ever hardcoded — VirusTotal and Anthropic credentials are read from CLI flags, environment variables, or (for Anthropic) `ant auth login`, never stored in a config file by this tool
- Case IDs are validated against the `INC-####` pattern everywhere a case is loaded (CLI or web), so a crafted case ID can't be used to walk outside the cases directory
- VirusTotal lookups validate that a value actually looks like an IP address or an MD5/SHA-1/SHA-256 hash before it's sent to the API
- The web UI has no authentication and binds to `127.0.0.1` by default; the CLI warns if you point `--host` anywhere else. Every state-changing API request (evidence upload, analyze, live capture, threat intel, AI hypothesis) also requires a custom header the browser frontend sets automatically — this blocks the kind of cross-site request forgery where another open tab silently submits requests to your local instance, which for a chain-of-custody tool matters more than most (forged "evidence" or a silently-started packet capture)
- Found a security issue? Open an issue at [github.com/Sh3n0bi/NetForensicAI/issues](https://github.com/Sh3n0bi/NetForensicAI/issues) — this is a community project without a dedicated security contact, so please avoid including real sensitive evidence data in a public report

## License

MIT — see [LICENSE](LICENSE).
