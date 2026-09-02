[← README](../README.md) · [Capabilities](capabilities.md) · [Commands](commands.md) · [HTTP API](api.md) · [Wireshark](wireshark.md) · [Architecture](architecture.md) · [Walkthrough](walkthrough.md)

---

# Capabilities

## Case management
`INC-####` IDs, one directory per case, a status lifecycle (`open` / `investigating` / `closed`, settable from the CLI or the dashboard), indexes over evidence, findings and artifacts, and irreversible deletion behind a typed confirmation.

## Evidence integrity
Every item is copied in, SHA-256 hashed from the stored copy, set read-only, and recorded in a manifest with its original path and modification time.

## Chain of custody
Every action — case created, evidence added, evidence parsed, analysis run, finding created or updated, report generated, capture started or stopped, threat intel checked, AI hypothesis requested, evidence sliced — is appended to a **hash-chained** `audit.log`. `case audit --verify` reports whether the record has been altered since it was written.

> This detects accidental corruption and casual after-the-fact editing. It does **not** stop an attacker who controls the machine, who could recompute the whole chain.

## Evidence parsers
All parsers normalize into one **Common Event Model**: `event_id`, `evidence_id`, `source`, `event_type`, `timestamp`, plus optional user/host/device, network (src/dst IP + port, protocol), process (name, PID, parent, command line), file (name, path, hash), domain/URL, severity/message, and `raw_event_reference` pointing back to the exact original record.

| Format | Notes |
|---|---|
| `.pcap` / `.pcapng` | Two interchangeable engines — **tshark** when Wireshark is installed, **scapy** (pure Python, no external binary) otherwise. Single streaming pass either way. |
| `.json` | Array, `{"events": [...]}`-wrapped, or single object. Case/separator-insensitive field aliasing (`src_ip` / `SourceIP` / `source_ip` all match). |
| `.csv` | Same aliasing, one event per row. |
| `.evtx` | Sysmon (ProcessCreate, NetworkConnection, ProcessTerminate, FileCreate, DNSQuery) gets rich field mapping; every other provider gets universal System fields plus full raw EventData. Pure Python, so Windows logs can be analyzed from any OS. |

Adding a fifth format means one `BaseParser` subclass — entity extraction, correlation, timeline, detections, and reporting need no changes.

## Network protocol analysis

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
| `anomaly` | IsolationForest outliers over size / inter-arrival / ports. Small captures only — see [Limitations](../README.md#limitations). |

Also handled: VLAN (802.1Q) tags, IP fragments, pcapng containers, truncated captures *(keeps what was read)*, and malformed payloads *(never aborts the parse)*.

**tshark engine** — Wireshark's ~3000 dissectors instead of eight hand-written analyses. Same Common Event Model, same streaming, and it adds what the scapy engine structurally cannot see:

| Event type | What the tshark engine adds |
|---|---|
| `authentication` | **Kerberos and NTLM attempts** — principal, realm, workstation. Lateral movement *is* authentication traffic; to the scapy engine a Kerberoasting run is an unremarkable TCP flow to port 88. |
| `file_access` | SMB file opens, reads and writes, naming the share path touched. |
| `file_transfer` | **Real object export** (HTTP, SMB, FTP-DATA, TFTP, IMF) — the dissector knows where each object begins and ends, rather than inferring it from magic bytes. |
| `network_connection` | Wireshark's own protocol stack per flow (`eth:ethertype:ip:tcp:tls:http2`), so an unfamiliar flow is identifiable without reopening the capture. |

Everything else — DNS, HTTP request/response pairing, TLS SNI, flow aggregation, anomaly scoring — is produced by both engines, **under the same event-type names**, so a timeline filter or a detection rule behaves identically whichever engine ran. Every event also records which engine produced it in `raw_event_reference.engine`, because *"which dissector found this"* is a question a report has to answer months later.

## Content search
Parsing normalizes packets into events and **deliberately keeps no payload** — storing the bytes of every packet would defeat the streaming design. So *"where does this token appear"* has to go back to the capture file, which is what `netforensic search` does, via tshark. Text, regex, or hex:

```bash
netforensic search --case INC-0001 'flag{'
netforensic search --case INC-0001 'flag\{[^}]+\}' --mode regex
netforensic search --case INC-0001 '4d5a9000' --mode hex          # MZ header
netforensic search --case INC-0001 'password' --display-filter 'http'
```

**Measured on a 1,000,000-packet / 132 MB capture: about six seconds.** Every hit reports a frame number *and* a stream index, so a result leads straight to the packets — `wireshark open` takes the frame, `stream follow` takes the stream.

Case-insensitive search compiles to `matches` over an escaped literal rather than to `contains`, because `contains` is a case-sensitive byte match. The alternative — lowercasing the evidence — is not something a forensics tool should do to the bytes it reports on.

## Stream reassembly
A credential or a flag rarely lives in one packet; it lives in a conversation the network split across dozens of them.

```bash
netforensic stream list   --case INC-0001          # ranked by volume
netforensic stream follow --case INC-0001 42
```

Reassembly is delegated to Wireshark rather than reimplemented: retransmissions, overlap and reordering are genuinely hard, and a hand-rolled version would be a subtly wrong copy of something you can check against the GUI.

## Triage presets
The first questions worth asking an unfamiliar capture, in one command — protocol hierarchy (flagging every protocol that carries credentials in the clear), candidate flags, credentials and secrets, recoverable files with hashes, and the largest conversations.

```bash
netforensic ctf triage --case INC-0001
netforensic ctf hunt   --case INC-0001 --category secrets
netforensic ctf patterns
```

Named for the case it serves best — a CTF network challenge — but the questions are the ones that open a real intrusion investigation too.

Two rules it keeps. It **never writes to the case**: nothing here creates a finding, and object export is reported rather than saved unless you pass `--extract-to`. And it reports **candidates, not verdicts** — a regex matching something password-shaped has found a string, so every result names the pattern that matched and the frame it came from, and the judging happens against the packets.

## Entity extraction & correlation
Eleven entity types — `user`, `hostname`, `device`, `ip_address`, `domain`, `url`, `file`, `hash`, `process`, `port`, `network_connection` — each linked to the events it appears in.

Two modelling rules matter more than the list:

- **A source port is not an entity.** It is ephemeral — the OS picks it per socket — so it identifies a connection, never a thing an investigation is about. `dst_port` *is* indexed, because that identifies a service and *"show me everything touching port 4444"* is a real question. Both remain fields on the event, so timeline filters and search are unaffected.
- **`network_connection` is keyed on the host pair**, not the full flow tuple. With ports in the key it was unique per flow, so it could never be *shared* between two events — an entity that by construction correlated with nothing, at one row per event.

Correlation links events within a time window and is explicit about strength:

- **`related`** — shares an entity *and* is time-proximate
- **`possible_relationship`** — time-proximate only

Neither implies causality, and the reports say so.

Three rules keep the link budget spent on signal:

- **A shared port is not a relationship.** On an HTTP capture *"both events touched port 80"* is true of nearly every pair. Measured before this rule on a 3,000-packet capture: 38,782 of 50,000 links were shared-port links, 29,333 of them port 80 alone, against **33** keyed on a shared domain. Ports are indexed; they are not correlated on.
- **No single entity may take more than a tenth of the budget.** Correlation is pairwise, so a high-degree entity produces links *quadratically* — with ports removed, one address took 49,536 of 50,000 links and left 100 for every domain combined.
- **`related` is never displaced by `possible_relationship`.** The weak tier only ever uses budget the strong tier left.

**The link count is a ceiling, not a total.** A number landing exactly on the budget means correlation stopped, and both the CLI and the API say so rather than printing the round number as though it were a finding. On a dense capture, shorten `--time-window`.

## Timeline
One chronological view across all evidence, filterable by time range, user, IP, hostname, process, file, event type, or evidence source.

## Detection rules
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

**Network rules** — the eight rules above grew from endpoint and web-scan evidence and matched nothing on a network intrusion. These cover that surface.

| Rule | Fires on |
|---|---|
| `SUSPICIOUS-TLD` | Domains on TLDs cheap enough to be used in bulk by phishing and malware infrastructure. *Low* on purpose: common in legitimate use too |
| `EXECUTABLE-DOWNLOAD` | An executable retrieved over **cleartext** HTTP. Not the file type alone — flagging every `.exe` would train people to ignore the rule |
| `CLEARTEXT-CREDENTIALS` | A credential crossing the network unencrypted (HTTP form, HTTP Basic, FTP, IMAP, POP, Telnet) |
| `KEY-MATERIAL-IN-TRANSIT` | Private key material by filename or content (`id_rsa`, `BEGIN … PRIVATE KEY`) |
| `OUTBOUND-BULK-TRANSFER` | Volume to an **external** host. Internal-to-internal is a file copy, and flagging it would bury the case that isn't |
| `PERIODIC-BEACON` | Repeated low-volume contact at a machine-regular interval |
| `CREDENTIAL-REUSE` | The **same** password observed on more than one protocol — a join no single-event rule can make |

Three deliberate suppressions, because a rule that cries wolf is worse than no rule:

- **A 0-second interval is not "periodic", it is simultaneous.** A burst of parallel flows is one burst, not a beacon.
- **A chunked upload is regular by nature** but it is an exfiltration, not an implant checking in. Volume separates them.
- **One activity, one finding.** A transfer already reported as bulk is not *also* reported as a beacon.

### How credentials are handled

Normalized events carry no payload by design, so a credential is invisible to a rule reading events — only the parser, holding the dissected packet, ever sees one. The tshark engine therefore emits a `credential_exposure` event carrying a **SHA-256 of the secret, never the secret**.

That is enough to answer *"is this the same credential seen elsewhere"* — which is what makes `CREDENTIAL-REUSE` possible — without putting a working password into a case database that then rides along in every export, report and backup. The plaintext stays in the evidence file, which is already hashed, read-only, and reachable through [content search](#content-search).

**Both engines produce it.** The rules live in `parsers/credentials.py`, which imports only the standard library, so the tshark engine (reading dissected fields) and the scapy engine (reading raw payload) share one vocabulary and one hash function. They were duplicated once and drifted — credential detection existed in tshark and silently did not exist in scapy — so a parity test now asserts the two engines report the same credentials from the same capture, and the sample incident is run through both.

Covered: HTTP form bodies, HTTP query strings, HTTP Basic (decoded to name the account), FTP, POP3, IMAP `LOGIN`, and SMTP `AUTH PLAIN`. **Telnet is deliberately not covered** — it negotiates in-band and sends a character per packet, so a line-oriented reader produces confident nonsense on it.

Only client-to-server payloads are scanned. A login *form* in an HTTP response carries the field names with no values, and reporting the page that asks for a password as a password crossing the network is exactly the false positive that teaches people to ignore a rule.


## MITRE ATT&CK mapping
Deterministic, rule-based, evidence-cited suggestions — never an automated "this happened" claim. Currently T1059, T1059.001, T1027, T1105. Each carries an investigator-settable status (`potential` / `confirmed` / `rejected`) that survives re-scans.

## Investigation
`netforensic investigate <entity>` returns everything the case knows about one IP, user, hash, host, domain, process, file, or device: related evidence, a scoped timeline, ranked related entities, a 1-hop relationship graph, and deterministic leads — plus optional threat-intel and AI enrichment.

## Threat intelligence
Optional, explicit, cached VirusTotal lookups for IPs and file hashes. Never automatic, never sent evidence content, cached in the case so repeat runs don't re-query. Values are validated as a real IP or MD5/SHA-1/SHA-256 before anything is sent.

## AI assistant
Optional, never on the critical path. Four interchangeable providers — **Anthropic, OpenAI, Ollama (fully local), Google Gemini** — selected per request. See [AI safety model](#ai-safety-model).

Two shapes, one contract. `investigate --ai` hands a fixed set of events to the model and gets back one hedged hypothesis. `chat` lets the model **retrieve** instead:

```bash
netforensic chat --case INC-0001 "was anything downloaded from an external host?"
netforensic chat --case INC-0001                    # interactive
```

It cannot see the evidence. It reaches it through eight read-only tools — content search, stream following, stream listing, event search, detections, entities, protocol summary, evidence listing — and **every tool call appends what it returned to a citation ledger.** The answer must cite from that ledger and nothing else.

Membership is an exact test on the `(kind, evidence_id, reference)` triple, not a substring search of the transcript: a looser check would accept the model quoting an identifier back out of *its own earlier reasoning*, which is the failure being guarded against. An unverifiable citation gets one correction pass naming exactly what failed; if it comes back unverifiable again the **whole answer is refused**, not shown with a caveat.

The loop is JSON the model returns rather than four native tool-calling integrations. Each provider expresses tool use differently, so native support would put the safety-critical path in four places and leave **Ollama** — the only provider that keeps an investigation entirely off the network — worst supported. The transport is not what makes this safe; the ledger is.

## Findings & reporting
Investigator-owned findings (`Open` / `Investigating` / `Confirmed` / `Rejected` / `False Positive` / `Resolved`), each citing specific evidence + event pairs, creatable from CLI or web UI. Reports render to **Markdown, JSON, and HTML**, every section traceable to evidence, with a stated limitations section.

## Web UI
A dependency-free frontend (no CDN, no build step — works offline) over the same core modules the CLI uses:

The rail groups destinations by the stage of an investigation rather than listing them flat:

| | |
|---|---|
| **Evidence** | Evidence · Live capture |
| **Dig** | Search · Streams · Triage |
| **Analysis** | Timeline · Entities · Detections · ATT&CK |
| **Conclude** | Findings · Reports · Chain of custody |
| **Assistant** | Ask (cited) |

The **Overview is a dashboard**: KPI tiles, an analysis runner reporting *in progress / complete / completed-with-errors* (per-evidence failures listed individually — a partially-failed analyze is not a success), an event-density chart, top entities, a one-hop entity graph, recent detections, carved files, triage matches, an ask box, and the custody trail with its verification state. Charts are inline SVG: no build step, no CDN, works offline.

Surfaces that need tshark are **dimmed and explained, never hidden** — a missing item reads as a missing feature, a disabled one reads as a setup step. The rail carries live capture status; the status bar reports which Wireshark tools were actually detected.

## Live capture
Rotating pcap capture that auto-ingests each finished window through the **exact same pipeline** as a manually added file — including detection rules, so a match surfaces as an alert within one poll. That makes it a lightweight live-alerting mode with no separate "watch" step.

| Backend | Notes |
|---|---|
| `dumpcap` | Wireshark's capture engine, preferred when installed. Does the packet copying and the rotation itself, in C, using its own ring buffer — so no packet is lost at a window boundary the way a Python-side rotation can lose one. It is also the one small program Wireshark isolates capture privileges into. |
| `scapy` | Pure-Python fallback. Every packet crosses into Python to be written, which is what limits it on a busy link. |

With dumpcap present, `--list-interfaces` also shows Wireshark's human-readable interface descriptions — which is what makes a Windows `\Device\NPF_{GUID}` identifiable as a particular NIC.

> Requires a packet-capture driver (Npcap / libpcap) and elevated privileges. This tool installs neither and grants neither.

## Case portability
Export a whole case to one zip archive with a SHA-256 manifest of every file. Import verifies **every** file against that manifest before writing anything, so a tampered or corrupted archive is rejected outright rather than partially extracted.

---

# AI safety model

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
