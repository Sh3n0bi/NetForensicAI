[← README](../README.md) · [Capabilities](capabilities.md) · [Commands](commands.md) · [HTTP API](api.md) · [Wireshark](wireshark.md) · [Architecture](architecture.md) · [Walkthrough](walkthrough.md)

---

# Deployment, sizing and compliance

What it costs to run, how to deploy it safely, and what it does and does not give you towards an audit.

Every performance figure on this page was **measured** with `samples/benchmark.py` on the hardware named below, not estimated. Reproduce them with:

```bash
python samples/benchmark.py --scale 150 300 600 --engine tshark
```

---

## Measured performance

Reference machine: **Windows 11, 16 logical cores, Python 3.12**, synthetic office traffic from `samples/generate_benign.py`, tshark 4.6.

| Packets | Capture | Events | Wall time | Throughput | Peak RAM |
|---:|---:|---:|---:|---:|---:|
| 25,752 | 12.6 MB | 9,174 | 17.0 s | 1,511 pkt/s | 90 MB |
| 51,450 | 25.1 MB | 18,324 | 25.8 s | 1,996 pkt/s | 104 MB |
| 103,028 | 50.3 MB | 36,624 | 40.6 s | 2,540 pkt/s | 103 MB |
| 258,090 | 126.2 MB | 91,524 | 58.9 s | **4,384 pkt/s** | 217 MB |

Two things in that table matter more than the headline number.

**Throughput rises with capture size.** Startup — imports, DuckDB open, tshark launch — is a fixed cost of a few seconds, so small captures look far worse per packet than large ones. Judge it on the bottom row, not the top.

**Peak memory stays small.** It moves from 90 MB to 217 MB while the capture grows 10×, because parsing streams: events are batched into the store rather than accumulated in a list. **Capture size is bounded by disk, not by RAM.** A capture larger than memory is a normal case, not an edge case.

### Which engine

| | tshark | scapy |
|---|---|---|
| Throughput | **1,511 pkt/s** | 464 pkt/s |
| Peak RAM | **90 MB** | 145 MB |
| Protocol coverage | ~3,000 dissectors | 7 analyses |

**tshark is 3.3× faster and uses less memory** — the opposite of the intuition that shelling out to another process must be slower. Install Wireshark on anything doing volume. The scapy engine remains the fallback and produces the same event types, so nothing breaks without it.

### Sizing a job

At the measured **128 MB/min** sustained on one core:

| Capture | Expected wall time |
|---|---|
| 100 MB / ~200k packets | ~45 s |
| **1M packets (CTF-scale)** | **~4 min** |
| 1 GB / ~2M packets | ~8 min |
| 10 GB | ~80 min |

Extrapolated from the 258k-packet row, which is the most representative — throughput was still rising there, so these are conservative. RAM stays in the low hundreds of MB throughout. Disk is the real budget: a case holds a **read-only copy** of every evidence file plus the DuckDB store and carved artifacts, so provision roughly **2.5× the raw capture size**.

### Cores

**The pipeline is single-threaded, and adding cores will not make one case faster.** The bottleneck is a serial write path into DuckDB, which is single-writer by design — not CPU saturation. Anyone sizing a box on "it'll use all 16 cores" will be disappointed.

What cores *do* buy you is **concurrent cases**. Each case is an independent directory and an independent DuckDB file with its own lock, so N investigations run genuinely in parallel. Size for the number of simultaneous cases, at roughly one core and ~150 MB each, plus a core for the OS.

> Measured honestly: this is a workbench, not a distributed pipeline. If you need line-rate continuous inspection across a network, you want an NSM platform (Zeek, Suricata) feeding a SIEM. This is for evidence you already have.

---

## Deployment

### Where it is meant to run

An **analyst workstation or a single investigation server**. It is local-first by design: no daemon, no database server, no message queue, no cluster.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[pcap,evtx,web]"
apt install tshark        # or: brew install wireshark; choco install wireshark
```

A server or container needs **only tshark** — no GUI, no Qt, no desktop stack.

### Network posture

Nothing here reaches the network unless you invoke a feature that does.

| Feature | Reaches out | Default |
|---|---|---|
| Parsing, correlation, timeline, detections, narrative, reports | **Never** | — |
| VirusTotal lookup | virustotal.com | Off (needs a key) |
| AI assistant / chat — Anthropic, OpenAI, Gemini | That provider | Off (needs a key) |
| AI assistant / chat — **Ollama** | **localhost only** | Off |

**For air-gapped or evidence-sensitive work, install neither `intel` nor the `ai-*` extras.** Everything that produces a finding still works: the detections and the narrative are deterministic and involve no model and no network. If you want AI assistance without evidence leaving the building, use the **Ollama** provider — it is the only one that keeps an investigation entirely on your own hardware.

### The web UI

```bash
netforensic web --host 127.0.0.1 --port 8000
```

**It binds to `127.0.0.1` by default, and that default is the security model.** There is no authentication, no user accounts, and no authorisation — it assumes the only person who can reach the port is the person sitting at the machine.

> **Do not expose it directly.** Binding to `0.0.0.0` publishes an unauthenticated interface that can read every case, delete cases, and start packet captures. If more than one analyst needs it, put it behind an authenticating reverse proxy (or an SSH tunnel) and keep the app on loopback.

State-changing requests require an `X-Requested-With` header, which blocks cross-site form posts from a browser the analyst has open elsewhere. That is a CSRF control, **not** an access control.

### Privileges

| Task | Needs |
|---|---|
| Everything except live capture | An ordinary user |
| Live capture | Packet-capture rights |

Live capture needs a capture driver (Npcap/libpcap) and elevated rights. **Do not run the whole tool as root or Administrator to get it.** On Linux, grant the capability to the binary instead:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)
```

### Backup

A case is a self-contained directory. Back up the cases directory, or use `netforensic case export` for a zip with a per-file manifest. **Configured API keys live outside the cases directory**, so they are never included in an export.

---

## Compliance and evidence handling

What the tool actually gives you. Read the limits as carefully as the capabilities — an overstated claim is worse here than a missing feature.

### What it provides

**Integrity.** Every evidence file is SHA-256 hashed on ingest and stored **read-only**. `netforensic case audit --verify` re-hashes and reports any mismatch. Analysis never writes to evidence; carved artifacts are written beside it, never over it.

**Chain of custody.** Every action — ingest, parse, export, delete — is appended to a **hash-chained** audit log, where each entry commits to the previous one. Altering or removing an entry breaks the chain, and `--verify` detects it. This addresses the *"can you show this evidence was not tampered with"* question directly.

**Attribution.** Each case records an investigator. Each finding records who created it and its status history.

**Reproducibility.** Parsing, correlation, the timeline, the detection rules and the narrative are **deterministic**: no model, no network, no randomness. The same evidence produces the same output, which is what lets a second analyst re-run your work and get your result. This is why the narrative is not generated by a language model — *"the model said so"* is not a chain of custody.

**Traceability.** No claim appears anywhere — report, narrative, detection, ATT&CK mapping — without the `evidence_id` and `event_id` it rests on.

**Data minimisation.** Credentials seen crossing the network are recorded as a **SHA-256, never the plaintext**, so a working password never enters the case database and never rides along in an export, a report or a backup. The plaintext stays in the original evidence file, which is already hashed and read-only.

**Right to erasure.** `netforensic case delete` removes evidence copies, the event store, artifacts, findings, reports **and the custody log**. There is no soft delete and no hidden copy — a tool that pretends to delete evidence while keeping one is worse than one that deletes it, because the copy is then unaccounted for.

### What it does not provide

Be direct about these with anyone who asks whether the tool "is compliant":

- **No authentication, authorisation, or multi-user separation.** Anyone who can reach the process can read and delete every case. Access control is the operating system's job and the network's.
- **No encryption at rest.** The case directory is plaintext on disk. Use full-disk or volume encryption (BitLocker, LUKS, FileVault) if evidence warrants it.
- **The audit log is tamper-*evident*, not tamper-*proof*.** A hash chain proves an entry was altered; it does not prevent it. Someone with write access to the case directory can rewrite the whole chain consistently. For a stronger guarantee, export and hold a signed copy externally.
- **No certification.** It is not accredited or validated against any standard, and no claim is made that it is. It supports evidence-handling practice; it does not confer compliance.
- **No retention or legal-hold management.** No timers, no automatic disposal, no hold flags.

### Deployment checklist

- [ ] Full-disk encryption enabled on the machine holding cases
- [ ] Web UI on `127.0.0.1`, or behind an authenticating proxy — never `0.0.0.0` unprotected
- [ ] OS permissions restrict the cases directory to the investigators who should see it
- [ ] `dumpcap` given capabilities; the tool **not** run as root/Administrator
- [ ] `intel` and `ai-*` extras omitted for air-gapped work, or Ollama used for local-only AI
- [ ] `netforensic case audit --verify` run before any handover, and the result kept
- [ ] Case exports stored on encrypted media with the manifest retained
- [ ] Backups cover the cases directory; configured keys backed up separately
