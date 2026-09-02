[← README](../README.md) · [Capabilities](capabilities.md) · [Commands](commands.md) · [HTTP API](api.md) · [Wireshark](wireshark.md) · [Architecture](architecture.md) · [Walkthrough](walkthrough.md)

---

# Command reference

Every command supports `--help` and `--cases-dir` (env `NETFORENSIC_CASES_DIR`, default `cases`).

**Cases**
```bash
netforensic case create --name "Incident" [--description "..."] [--investigator "..."]
netforensic case list
netforensic case status --case INC-0001 open|investigating|closed
netforensic case audit  --case INC-0001 [--verify]
netforensic case export --case INC-0001 [--output INC-0001.zip]
netforensic case import ./INC-0001.zip [--cases-dir other_cases]
netforensic case delete --case INC-0001              # irreversible; see below
```

`case delete` removes the evidence copies, the event store, carved artifacts, findings, reports **and the chain of custody** — the audit log lives inside the case directory. There is no soft delete and no trash: a forensics tool that pretends to delete evidence while keeping a copy is worse than one that deletes it, because the copy is then unaccounted for. Both the CLI and the web UI make you **type the case ID** rather than click through a yes/no, and both report what was removed.

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

**The story** — what happened, rather than how many objects there are
```bash
netforensic story --case INC-0001
```

Assembles the case into an account: beats (one per rule, grouped), grouped into the stages of an intrusion, under a one-sentence assessment. Same thing at `GET /api/cases/<id>/narrative`, in the web UI's **What happened** tab, and as the `## What Happened` section of an exported report.

It is **deterministic** — no model, no network, no score that can't be explained. A narrative that goes into an incident report has to be reproducible by whoever reads it, and *"the language model said so"* is not a chain of custody. The AI assistant may interpret the narrative; it is not permitted to write it.

Every beat names the `event_id`s it rests on, so each sentence walks back to a packet — in the UI those ids are clickable and resolve to the Wireshark display filter that isolates them.

A case with no detections still produces a story, and it says so plainly:

> No bundled detection rule matched this evidence. That is not the same as 'nothing happened' — it means nothing matched the rules that exist.


**Wireshark** *(only available when Wireshark is installed — see [Wireshark integration](wireshark.md))*
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
