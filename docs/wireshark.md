[← README](../README.md) · [Capabilities](capabilities.md) · [Commands](commands.md) · [HTTP API](api.md) · [Wireshark](wireshark.md) · [Architecture](architecture.md) · [Walkthrough](walkthrough.md)

---

# Wireshark integration

Optional and auto-detected. Install Wireshark and NetForensicAI starts using it; don't, and every feature below simply isn't offered while the rest of the platform works unchanged. Nothing here installs, downloads, or elevates anything.

## tshark, not the GUI

The integration is built on **`tshark`** — Wireshark's command-line engine — plus **`dumpcap`** for capture. The desktop GUI is used for exactly one thing: opening a capture for you to look at, when you ask it to. Everything else runs headless.

That matters in practice: a server, container, or CI runner installs `tshark` alone and gets the entire analysis path. See [Installation](../README.md#wireshark-optional-external) for per-platform commands, and run `netforensic wireshark status` to see what was detected.

## What it adds

| | |
|---|---|
| **Dissection** | tshark's ~3000 protocol dissectors replace eight hand-written analyses — see [Network protocol analysis](capabilities.md#network-protocol-analysis). |
| **Live capture** | dumpcap replaces the scapy sniffer — see [Live capture](capabilities.md#live-capture). |
| **Display filters** | Wireshark's filter language, validated by tshark itself, both to narrow a parse and to carve evidentiary slices. |
| **GUI pivot** | Open the capture behind any finding in Wireshark, pre-filtered to the exact packets that finding was drawn from. |

## Display filters

Filters can narrow ingestion, which is how a focused subset of a very large capture gets analyzed without carving it first:

```bash
netforensic parse --case INC-0001 --evidence EV-0001 --display-filter 'ip.addr == 10.0.0.5 && tcp.port == 445'
```

Or carve a slice, which is the *evidentiary* form. The slice is a real capture file, so it goes back through the normal evidence path — hashed, recorded against its parent and the exact filter that produced it, and analyzable on its own. That is what makes "I filtered the capture down to this" reproducible by someone else later, which a screenshot of a filtered GUI is not:

```bash
netforensic wireshark slice --case INC-0001 --evidence EV-0001 --display-filter 'dns.qry.name contains "evil"'
```

A filter that matches nothing writes nothing: an empty capture in the chain of custody would imply something was found. Asking for a display filter while the scapy engine is in use is an **error**, not a silent no-op — being handed every packet while believing you filtered is the worst possible outcome.

## GUI pivot

```bash
netforensic wireshark open --case INC-0001 --event EVT-EV-0001-000042
```

The filter is derived from the event's own recorded frame numbers, so what opens is exactly the traffic behind the finding rather than something that merely resembles it. `--print` emits the command instead of launching, for use over SSH or in a report.

The web UI deliberately **does not** launch the GUI. It returns the filter and the command for you to run: a browser page must not be able to spawn a desktop application on the machine running the server, and "it's bound to localhost" is a deployment detail, not a guarantee.

## Discovery

PATH first, then the standard install directories (including `C:\Program Files\Wireshark`, which the Windows installer does not add to PATH). Override with `NETFORENSIC_WIRESHARK_DIR`, or point at individual binaries with `NETFORENSIC_TSHARK` / `NETFORENSIC_DUMPCAP` / `NETFORENSIC_WIRESHARK`.

Requesting a specific engine that isn't installed is an error rather than a silent fallback — an analyst who passed `--engine tshark` is asking for a reproducible dissection, and quietly substituting a different one would put results in a report that the command printed beside them cannot reproduce.

---
