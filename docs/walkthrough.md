[← README](../README.md) · [Capabilities](capabilities.md) · [Commands](commands.md) · [HTTP API](api.md) · [Wireshark](wireshark.md) · [Architecture](architecture.md) · [Walkthrough](walkthrough.md)

---

# A worked investigation

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
