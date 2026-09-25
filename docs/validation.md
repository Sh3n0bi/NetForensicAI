# Validation against real captures

NetForensicAI's tests use synthetic captures, which prove the code does what
the tests assert but not that it holds up on traffic it did not generate. This
is a first pass at that: the tool run against **real, public packet captures**
with known content, checking that it finds the right things — and, just as
importantly, recording what it does *not*.

## Method

- **Corpus:** eight captures from the [Zeek test traces](https://github.com/zeek/zeek/tree/master/testing/btest/Traces)
  — real protocol traffic (real browsers, real FTP/SSH/SMTP sessions), public
  and non-sensitive. Chosen to exercise the features that matter for DFIR:
  credential recovery, domain/SNI extraction, file transfer, and the bundled
  detections. No live-malware captures were used.
- **Engine:** the pure-Python **scapy** engine (the slower path; the tshark
  engine would parse the same bytes faster). Each capture was parsed, its
  entities extracted and correlated, and the bundled detections run.
- **Ground truth:** each capture's protocol and content are known, so the
  output can be checked, not just observed.

## Results

| Capture | Size | What the tool produced | Verdict |
|---|---|---|---|
| **ftp/bruteforce** | 55 KB | 121 events; **30 cleartext-credential exposures** flagged (`Credentials submitted without encryption`) to the FTP server `192.168.56.101:21` | ✅ Correct — a brute-force is exactly a stream of cleartext logins |
| **http/basic-auth** | 1.8 KB | Decoded HTTP Basic Auth: **user `test`** recovered, flagged as sent without encryption | ✅ Correct — credential decoded from the `Authorization` header |
| **http/bro.org** | 506 KB | 126 events, 31 HTTP request/response pairs, domains `bro.org` / `www.bro.org` | ✅ Correct — real browsing session, request/response pairing and domains right |
| **tls/chrome-google** | 11 KB | `tls_handshake` with SNI **`google.de`** | ✅ Correct — SNI extracted from a real Chrome ClientHello |
| **dns** | 492 B | `dns_query` + `dns_response`, domain `example.net` | ✅ Correct |
| **ssh** | 1.3 MB | 138 events; **3 `Bulk transfer to an external host`** detections | ✅ Correct — a 1.3 MB SSH session is a bulk transfer; encrypted, so no content |
| **ftp/bigtransfer** | 32 KB | Connections seen, but the transferred file was **not carved** | ⚠️ Gap — see below |
| **smtp** | 2.8 KB | Connection seen as a generic TCP flow; no SMTP fields extracted | ⚠️ Gap — see below |

**All eight parsed without a crash, hang, or unhandled error** on the scapy path.

## What this validates

- **Credential recovery works on real traffic** — both cleartext FTP (30
  exposures in the brute-force) and HTTP Basic Auth (username decoded).
- **Domain and TLS-SNI extraction are correct** against a real Chrome handshake
  and a real HTTP browsing session.
- **HTTP request/response pairing** holds on a 500 KB real capture.
- **The bundled detections fire correctly and specifically** — cleartext
  credentials and bulk transfers were flagged; the benign browsing/DNS captures
  produced no detections (no false alarms).

## Findings and gaps (honest)

None of these are crashes; they are coverage limits worth knowing.

1. **FTP data-channel file transfers are not carved.** `ftp/bigtransfer` moved a
   file over a separate PASV/PORT data connection; the tool recovers FTP
   *credentials* (control channel) but object carving is HTTP-only, so the
   transferred file did not appear. *Recommendation:* carve FTP data streams,
   or document the limit.
2. **No SMTP protocol parsing.** SMTP is treated as a generic TCP flow — no
   sender/recipient/subject extraction — unlike HTTP/DNS/TLS/FTP-credentials.
   *Recommendation:* an SMTP mapper (sender, recipients, subject, attachments).
3. **Recovered FTP usernames are not promoted to the `user` entity field.** The
   FTP credential *event* fires, but the username lives only in the message,
   where HTTP Basic Auth populates `user`. So FTP usernames do not appear in the
   entity graph. *Recommendation:* set `user` on the FTP credential event.
4. **Statistical anomaly volume is high on mid-size captures** (e.g. 90 anomaly
   features on the 138-event SSH capture). This is the documented IsolationForest
   behaviour — it flags a fixed fraction — and is already disabled above ~20k
   packets, but it is noisy in the mid range.

## Reproduce

```python
# Point PcapParser at each capture, then extract/correlate/scan.
from netforensicai.parsers.pcap import PcapParser
from netforensicai.core.store import CaseStore
from netforensicai.core.entities import extract_and_store_ids
from netforensicai.core.correlation import correlate_case
from netforensicai.core.detections import scan_case

events = PcapParser().parse("bruteforce.pcap", evidence_id="EV-0001", output_dir="out")
with CaseStore("case") as store:
    store.replace_events_for_evidence("EV-0001", events)
    extract_and_store_ids(store, events)
    correlate_case(store)
    print(len(events), "events;", len(scan_case(store)), "detections")
```

## Scope

This is protocol-correctness validation on real captures, not an IDS accuracy
benchmark. It does not measure detection precision/recall against a labelled
incident dataset, and it did not exercise the tshark engine or very large
(multi-gigabyte) captures. Those are worthwhile next steps.
