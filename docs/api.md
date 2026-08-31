[← README](../README.md) · [Capabilities](capabilities.md) · [Commands](commands.md) · [HTTP API](api.md) · [Wireshark](wireshark.md) · [Architecture](architecture.md) · [Walkthrough](walkthrough.md)

---

# HTTP API

The web UI is a client of this API, not a second implementation — every route calls the same core modules the CLI does. It is served on `127.0.0.1` by default and has **no authentication**; see [Limitations](../README.md#limitations).

State-changing requests need an `X-Requested-With: NetForensicAI` header. That is not a session token — the app has no sessions — it is there so a cross-origin form or `fetch` from a malicious page cannot reach these routes blind.

| | |
|---|---|
| `GET /api/cases` · `GET /api/cases/<id>` | list, and one case with its counters |
| `POST /api/cases/<id>/status` | `open` / `investigating` / `closed` |
| `DELETE /api/cases/<id>` | irreversible; body must echo `{"confirm": "<id>"}` |
| `GET · POST /api/cases/<id>/evidence` | list and upload |
| `POST /api/cases/<id>/analyze` | parse, correlate, scan rules |
| `GET /api/cases/<id>/timeline` · `/entities` · `/detections` · `/attack` · `/findings` · `/audit` · `/artifacts` | the case, read back |
| `POST /api/cases/<id>/search` | content search over a capture |
| `GET /api/cases/<id>/streams` · `/streams/<n>` | list conversations, reassemble one |
| `GET /api/cases/<id>/triage` | protocols, candidates, files, conversations |
| `POST /api/cases/<id>/chat` | ask a question; refusals return 502 |
| `GET /api/wireshark/status` · `POST /api/wireshark/check-filter` | tooling and filter validation |
| `POST /api/cases/<id>/evidence/<eid>/slice` | carve a display-filter slice as new evidence |
| `GET /api/cases/<id>/capture/status` · `POST .../start` · `.../stop` | live capture |

`search`, `streams`, `triage` and `artifacts` are **read-only questions asked of a capture file**: none writes to the store, creates a finding, or records an audit entry — noting that somebody *looked* at evidence is not what a chain of custody is for. `triage` deliberately does not extract files, because a GET a dashboard polls must not write to disk.

The entities route takes `?sort=events&limit=N`, applied after sorting so `limit` means "the top N".

---
