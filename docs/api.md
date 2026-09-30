[← README](../README.md) · [Capabilities](capabilities.md) · [Commands](commands.md) · [HTTP API](api.md) · [Wireshark](wireshark.md) · [Architecture](architecture.md) · [Walkthrough](walkthrough.md)

---

# HTTP API

The web UI is a client of this API, not a second implementation — every route calls the same core modules the CLI does. It is served on `127.0.0.1` by default and has **no authentication**; see [Limitations](../README.md#limitations).

State-changing requests need an `X-Requested-With: NetForensicAI` header. That is not a session token — the app has no sessions — it is there so a cross-origin form or `fetch` from a malicious page cannot reach these routes blind.

| | |
|---|---|
| `GET · POST /api/cases` · `GET /api/cases/<id>` | list cases with their state and story assessment (`?brief=1` for names only); create one (`name`, optional `investigator`, `description`); one case with its counters |
| `POST /api/cases/<id>/status` | `open` / `investigating` / `closed` |
| `DELETE /api/cases/<id>` | irreversible; body must echo `{"confirm": "<id>"}` |
| `GET · POST /api/cases/<id>/evidence` | list and upload |
| `POST /api/cases/<id>/analyze` | parse, correlate, scan rules |
| `GET /api/cases/<id>/timeline` · `/entities` · `/detections` · `/attack` · `/findings` · `/audit` | the case, read back |
| `GET /api/cases/<id>/artifacts` | recovered files: real type, risk and reasons, content hints, SHA-256, where each came from |
| `GET /api/cases/<id>/artifacts/preview?path=` | a safe look inside: `text`, `table` (CSV), `image`, `hex` or `empty` — never HTML |
| `GET /api/cases/<id>/artifacts/content?path=[&inline=1]` | the file as a download (audited); `inline=1` only for PNG/JPEG/GIF/WebP |
| `GET /api/cases/<id>/streams/<n>/data?direction=a\|b` | what one side of a conversation sent, byte-exact, as a download (audited) |
| `GET · POST · DELETE /api/cases/<id>/iocs` | list indicators (with match state), import a feed (multipart `file`, optional `source`; re-runs detections), remove all or one `source` |
| `POST /api/cases/<id>/search` | content search over a capture |
| `GET /api/cases/<id>/streams` · `/streams/<n>` | list conversations (each with per-direction bytes and a `plain` description), reassemble one (with content `hints`) |
| `GET /api/glossary` | plain-language names for protocols and event types |
| `GET /api/cases/<id>/triage` | protocols, candidates, files, conversations |
| `POST /api/cases/<id>/chat` | ask a question; refusals return 502 |
| `GET · POST /api/cases/<id>/team` | investigation team: status (live run + latest result) / start a run in the background (`202`; `409` if one is running). Body: `provider`, `model`, `api_key`, `base_url`, `roles`, `max_steps` |
| `POST /api/cases/<id>/team/findings/<n>/accept` | record team finding `n` as an **Open** finding (`201`; `409` if already accepted, a run is in progress, or a cited event no longer exists) |
| `GET /api/wireshark/status` · `POST /api/wireshark/check-filter` | tooling and filter validation |
| `POST /api/cases/<id>/evidence/<eid>/slice` | carve a display-filter slice as new evidence |
| `GET /api/cases/<id>/capture/status` · `POST .../start` · `.../stop` | live capture |

`search`, `streams`, `triage` and `artifacts` are **read-only questions asked of a capture file**: none writes to the store, creates a finding, or records an audit entry — noting that somebody *looked* at evidence is not what a chain of custody is for. `triage` deliberately does not extract files, because a GET a dashboard polls must not write to disk.

AI routes (`chat`, `ai-hypothesis`, `team`) use the request's `provider` / `model` / `base_url` when given, otherwise the **Settings** saved in the UI, otherwise the built-in defaults. A team run is recorded in the chain of custody (`ai.team_run`); its latest result is kept in `cases/<id>/team/latest.json` (never the API key).

The entities route takes `?sort=events&limit=N`, applied after sorting so `limit` means "the top N".

---
