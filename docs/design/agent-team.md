# Design: NetForensicAI Investigation Team (multi-agent roles)

**Status:** Approved. Phases 1–3 landed (foundation, the Network + Host roles, and the coordinator that merges/ranks their findings);
phases 2–6 follow. Defaults chosen: provider-agnostic (default `anthropic`, works
on local Ollama); findings are *proposed* for one-click acceptance, never
auto-written; CLI entry point will be `netforensic team`.
**Author:** drafted with Claude, 2026-09-25.
**Scope:** a set of role-specialized AI agents ("bots") that investigate a case
together, grounded in evidence, on top of the existing tool.

---

## 1. Goal & non-goals

**Goal.** Turn the single grounded assistant into a *team* of specialists —
network, host, malware, threat-intel, and a coordinator + reporter — that each
analyze the part of a case they know best and hand back **evidence-cited**
findings, which the coordinator merges into one investigation.

**Non-goals (deliberately out of scope).**
- Not a set of chatbot "personalities." Roles differ by **scope, tools and
  prompt**, not by tone.
- Not autonomous action. Agents **read** evidence and **write findings**; they
  never send email, touch the network beyond opt-in threat-intel, or run code.
- Not a replacement for the deterministic engine. Agents **interpret**
  detections/correlations; they do not invent detections.

## 2. Principles (non-negotiable)

1. **Grounding above all.** Every agent runs on the existing `core/chat.py`
   engine, whose citation ledger *refuses any claim not backed by a tool
   result*. A DFIR agent that speculates is worse than none. No agent gets a
   looser contract.
2. **Deterministic-first.** Agents are told to prefer the tool's own
   detections, correlations, ATT&CK mappings and entities, and to use the LLM
   only to connect and explain them.
3. **Local-first & provider-agnostic.** Works with Anthropic / OpenAI / Gemini
   / **local Ollama**, like today's assistant — so a team can run fully offline.
4. **Opt-in & bounded.** Off by default. Every role has a step budget and the
   whole run has a wall-clock and token ceiling. Cost is predictable.
5. **Evaluable.** "Works perfectly" is meaningless unless measured. The team is
   validated against the same real captures as `docs/validation.md`, checked
   against known ground truth.

## 3. Architecture

Built entirely on what already exists:

- `core/chat.py :: ask()` — a grounded tool-loop (max-steps, provider call,
  citation ledger). It already accepts a `call` override and a `max_steps`.
- `core/chat.py :: CaseTools` — read-only retrieval: `list_evidence`,
  `search_events`, `list_detections`, `list_entities`, `search_packets`,
  `list_streams`, `follow_stream`, `protocol_summary`.

**An agent = `ask()` + a role system-prompt + a scoped subset of `CaseTools` +
a role step-budget.** Nothing about grounding is re-implemented.

```
                        ┌──────────────────────────┐
   case  ──────────────▶│  Lead Investigator        │  (coordinator)
                        │  - scopes the case         │
                        │  - dispatches to roles     │
                        │  - merges cited findings   │
                        └──────────┬───────────────┘
             ┌───────────┬─────────┼──────────┬────────────┐
             ▼           ▼         ▼          ▼            ▼
        Network      Host/DFIR   Malware/   Threat-Intel  Reporter
        Forensics               IOC          & Corr.
        (scoped CaseTools, role prompt, grounded, cite-or-refuse)
```

New module: `netforensicai/agents/` — `base.py` (Role definition + runner over
`ask()`), `roles.py` (the role table below), `coordinator.py` (dispatch +
merge), `team.py` (public entry point). No change to `core/chat.py`'s contract.

## 4. The roles (full set)

Each role has a **mission**, the **evidence it reads**, the **tools** it may
call, and a strict **output contract** (structured, cited findings only).

| Role | Mission | Reads | Tool scope |
|---|---|---|---|
| **Lead Investigator** (coordinator) | Scope the case, decide which roles are relevant, dispatch, then merge and de-duplicate their cited findings into one ranked account. Does **no** analysis of its own. | roles' outputs + `list_evidence`, `list_detections` for scoping | minimal |
| **Network Forensics** | Flows, DNS, TLS/SNI, HTTP, beaconing cadence, exfil volume, C2 candidates. | pcap + Suricata events | `search_events`, `search_packets`, `list_streams`, `follow_stream`, `protocol_summary`, `list_entities` |
| **Host / Endpoint (DFIR)** | Process creation, file writes, persistence, logons, lateral movement. | EVTX/Sysmon events | `search_events`, `list_entities`, `list_detections` |
| **Malware / IOC** | Carved files, hashes, suspicious downloads, key/secret material, and matches to imported indicators. | artifacts, IOC matches, file entities | `list_entities`, `search_events`, `list_detections` |
| **Threat-Intel & Correlation** | Cross-source ties (same IP/host/hash across pcap+host), ATT&CK coverage, optional VirusTotal (opt-in), and what a single indicator touches. | entity graph, correlation links, ATT&CK, threat-intel | `list_entities`, `list_detections`, `search_events` |
| **Reporter** | Turn *confirmed* findings into the case report/narrative language. Adds nothing not already cited. | the coordinator's merged findings | none (writes only) |

**Why these six.** They map 1:1 to the evidence the tool already normalizes
(network / host / files / cross-source) plus the two bookend roles (coordinate,
report). No role exists without evidence to stand on.

## 5. Grounding & output contract

- Each role's system prompt ends with the same hard rule the chat engine
  already enforces: *cite a tool result for every claim, or say you cannot
  determine it.* The citation ledger makes this mechanical, not aspirational.
- Role output is **structured**: a list of `{title, severity, assessment,
  evidence: [citations], attck?: [...], confidence}` — not prose. This is what
  makes merging and de-duplication possible, and it maps straight onto the
  existing `Finding` model so a human can accept a finding with one click.
- A role that finds nothing in its domain returns an explicit "no findings in
  scope," which is itself signal (and prevents invented findings).

## 6. Orchestration (coordinator)

1. **Scope.** The Lead reads `list_evidence` + `list_detections`, and runs only
   the roles whose evidence is present (no Host role if there's no EVTX).
2. **Dispatch.** Roles run — sequentially by default (predictable cost/logs),
   optionally in parallel later.
3. **Merge.** Findings are de-duplicated by cited evidence (two roles flagging
   the same event = one finding, richer). Conflicts are surfaced, not hidden.
4. **Rank & narrate.** The Lead orders by severity + corroboration; the Reporter
   phrases the confirmed set. Output is a consolidated, cited investigation the
   human owns and edits.

## 7. Interfaces

- **CLI:** `netforensic team --case INC-0001 [--roles network,host] [--provider ollama] [--max-steps N]`. Prints each role's cited findings and the merged result; can write them straight into the case as `Finding`s (investigator still confirms).
- **Web UI:** an "Investigation team" panel — run the team, watch each role's findings stream in, accept the ones you agree with. Reuses the existing findings UI.
- **(Later) Slack/Discord** is a *delivery channel* on top of this, not part of it — a separate, optional build.

## 8. Cost, performance, safety

- **Cost control:** off by default; per-role step budget (e.g. 6); a global
  ceiling; the Lead skips irrelevant roles. Per-role model choice — a cheap/
  local model for narrow roles, the strongest for the Lead — is a config knob.
- **Safety:** all tools are read-only (existing `CaseTools`); no external calls
  except opt-in VirusTotal/AI, exactly as today; no code execution; secrets
  handled by the existing config layer and never printed. Local-first holds:
  point every role at Ollama and nothing leaves the machine.

## 9. Evaluation (how we prove it)

- Run the team on the **real captures** from `docs/validation.md` and the
  synthetic incident, and check each role's findings against known ground truth
  (e.g. Network role must surface the cleartext-credential exfil; Malware role
  the carved executable).
- A regression harness asserts the team produces the expected *categories* of
  cited finding on those fixtures — so "does a lot of work" becomes a test, not
  a vibe.

## 10. Phased delivery (even though the target is the full set)

1. **Foundation** — `agents/base.py`: a `Role` (prompt + tool scope + budget)
   run over `ask()`, returning structured cited findings. Tests with a scripted
   model (like the chat tests) — no live provider needed.
2. **First two roles** — Network Forensics + Host/DFIR. Prove they beat the
   single assistant on the validation fixtures.
3. **Coordinator + merge** — Lead Investigator; de-dup + rank.
4. **Remaining roles** — Malware/IOC, Threat-Intel/Correlation, Reporter.
5. **Interfaces** — `netforensic team` CLI, then the web panel.
6. **Eval harness** — the ground-truth regression above.

Each phase ships as its own PR, CI-green, like everything else.

## 11. Risks & open questions

- **Over-engineering.** Mitigation: the phased plan proves value at phase 2
  before the full orchestra exists.
- **LLM inconsistency across roles.** Mitigation: structured output + citation
  ledger + deterministic-first prompt; the Lead reconciles conflicts explicitly.
- **Latency/cost on big cases.** Mitigation: budgets, role-skipping, per-role
  model selection, sequential-by-default.
- **Open questions for you:** (a) default provider for the team — Anthropic or
  local Ollama? (b) should the team auto-write findings, or only propose them
  for one-click acceptance (my recommendation: propose)? (c) name — "team",
  "agents", "analysts", "crew"?

---

**Recommendation:** approve phases 1–3 (foundation + two roles + coordinator)
as the first milestone; it de-risks the whole idea and is independently useful.
The remaining roles and interfaces follow once that proves out.
