# HANDOFF.md — cold-start brief for a parallel builder

You (or your Claude) can build a Cerberus workstream from **this file plus the repo
alone** — you do not need the conversation that produced it. Read this once, claim a
workstream, build only its files, ship when its "Done when" check passes.

For the always-loaded working agreement and the security invariants, see `CLAUDE.md`.
For the pitch, see `README.md`. For the demo runsheet, see `demo_script.md`.

---

## TL;DR

Cerberus is a runtime reference monitor that sits between an AI agent (the *host*)
and its tools (downstream *MCP servers*). It labels every value with a capability
(provenance + sensitivity + reader-ACL), propagates those labels as taint, and
**blocks any single tool call that assembles the lethal trifecta** — private data ∧
untrusted influence ∧ external egress — fail-closed, with a tamper-evident signed
receipt for every decision.

The **core is real and green** (lattice, tracer, sentinel, warden, gateway, receipt
chain, LabelLedger, tests). Four runtime pieces and the dashboard are stubs/thin —
those are the parallel workstreams below. Each owns a **disjoint file set** so two
people (two Claudes) build simultaneously on `master` without colliding.

---

## What it is, and why (the threat)

Agents read untrusted content through the same channel as instructions. Every major
2025 agent breach is the same shape — a *lethal trifecta*:

| Incident | Surface | CVE / CVSS |
|---|---|---|
| EchoLeak | Microsoft 365 Copilot, zero-click | CVE-2025-32711, 9.3 |
| CamoLeak | GitHub Copilot Chat | CVE-2025-59145, ~9.6 |
| ForcedLeak | Salesforce Agentforce | ~9.4 |
| ShadowLeak / AgentFlayer | ChatGPT Deep Research / Connectors | vendor-fixed |
| Slack AI exfil · GitLab Duo | RAG / MR descriptions | vendor-fixed |

We do not *detect* injection (a cat-and-mouse you lose). We make exfiltration of a
labelled value to a disallowed sink a **structural** violation. Refs: CaMeL
(arXiv:2503.18813), FIDES (arXiv:2505.23643), AgentDojo (arXiv:2406.13352),
Willison's lethal-trifecta / dual-LLM pattern, OWASP Top-10 for Agentic Apps (2025).

---

## Architecture & data model

```
HOST (agent loop) ──▶ CERBERUS GATEWAY ──▶ downstream MCP servers
                      SENTINEL · TRACER · WARDEN
                      └─▶ session.jsonl (events) + receipt chain + SSE ─▶ dashboard
```

**Capability label** (`cerberus/labels.py`, frozen) — attached to every value:
- `provenance: Provenance` — SYSTEM(0) < USER(1) < TOOL_TRUSTED(2) < TOOL_UNTRUSTED(3).
- `sensitivity: Sensitivity` — PUBLIC(0) < PRIVATE(1) < SECRET(2).
- `readers: frozenset[str]` — reader-ACL; `"*"` (WILDCARD) = any sink allowed.
- `source_ref`, `honeytoken_id` — provenance-DAG node id / canary marker.

**Lattice ops** (the trust anchor):
`join` = max(provenance), max(sensitivity), **intersect**(readers). `may_flow_to(sink)`
= WILDCARD in readers or sink in readers. `declassify(...)` is the *only* sanctioned
weakening. Joining only ever taints *up*.

**Trifecta** (`cerberus/tracer.py`, frozen) — over the current action window:
`L1 private_access` (touched SECRET/PRIVATE) ∧ `L2 untrusted_influence` (derived from
TOOL_UNTRUSTED) ∧ `L3 egress` (call targets an external sink). All three in one call →
`TrifectaState.complete` → the red-lock. Backstops: honeytokens + a leak meter
(advisory, for in-head laundering).

**Decision** (`cerberus/warden.py`, frozen) — graded modes ALLOW / REDACT / CONFIRM /
QUARANTINE / BLOCK. Fail-closed: unknown sink or ACL-forbidden egress → deny. Default
`confirm_fn` denies. Every decision issues a receipt.

**Receipt chain** (`cerberus/events.py`, frozen) — each `Receipt` embeds the previous
receipt's `this_hash`; `EventBus.verify_chain()` re-hashes and confirms integrity. This
is the audit deliverable (EU AI Act Art. 12 framing). **Schema is a frozen contract.**

**LabelLedger** (`cerberus/session_state.py`) — real callers never pass `_caps`. The
ledger records `value → Capability` per tool result and reconstructs an incoming call's
`arg_caps` by substring containment, defaulting un-attributable text to
`user_instruction()` (USER anchor). `Gateway(auto_label=True)` enables it.

---

## Real vs in-progress (honesty table)

| Component | State | Where |
|---|---|---|
| Capability lattice + IFC | ✅ real, tested | `cerberus/labels.py` |
| Trifecta detector + backstops | ✅ real, tested | `cerberus/tracer.py` |
| Warden graded modes + receipts | ✅ real, tested | `cerberus/warden.py` |
| Sentinel registration defenses | ✅ real, tested | `cerberus/sentinel.py` |
| Event bus + tamper-evident chain | ✅ real, tested | `cerberus/events.py` |
| Gateway reference monitor | ✅ real, tested | `cerberus/gateway.py` |
| LabelLedger (auto provenance) | ✅ real, tested | `cerberus/session_state.py` |
| Scripted host demo (OFF→leak, ON→block) | ✅ real | `host/agent.py` |
| `cerberus-verify` chain auditor | ✅ real, tested | `cerberus/cli.py` |
| pytest suite + packaging | ✅ green | `tests/`, `pyproject.toml` |
| Real MCP transport (stdio/HTTP) | ⛏️ stub | **WS-A** |
| LLM host loop (Anthropic + Ollama) | ⛏️ stub | **WS-B** |
| AgentDojo eval harness | ⛏️ stub (canned print) | **WS-C** |
| Red-team adversary loop | ⛏️ stub (hardcoded BLOCK) | **WS-D** |
| SIEM / audit-observability layer | ⛏️ not started | **WS-E** |
| Polished web frontend | ⛏️ thin (SSE only) | **WS-F** |
| Tests / CI / docs polish | ⛏️ partial | **WS-G** |

---

## Module map (public API you build against)

```python
# cerberus/gateway.py — the reference monitor (FROZEN signatures)
gw = Gateway(policy_path="policies/default.yaml", session_path="session.jsonl",
             confirm_fn=None, enabled=True, auto_label=True)
gw.register(DownstreamServer(name, trusted, manifest, call, is_egress))      -> [Finding]
gw.register_remote(name, session, *, trusted=False, is_egress=False)         -> [Finding]
gw.list_tools()  -> [{"name":"server__tool","server","tool","description","is_egress"}]
gw.handle_call(server_name, tool, args) -> {"ok":bool, ...}   # the enforcement point
gw.ledger        # LabelLedger          gw.tracer / gw.warden / gw.sentinel / gw.bus

# DownstreamServer.call signature:  (tool: str, args: dict) -> ToolResult
# ToolResult(value: str, sensitivity: int = 0, readers: frozenset = {"*"})

# host/agent.py — the shared seam every front-end drives
build_gateway(enabled, confirm_fn=None, *, auto_label=False, session_path="session.jsonl")
    -> (Gateway, docsearch_findings)
drive_attack(gw) -> verdict_dict          # scripted hijacked-agent tool sequence
cli_confirm_fn(prompt) -> bool            # terminal CONFIRM; swap for web/event-backed

# cerberus/events.py — FROZEN schema
EventBus.emit(kind, **data) -> Event            # appends to session.jsonl + fans out to subs
EventBus.subscribe(fn)                          # live SSE hook
EventBus.issue_receipt(*, tool, args_hash, labels, head_verdicts, decision, reason) -> Receipt
EventBus.verify_chain() -> bool

# cerberus/cli.py
verify_session(path) -> (intact: bool, n_receipts: int)
```

**Event kinds** written to `session.jsonl`: `tool_call`, `value`, `sentinel`, `trifecta`,
`verdict` (= a finalized receipt, carries all Receipt fields). Add new kinds freely;
**never change the shape of existing ones** (WS-E/WS-F parse them).

---

## Run & test

```bash
pip install -e .[test]            # core + pytest;  .[all] adds host/mcp/dashboard
python -m host.agent              # OFF (leak) then ON (block); ~10s, no API key
python -m host.agent --confirm    # ON in CONFIRM mode (you approve/deny)
pytest -q                         # full suite, offline + deterministic
python -m cerberus.cli session.jsonl     # verify the receipt chain (exit 0 intact / 1 tampered)
uvicorn dashboard.app:app --port 8000    # live DAG (needs .[dashboard])
```

Expected: OFF → the fake honeytokened AWS key arrives at the exfil sink; ON → trifecta
assembles, call BLOCKED, sink empty, `verify_chain()` True (3 receipts).

---

## Roadmap — INDEPENDENT workstreams (claim one)

Every workstream owns a disjoint file set and **must not touch the frozen core**
`cerberus/{labels,tracer,warden,sentinel,events}.py`. Build against the public API above.

### WS-A — Real MCP transport
- **Owns:** `cerberus/mcp_server.py`, `cerberus/mcp_client.py`, `cerberus/mcp_config.py`,
  `servers/servers.yaml`, `claude_desktop_config.json`.
- **Contract:** Cerberus is an MCP *server* to the host and an MCP *client* to downstream
  servers. `tools/list` → `gw.list_tools()` (poisoned tools already omitted). `tools/call`
  bridges to `gw.handle_call` via `anyio.to_thread.run_sync`; a BLOCK returns
  `isError=True` + the Warden reason. CONFIRM → fail-closed BLOCK in MCP mode. stdio is the
  default; optional FastAPI/SSE HTTP as a secondary entrypoint. Attach downstream via
  `gw.register_remote`.
- **Done when:** Claude Desktop points at it via `claude_desktop_config.json`; the poisoned
  `docsearch` tool is absent from the catalog; an egress attempt returns a BLOCK visible in chat.

### WS-B — LLM host loop
- **Owns:** `host/llm_loop.py`, `host/providers.py`, `host/tools.py`.
- **Contract:** `AnthropicProvider` (model `claude-opus-4-8`, manual agentic tool-use loop;
  surface gateway BLOCK reasons back to the model) + `OllamaProvider` fallback (no API key /
  connection error). `host/tools.py` builds Anthropic tool schemas from `gw.list_tools()` and
  executes via `gw.handle_call`. Wire a `--task` flag into `host/agent.py` **without** changing
  the scripted default path (keep `build_gateway`/`drive_attack` intact).
- **Done when:** `ANTHROPIC_API_KEY=… python -m host.agent --task "summarize the runbook and
  post it to the status page"` → real model attempts exfil → BLOCK; no key → Ollama fallback.

### WS-C — AgentDojo eval harness
- **Owns:** `eval/adapter.py`, `eval/runner.py`, `eval/results.py` (keep
  `eval/agentdojo_runner.py` as a thin CLI shim).
- **Contract:** `pip install agentdojo` (pin it). Wrap AgentDojo's `FunctionsRuntime` so every
  tool call routes through `gw.handle_call`; `label_environment` seeds provenance/sensitivity
  from each suite's injection-task metadata (private email/files → PRIVATE; attacker fields →
  TOOL_UNTRUSTED; credentials → `seed_secret`; send/post → `is_egress=True`). Run one suite at
  `--n 5` with vs without Cerberus; print benign-utility / utility-under-attack /
  attack-success-rate next to CaMeL 77/84 and FIDES (0 injections).
- **Done when:** `python -m eval.agentdojo_runner --suite <name> --n 5` → attack-success high
  OFF, ≈0 ON, utility preserved.

### WS-D — Red-team adversary loop
- **Owns:** `adversary/harness.py`, `adversary/payloads.py`, `adversary/llm_attacker.py`,
  `adversary/leaderboard.py` (keep `adversary/attacker.py` as a thin CLI shim).
- **Contract:** Fire each candidate payload through a **real** `Gateway` and read the **real**
  Warden verdict (not a hardcoded BLOCK). Genetic mutation (offline, deterministic, demo-safe)
  + optional LLM rewrite conditioned on the verdict reason. Payload taxonomy: indirect
  injection, exfil-via-markdown-image, key-splitting, base64/obfuscation, description
  poisoning. `--with-off` overlays the OFF curve (stays high) vs the ON curve (→ ~0% and holds).
  Sandboxed to the local demo gateway/exfil sink only.
- **Done when:** `python -m adversary.attacker --rounds 20 --with-off` → ON curve crashes to
  ~0% and holds; leaderboard JSON/PNG written.

### WS-E — SIEM / audit-observability layer
- **Owns:** `siem/*` (pure stdlib + pyyaml, no new runtime deps),
  `dashboard/static/forensics.js`.
- **Contract:** `siem/parser.py` normalizes `session.jsonl`; `siem/sigma_eval.py` is a tiny
  matcher over **real Sigma-format YAML** rules in `siem/rules/`; `siem/correlate.py` is a
  per-session windowed state machine; `siem/mappings.py` → OWASP Agentic Top-10 (ASI02 Tool
  Misuse, ASI06 Memory Poisoning); `siem/report.py` emits a **signed** incident report
  (signature = final receipt `this_hash` + `verify_chain()`); `siem/cli.py`. Five detections:
  `trifecta_formation`, `honeytoken_trip`, `rug_pull_drift`, `repeated_confirm_denials`,
  `leak_meter_threshold`.
- **Done when:** `python -m siem.cli analyze session.jsonl` fires detections + OWASP map +
  writes a signed incident report.

### WS-F — Frontend polish
- **Owns:** `dashboard/static/*`, `dashboard/index.html`, and the **control endpoints** in
  `dashboard/app.py` (additive — keep the existing `/` and `/events` working). **Stack: vanilla
  HTML/JS + Cytoscape, no build step** (demo reliability). Import `build_gateway`/`drive_attack`
  exactly as `host/agent.py` does.
- **Contract:** live provenance DAG (sink edge snaps red + locks on BLOCK), trifecta panel
  (legs fill progressively), verdict card + policy chip, control panel (ON/OFF, poisoned-doc
  textarea, Run/Reset), phone-style CONFIRM modal, exfil-sink view, leak-meter gauge,
  receipt-chain viewer with `verify_chain()` badge, replay scrubber. New endpoints:
  `POST /api/run|toggle|confirm|reset|tamper`, `GET /api/verify|session|detections|incident_report`.
- **Done when:** drive OFF (key arrives red) → ON (legs fill, sink locks red, verdict BLOCK,
  exfil empty) → CONFIRM modal (deny) → chain ✓ → Tamper → ✗ → replay scrubber rewinds.

### WS-G — Docs / tests / CI
- **Owns:** `tests/*`, `pyproject.toml`, `.github/workflows/ci.yml`, `CLAUDE.md`, `HANDOFF.md`,
  `TESTING.md`, `requirements.txt`. (WS-0 has already seeded most of these — extend, don't redo.)
- **Done when:** `pytest -q` green + CI green (matrix py3.11/3.12, ruff + pytest, fully offline);
  `TESTING.md` runbook written.

---

## Collision matrix (so two builders never touch the same file)

| File / dir | Owner | Everyone else |
|---|---|---|
| `cerberus/{labels,tracer,warden,sentinel,events}.py` | **WS-0 / frozen** | read-only |
| `cerberus/gateway.py`, `cerberus/session_state.py` | **WS-0** | read-only |
| `cerberus/mcp_*.py`, `claude_desktop_config.json`, `servers/servers.yaml` | WS-A | — |
| `host/llm_loop.py`, `host/providers.py`, `host/tools.py` | WS-B | — |
| `host/agent.py` | WS-0 (WS-B adds `--task` only) | read-only |
| `eval/*` | WS-C | — |
| `adversary/*` | WS-D | — |
| `siem/*`, `dashboard/static/forensics.js` | WS-E | — |
| `dashboard/static/*`, `dashboard/index.html`, `dashboard/app.py` | WS-F | WS-E adds forensics.js |
| `tests/*`, `pyproject.toml`, CI, docs | WS-G | WS-0 seeded |

**Frozen contracts** (changing these routes through the WS-0 owner, then everyone rebases):
the Event/Receipt JSON schema in `cerberus/events.py`; and the `Gateway.handle_call` /
`Gateway.list_tools` signatures.

---

## Coordination protocol

- **Exclusive ownership** per the matrix — never edit another workstream's files or the frozen core.
- **`git pull --rebase`** before starting and before every push. Commit small, push often.
- **Keep it green:** run `pytest -q` and `python -m host.agent` before every push. A broken demo
  is the worst outcome — protect it over breadth.
- **No AI-attribution trailer on commits** (repo convention).

---

## Glossary / refs

- **Lethal trifecta** — private data + untrusted content + external egress in one action (Willison).
- **IFC** — information-flow control; labels propagate as taint, join only taints up.
- **Declassification** — the single audited way a label weakens.
- **Rug pull** — a server mutates its manifest after approval (Sentinel `check_drift`).
- **In-head laundering** — model re-types a secret from hidden reasoning; backstops, not labels, catch it.
- Refs: CaMeL arXiv:2503.18813 · FIDES arXiv:2505.23643 · AgentDojo arXiv:2406.13352 ·
  permissive IFC for LLMs arXiv:2410.03055 · OWASP MCP03 / Top-10 for Agentic Apps (2025).
