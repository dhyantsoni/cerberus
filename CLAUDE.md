# CLAUDE.md

Working agreement for Claude in this repo. Terse on purpose — every line here is
load-bearing. For the full pitch see @README.md; for the demo runsheet see @demo_script.md.

## What Cerberus is

A runtime reference monitor / MCP security gateway that makes prompt-injection data
exfiltration — the **lethal trifecta** (private read ∧ untrusted influence ∧ external
egress) — *structurally* impossible via capability-label dataflow tracking, and proves it
with a tamper-evident signed receipt chain. It operationalizes CaMeL (arXiv:2503.18813)
and FIDES (arXiv:2505.23643) as the first protocol-level, framework-agnostic deployment.

## The three heads (mental model)

```
HOST (agent loop) ──▶ CERBERUS GATEWAY ──▶ downstream MCP servers
                      SENTINEL · TRACER · WARDEN ──▶ session.jsonl + receipts + SSE
```

- **Sentinel** (`cerberus/sentinel.py`) — registration-time: poisoned-description scan,
  typosquat, cross-server shadowing, rug-pull drift. A BLOCK finding quarantines the server.
- **Tracer** (`cerberus/tracer.py`) — the capability engine: label propagation + the
  trifecta detector (L1 private · L2 untrusted · L3 egress) + honeytoken/leak-meter backstops.
- **Warden** (`cerberus/warden.py`) — capability-ACL policy → graded modes
  (ALLOW / REDACT / CONFIRM / QUARANTINE / BLOCK) → signed, chain-hashed receipts.

Lattice in `cerberus/labels.py`; event bus + receipt chain in `cerberus/events.py`;
the reference monitor itself in `cerberus/gateway.py`.

## Repo map

```
cerberus/   labels · events · sentinel · tracer · warden · gateway · session_state · cli
host/       agent.py (scripted demo: build_gateway + drive_attack), llm_loop (WS-B)
servers/    filesystem · weather · docsearch(EVIL) · exfil_server
policies/   default.yaml   (capability-ACL + graded response + declassification)
dashboard/  app.py + index.html (live provenance DAG via Cytoscape + SSE)
eval/       AgentDojo harness (WS-C)        adversary/  red-team loop (WS-D)
siem/       audit/SIEM layer (WS-E)         tests/      pytest suite
sandbox/    fake honeytokened creds/keys + runbook.md
```

## Build / run / test

```bash
pip install -e .[test]            # core + pytest; .[all] for host/mcp/dashboard too
python -m host.agent              # OFF (the kill) then ON (the block) — no API key, ~10s
python -m host.agent --confirm    # ON in CONFIRM mode; you approve/deny at the prompt
pytest -q                         # full suite, offline + deterministic
python -m cerberus.cli session.jsonl   # cerberus-verify: re-hash the receipt chain
uvicorn dashboard.app:app --port 8000  # live DAG dashboard
```

## SECURITY INVARIANTS — do not violate these

1. **Fail-closed.** Unknown sink, or a SECRET/PRIVATE value whose reader-ACL does not
   permit the destination → deny. The default `confirm_fn` denies.
2. **The deterministic core is the only trust anchor.** No LLM judge ever gates a decision
   (a naive LLM judge is itself prompt-injectable). Any judge is advisory, quarantined, no tools.
3. **Labels only ever join *up*.** `join` = max(provenance), max(sensitivity),
   intersect(readers). The single sanctioned weakening is explicit `declassify()`.
4. **The trifecta needs all three legs in one outbound call** — never "2 of 3". L1∧L2∧L3.
5. **Receipts are append-only and `verify_chain()` must stay True.** Each receipt embeds the
   previous hash. Never mutate a past receipt; never reorder the chain.
6. **Honeytokens + leak meter are backstops only** — advisory evidence for in-head laundering,
   never the primary boundary. The capability labels are the boundary.

## The frozen core — additive changes only

`cerberus/{labels,tracer,warden,sentinel,events}.py` are **frozen**. Extend at the seams,
do not rewrite. The Event/Receipt JSON schema in `events.py` and the
`Gateway.handle_call` / `Gateway.list_tools` signatures are **frozen contracts** — other
workstreams depend on them. If one genuinely must change, it routes through the WS-0 owner.

Real callers (LLM loop, MCP client, benchmark) never pass `args["_caps"]`. The
`LabelLedger` (`cerberus/session_state.py`) reconstructs provenance from prior results by
substring containment; `Gateway(auto_label=True)` turns that on. The scripted demo passes
explicit `_caps` with `auto_label=False` and its event stream must stay byte-identical.

## How to work here

- **Think before editing.** State what you'll change and why; make the smallest surgical
  change that holds the invariants above. Match the surrounding style and comment density.
- **The number and the block are the deliverables.** Protect the green demo and one green
  eval suite over breadth. A broken `python -m host.agent` is the worst outcome.
- **Verify, don't assume.** After a change run `python -m host.agent` and `pytest -q`.
  Report failures with the actual output — never claim green you didn't see.
- **Stay in your lane.** If you own a workstream (see `HANDOFF.md`), touch only its files
  and never the frozen core. `git pull --rebase` before starting and before every push.
- **No AI-attribution trailer on commits** (repo convention). Small, frequent commits.
