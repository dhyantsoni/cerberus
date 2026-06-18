# Cerberus

**A runtime reference monitor for AI agents.** Static MCP scanners lint your config
before you deploy; Cerberus enforces capabilities on the **live dataflow** and severs
the **lethal trifecta** the moment it forms. It's the deployable version of *"defeat
prompt injection by design."*

> Agents read untrusted content through the same channel as instructions — it's XSS
> with a credit card. Scanners are spellcheck. Cerberus is a reference monitor that
> enforces capabilities on live dataflow, blocks the lethal trifecta as it forms, and
> ships every decision with a cryptographic receipt.

---

## Why this, why now

We don't *detect* prompt injection — detection is a cat-and-mouse you lose. Cerberus
treats exfiltration as a **dataflow** problem: every value carries a capability label
(provenance + sensitivity + reader-ACL), labels propagate as taint, and a value can
only leave to a sink its ACL permits. Injection-driven exfiltration becomes a
*structural* violation, not a string to catch.

This operationalizes **CaMeL** (*Defeating Prompt Injections by Design*,
arXiv:2503.18813 — 77% utility *with provable security* vs 84% undefended on AgentDojo)
and Microsoft **FIDES** (arXiv:2505.23643 — deterministically blocked every AgentDojo
injection) — but as a **protocol-level, framework-agnostic MCP gateway**, not a research
interpreter (CaMeL) or a single-framework library (FIDES). That gap is the whole point.

The threat is no longer theoretical — every one of these 2025 incidents is a lethal
trifecta (private data + untrusted content + egress):

| Incident | Surface | CVE / CVSS |
|---|---|---|
| **EchoLeak** | Microsoft 365 Copilot, zero-click | CVE-2025-32711, 9.3 |
| **CamoLeak** | GitHub Copilot Chat | CVE-2025-59145, ~9.6 |
| **ForcedLeak** | Salesforce Agentforce | ~9.4 |
| ShadowLeak / AgentFlayer | ChatGPT Deep Research / Connectors | vendor-fixed |
| Slack AI exfil · GitLab Duo | RAG / MR descriptions | vendor-fixed |

And the demand is priced in: OWASP shipped a **Top 10 for Agentic Applications**
(Dec 2025) explicitly calling for *"runtime guardrails that inspect the tool-call
sequence"*; Gartner projects **"guardian agents" at 10–15% of the agentic market by
2030** and **25% of enterprise breaches via agent abuse by 2028**; and the space saw a
2025 acquisition wave (Invariant→Snyk, Protect AI→Palo Alto ~$500M, Prompt
Security→SentinelOne ~$250M, Lakera→Check Point ~$300M).

## The three heads

```
HOST (agent loop) ──MCP──▶ CERBERUS GATEWAY ──MCP──▶ downstream servers
                           ┌────────┐┌────────┐┌────────┐   (filesystem · weather ·
                           │SENTINEL ││ TRACER ││ WARDEN │    DocSearch[EVIL] · exfil)
                           └────────┘└────────┘└────────┘
                            emits events ─▶ session.jsonl + SSE ─▶ live DAG dashboard
```

- **Sentinel** (`cerberus/sentinel.py`) — registration-time: manifest pinning + rug-pull
  drift, poisoned-description scan, typosquat, cross-server shadowing.
- **Tracer** (`cerberus/tracer.py`) — the capability engine: label propagation, the
  **lethal-trifecta detector** (L1 private access · L2 untrusted influence · L3 egress),
  honeytokens + leak meter as backstops.
- **Warden** (`cerberus/warden.py`) — capability-ACL policy + graded response modes
  (ALLOW / REDACT / CONFIRM / QUARANTINE / BLOCK) + signed, chain-hashed receipts.

The capability lattice lives in `cerberus/labels.py`; the event bus + tamper-evident
receipt chain in `cerberus/events.py`.

## Run the demo (no API key, no GPU, ~10 seconds)

```bash
pip install -r requirements.txt          # only pyyaml is strictly required
python -m host.agent                     # Act 1 (Cerberus OFF, the kill) then Act 2 (ON, the block)
python -m host.agent --confirm           # Act 2 in CONFIRM mode — you approve/deny live
```

Expected: with Cerberus **OFF** the (fake, honeytokened) AWS key prints at the exfil
endpoint; with it **ON** the trifecta assembles, the call is **BLOCKED**, the exfil
endpoint stays empty, and the receipt chain verifies.

Live dashboard (the glamour layer):

```bash
uvicorn dashboard.app:app --port 8000    # open http://127.0.0.1:8000 — Cytoscape DAG + SSE
python -m dashboard.app                  # or: forensic replay of session.jsonl in the terminal
```

## Repo layout

```
cerberus/   labels.py · events.py · sentinel.py · tracer.py · warden.py · gateway.py
host/       agent.py            # scripted attack path (drop-in: Anthropic API / Ollama)
servers/    filesystem · weather · docsearch(EVIL) · exfil_server
policies/   default.yaml        # capability-ACL + graded response + declassification
dashboard/  index.html · app.py # live provenance DAG (Cytoscape + SSE) + replay scrubber
eval/       agentdojo_runner.py # stretch — the benchmark number
adversary/  attacker.py         # stretch — evolving attacker + leaderboard
sandbox/    fake creds/keys (honeytokened) + runbook.md
```

## Threat model (the honest limits — credibility, not weakness)

**Defends, by construction:** tool poisoning, rug pulls, cross-server shadowing,
indirect prompt injection via tool content, and the resulting exfiltration — backstopped
by honeytokens + a leak meter.

**Limits we state out loud:**
- **In-head laundering.** A pure gateway can't track a label through the model's hidden
  reasoning (it can read a secret and re-type it). Backstops (honeytokens, leak meter)
  cover the common cases; the full closure is **code-mode** — the agent emits a plan and
  Cerberus executes it — noted as the rigorous extension.
- **Don't let the detector be injectable.** A naive LLM-judge is itself prompt-injectable.
  Cerberus's optional judge runs quarantined (no tools, no actions) and is **advisory
  only** — the deterministic capability core is the trust anchor.
- **Single point of trust.** Cerberus sees everything. Mitigation: store hashes not
  secrets; minimize trust; signed receipts make every decision auditable.
- **Fail-closed.** Unknown sink or insufficient reader-ACL → deny.

## Roadmap to impact

1. **Standards:** map controls to OWASP Agentic **ASI02 (Tool Misuse) / ASI06 (Memory
   Poisoning)**; file into the **COSAI/OASIS WS4** gap (it openly admits no standard yet
   specifies the dataflow-enforcement primitive); pursue an **MCP SEP** for capability
   attestation.
2. **Open source:** ship the gateway + an AgentDojo eval harness anyone can reproduce
   (the garak / NeMo-Guardrails adoption playbook).
3. **Commercial:** the signed receipt chain *is* an EU AI Act high-risk audit trail
   (obligations land Aug 2026) — a wedge for enterprise design partners.

---

*Design anchors: CaMeL (arXiv:2503.18813) · FIDES (arXiv:2505.23643) · AgentDojo
(arXiv:2406.13352) · the lethal trifecta & dual-LLM pattern (Simon Willison) · MCP tool
poisoning (Invariant Labs → OWASP MCP03) · OWASP Top 10 for Agentic Applications (2025).*
