# Cerberus

**A runtime reference monitor for AI agents.**

Static MCP scanners check your config before you deploy. Cerberus enforces capabilities on the live dataflow and shuts down the lethal trifecta the moment it forms. It's "defeat prompt injection by design" as a deployable thing, not a paper.

> Agents read untrusted content through the same channel as instructions. It's XSS with a credit card attached. Scanners are spellcheck. Cerberus is a reference monitor that enforces capabilities on live dataflow, blocks the lethal trifecta as it forms, and signs every decision with a cryptographic receipt.

---

## Why this, why now

We don't detect prompt injection. Detection is a cat-and-mouse game you lose. Cerberus treats exfiltration as a dataflow problem: every value carries a capability label (provenance, sensitivity, reader-ACL), labels propagate as taint, and a value can only leave to a sink its ACL permits. Injection-driven exfiltration becomes a structural violation, not a string to catch.

This operationalizes **CaMeL** (arXiv:2503.18813, 77% utility with provable security vs. 84% undefended on AgentDojo) and Microsoft **FIDES** (arXiv:2505.23643, deterministically blocked every AgentDojo injection) as a protocol-level, framework-agnostic MCP gateway, not a research interpreter (CaMeL) or a single-framework library (FIDES). That gap is the whole point.

The threat is real. Every one of these 2025 incidents is a lethal trifecta: private data plus untrusted content plus egress.

| Incident | Surface | CVE / CVSS |
|---|---|---|
| **EchoLeak** | Microsoft 365 Copilot, zero-click | CVE-2025-32711, 9.3 |
| **CamoLeak** | GitHub Copilot Chat | CVE-2025-59145, ~9.6 |
| **ForcedLeak** | Salesforce Agentforce | ~9.4 |
| ShadowLeak / AgentFlayer | ChatGPT Deep Research / Connectors | vendor-fixed |
| Slack AI exfil / GitLab Duo | RAG / MR descriptions | vendor-fixed |

The demand is priced in too. OWASP shipped a Top 10 for Agentic Applications in December 2025 explicitly calling for runtime guardrails that inspect the tool-call sequence. Gartner projects guardian agents at 10-15% of the agentic market by 2030 and 25% of enterprise breaches via agent abuse by 2028. The space saw a 2025 acquisition wave: Invariant to Snyk, Protect AI to Palo Alto (~$500M), Prompt Security to SentinelOne (~$250M), Lakera to Check Point (~$300M).

---

## The three heads

```
HOST (agent loop) ──MCP──▶ CERBERUS GATEWAY ──MCP──▶ downstream servers
                           ┌────────┐┌────────┐┌────────┐   (filesystem · weather ·
                           │SENTINEL ││ TRACER ││ WARDEN │    DocSearch[EVIL] · exfil)
                           └────────┘└────────┘└────────┘
                            emits events ─▶ session.jsonl + SSE ─▶ live DAG dashboard
```

- **Sentinel** (`cerberus/sentinel.py`) handles registration-time checks: manifest pinning, rug-pull drift detection, poisoned-description scanning, typosquats, cross-server shadowing.
- **Tracer** (`cerberus/tracer.py`) is the capability engine: label propagation, the lethal-trifecta detector (L1 private access, L2 untrusted influence, L3 egress), honeytokens, and a leak meter as backstops.
- **Warden** (`cerberus/warden.py`) enforces the capability-ACL policy with graded response modes (ALLOW / REDACT / CONFIRM / QUARANTINE / BLOCK) and produces signed, chain-hashed receipts.

The capability lattice lives in `cerberus/labels.py`. The event bus and tamper-evident receipt chain are in `cerberus/events.py`.

---

## Run the demo (no API key, no GPU, ~10 seconds)

```bash
pip install -r requirements.txt          # only pyyaml is strictly required
python -m host.agent                     # Act 1 (Cerberus OFF, the kill) then Act 2 (ON, the block)
python -m host.agent --confirm           # Act 2 in CONFIRM mode — you approve/deny live
```

With Cerberus **OFF**, the (fake, honeytokened) AWS key prints at the exfil endpoint. With it **ON**, the trifecta assembles, the call is blocked, the exfil endpoint stays empty, and the receipt chain verifies.

Live dashboard:

```bash
uvicorn dashboard.app:app --port 8000    # open http://127.0.0.1:8000 — Cytoscape DAG + SSE
python -m dashboard.app                  # or: forensic replay of session.jsonl in the terminal
```

---

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

---

## Threat model (the honest limits)

**Defends by construction:** tool poisoning, rug pulls, cross-server shadowing, indirect prompt injection via tool content, and the resulting exfiltration, backstopped by honeytokens and a leak meter.

**Limits we state out loud:**

- **In-head laundering.** A pure gateway can't track a label through the model's hidden reasoning. A model can read a secret and re-type it. Backstops cover the common cases; the full closure is code-mode, where the agent emits a plan and Cerberus executes it. That's the rigorous extension.
- **Don't let the detector be injectable.** A naive LLM judge is itself prompt-injectable. Cerberus's optional judge runs quarantined with no tools, no actions, and is advisory only. The deterministic capability core is the trust anchor.
- **Single point of trust.** Cerberus sees everything. Mitigation: store hashes not secrets, minimize trust, use signed receipts to make every decision auditable.
- **Fail-closed.** Unknown sink or insufficient reader-ACL means deny.

---

## Roadmap

1. **Standards:** map controls to OWASP Agentic ASI02 (Tool Misuse) / ASI06 (Memory Poisoning); file into the COSAI/OASIS WS4 gap (which openly admits no standard yet specifies the dataflow-enforcement primitive); pursue an MCP SEP for capability attestation.
2. **Open source:** ship the gateway and an AgentDojo eval harness anyone can reproduce (the garak / NeMo-Guardrails adoption playbook).
3. **Commercial:** the signed receipt chain is an EU AI Act high-risk audit trail (obligations land August 2026), a wedge for enterprise design partners.

---

*Design anchors: CaMeL (arXiv:2503.18813) · FIDES (arXiv:2505.23643) · AgentDojo (arXiv:2406.13352) · the lethal trifecta and dual-LLM pattern (Simon Willison) · MCP tool poisoning (Invariant Labs / OWASP MCP03) · OWASP Top 10 for Agentic Applications (2025).*
