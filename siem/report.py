"""Build a signed incident report from a Cerberus session.

NIST SP 800-61 / SANS PICERL shaped (Identification -> Containment -> evidence ->
Lessons), with the tamper-evident receipt chain as the integrity attestation that
frames the log as the EU AI Act Art. 12 audit artifact. Authored with the
07-incident-response skill's report structure.
"""
from __future__ import annotations

from typing import List

from .correlate import Detection


def _head_hash(events: List[dict]) -> str:
    for e in reversed(events):
        if e.get("kind") == "verdict":
            return e["data"].get("this_hash", "") or ""
    return ""


def _timeline(events: List[dict]) -> str:
    if not events:
        return "_(no events)_"
    t0 = events[0].get("ts", 0)
    rows = []
    for e in events:
        d = e.get("data", {}) or {}
        kind = e.get("kind")
        rel = e.get("ts", 0) - t0
        if kind == "tool_call":
            desc = f"tool call → `{d.get('server')}.{d.get('tool')}`"
        elif kind == "value":
            tag = "UNTRUSTED" if d.get("value_kind") == "untrusted" else "tool"
            desc = f"value labelled **{tag}** (sensitivity={d.get('sensitivity')})"
        elif kind == "sentinel":
            desc = f"SENTINEL **{d.get('severity')} {d.get('code')}** on `{d.get('server')}`"
        elif kind == "trifecta":
            desc = "**LETHAL TRIFECTA** assembled (L1 ∧ L2 ∧ L3)"
        elif kind == "verdict":
            desc = f"VERDICT **{d.get('decision')}** — {d.get('reason', '')}"
        elif kind == "confirm_request":
            desc = "human approval requested (CONFIRM)"
        else:
            desc = kind
        rows.append(f"| +{rel:6.2f}s | `{kind}` | {desc} |")
    return "\n".join(rows)


def build_report(events: List[dict], detections: List[Detection],
                 intact: bool, n_receipts: int) -> str:
    head = _head_hash(events)
    blocked = sum(1 for e in events if e.get("kind") == "verdict"
                  and e["data"].get("decision") in ("BLOCK", "QUARANTINE"))
    top = detections[0].level.upper() if detections else "NONE"
    det_rows = "\n".join(
        f"| {d.level.upper()} | {d.title} | {d.owasp} | {d.count} |" for d in detections
    ) or "| — | no detections | — | 0 |"

    return f"""# Cerberus — Security Incident Report

> Generated from a tamper-evident `session.jsonl`. This document is the EU AI Act
> Art. 12 (record-keeping) audit artifact: every line below is backed by a signed,
> chain-hashed receipt. Structure follows NIST SP 800-61 / SANS PICERL.

## 1. Executive summary

- **Events analysed:** {len(events)}  ·  **Detections:** {len(detections)}  ·  **Highest severity:** {top}
- **Egress attempts blocked by Cerberus:** {blocked}
- **Receipt chain:** {"✓ INTACT" if intact else "✗ TAMPERED"} ({n_receipts} receipts)
- **Outcome:** {"Exfiltration was prevented structurally — no SECRET value reached an external sink."
                if blocked else "No blocking action was required in this session."}

## 2. Identification — detections (mapped to OWASP Agentic Top-10)

| Severity | Detection | OWASP | Hits |
|----------|-----------|-------|------|
{det_rows}

## 3. Forensic timeline

| t (rel) | event | description |
|---------|-------|-------------|
{_timeline(events)}

## 4. Containment & outcome

Cerberus is a reference monitor: containment is **inline and automatic**. The lethal
trifecta (private data ∧ untrusted influence ∧ external egress) is a *structural*
violation, so the offending egress call was denied before it executed — there is no
post-hoc cleanup because the secret never left the trust boundary. Honeytoken and
leak-meter backstops cover the in-head-laundering case where labels alone cannot see.

## 5. Integrity attestation (the signature)

- `verify_chain()` → **{"INTACT" if intact else "BROKEN"}**
- receipts: **{n_receipts}**
- chain head: `{head[:32] + "…" if head else "(none)"}`

Re-verify independently:  `cerberus-verify session.jsonl`

## 6. Lessons learned / recommendations

- Keep `trifecta_mode: BLOCK` for high-risk sinks; use `CONFIRM` only where a human
  can meaningfully adjudicate.
- Quarantined servers (Sentinel BLOCK findings) should be removed from the deployment,
  not merely hidden — investigate the source of any POISONED_DESC / RUG_PULL finding.
- Retain `session.jsonl` per your record-keeping obligations; its chain makes tampering
  detectable after the fact.
"""
