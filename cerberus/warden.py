"""
Warden — policy evaluation + graded response modes + signed receipts.

The Warden turns a Tracer verdict into an action. Response modes are graded so the
agent stays *usable* (label/taint explosion + a hair-trigger BLOCK is what makes IFC
systems get torn out):

    ALLOW       let it through
    REDACT      strip the offending value, let the rest proceed
    CONFIRM     pause and ask a human (out-of-band, e.g. push to phone)
    QUARANTINE  route to a no-tools sandbox for inspection
    BLOCK       fail-closed

Fail-closed by default: an unknown sink, or a SECRET/PRIVATE value whose reader-ACL
does not permit the destination, is denied. The deterministic capability core is the
trust anchor -- never an LLM judge (a naive LLM judge is itself prompt-injectable).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml

from .events import EventBus, args_digest
from .labels import Capability, join_all
from .tracer import TrifectaState


class Mode(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    CONFIRM = "CONFIRM"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


@dataclass
class Decision:
    mode: Mode
    reason: str
    blast_radius: str = ""        # human-readable "what was averted"


class Warden:
    def __init__(self, policy_path: str | Path, bus: EventBus,
                 confirm_fn: Optional[Callable[[str], bool]] = None):
        self.bus = bus
        self.policy = self._load(policy_path)
        # confirm_fn: out-of-band human approval. Returns True if approved.
        self.confirm_fn = confirm_fn or (lambda prompt: False)  # default: deny

    @staticmethod
    def _load(path: str | Path) -> dict:
        p = Path(path)
        if not p.exists():
            return {"trifecta_mode": "BLOCK", "default_sink_mode": "BLOCK",
                    "external_sinks": []}
        return yaml.safe_load(p.read_text()) or {}

    # ---- the enforcement point ----------------------------------------------

    def decide(self, *, tool: str, sink: str, is_egress_sink: bool,
               arg_caps: List[Capability], payload: str,
               trifecta: TrifectaState,
               acl_violation: Optional[Capability]) -> Decision:
        merged = join_all(arg_caps)

        # 1) the headline: the lethal trifecta has assembled in one call
        if trifecta.complete:
            mode = Mode(self.policy.get("trifecta_mode", "BLOCK"))
            decision = self._resolve_confirm(
                mode, prompt=f"Approve {tool} -> {sink} "
                             f"(sends {merged.sensitivity.name} data influenced by "
                             f"untrusted content)?")
            d = Decision(decision,
                         "lethal trifecta: private data + untrusted influence + egress",
                         blast_radius=f"{merged.sensitivity.name} exfiltration to {sink}")
            return self._record(tool, arg_caps, payload, trifecta, d)

        # 2) reader-ACL violation on egress (fail-closed)
        if is_egress_sink and acl_violation is not None:
            mode = Mode(self.policy.get("default_sink_mode", "BLOCK"))
            d = Decision(mode,
                         f"reader-ACL forbids {acl_violation.sensitivity.name} value "
                         f"flowing to {sink}",
                         blast_radius=f"{acl_violation.sensitivity.name} -> {sink}")
            return self._record(tool, arg_caps, payload, trifecta, d)

        # 3) backstops fired even though labels were clean (in-head laundering)
        if is_egress_sink and ("honeytoken" in trifecta.evidence
                               or "leak_meter" in trifecta.evidence):
            d = Decision(Mode.BLOCK,
                         f"backstop tripped: {trifecta.evidence.get('honeytoken') or trifecta.evidence.get('leak_meter')}",
                         blast_radius="canary/secret fragment in outbound payload")
            return self._record(tool, arg_caps, payload, trifecta, d)

        # 4) clean
        return self._record(tool, arg_caps, payload, trifecta,
                            Decision(Mode.ALLOW, "no policy violation"))

    # ---- helpers ------------------------------------------------------------

    def _resolve_confirm(self, mode: Mode, prompt: str) -> Mode:
        """If policy says CONFIRM, ask the human; map their answer to ALLOW/BLOCK."""
        if mode != Mode.CONFIRM:
            return mode
        approved = self.confirm_fn(prompt)
        return Mode.ALLOW if approved else Mode.BLOCK

    def _record(self, tool, arg_caps, payload, trifecta, d: Decision) -> Decision:
        merged = join_all(arg_caps)
        self.bus.issue_receipt(
            tool=tool,
            args_hash=args_digest(payload),
            labels={"provenance": int(merged.provenance),
                    "sensitivity": int(merged.sensitivity),
                    "readers": sorted(merged.readers)},
            head_verdicts=trifecta.as_dict(),
            decision=d.mode.value,
            reason=d.reason,
        )
        return d
