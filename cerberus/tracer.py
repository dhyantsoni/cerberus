"""
Tracer — the capability engine: label propagation, the lethal-trifecta detector,
honeytokens, and the leak meter.

The trifecta detector is the headline. Over the current action window we track:

    L1 private_access     has the agent touched SECRET/PRIVATE data?
    L2 untrusted_influence is this action influenced by TOOL_UNTRUSTED provenance?
    L3 egress             is this call an external sink?

When ONE tool call satisfies all three -> TRIFECTA -> the red-lock moment. This
is exactly Willison's lethal trifecta (private data + untrusted content + external
communication) made operational and enforced, not merely detected.

Backstops, for the honest limit where a model launders a secret in its own
reasoning (a pure gateway can't track a label through hidden chain-of-thought):
  * honeytokens  - unique canaries seeded into SECRET sources; a canary in any
                   outbound payload flags regardless of labels.
  * leak meter   - n-gram overlap between known secrets and the outbound payload,
                   to catch base64 / light transforms. Reported as "~N bits".
The deterministic capability core remains the trust anchor; backstops are advisory.
"""
from __future__ import annotations

import math
import re
import secrets as _secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .labels import Capability, Provenance, Sensitivity, join_all, next_ref


# ---- honeytokens ------------------------------------------------------------

class HoneytokenVault:
    """Seeds and recognises canaries planted in SECRET sources."""

    def __init__(self) -> None:
        self._tokens: Dict[str, str] = {}   # id -> canary string

    def mint(self, label: str = "canary") -> str:
        tok = f"CERB-{_secrets.token_hex(8)}"
        self._tokens[label] = tok
        return tok

    def scan(self, payload: str) -> List[str]:
        """Return ids of any canaries (or 4+ char fragments) present in payload."""
        hits = []
        for label, tok in self._tokens.items():
            if tok in payload or tok[5:13] in payload:
                hits.append(label)
        return hits


# ---- leak meter -------------------------------------------------------------

def _ngrams(s: str, n: int = 4) -> set:
    s = re.sub(r"\s+", "", s.lower())
    return {s[i:i + n] for i in range(len(s) - n + 1)} if len(s) >= n else {s}


def estimate_leak_bits(secret_value: str, payload: str) -> float:
    """Crude mutual-information proxy: n-gram overlap scaled by secret entropy.

    Not a security boundary -- a *meter*. Catches verbatim and lightly-transformed
    leaks (e.g. the secret echoed inside a larger payload) and renders a number the
    judge can see. Returns estimated bits of the secret present in the payload.
    """
    if not secret_value or not payload:
        return 0.0
    sg, pg = _ngrams(secret_value), _ngrams(payload)
    if not sg:
        return 0.0
    overlap = len(sg & pg) / len(sg)
    secret_entropy_bits = len(secret_value) * math.log2(64)  # ~base64 alphabet
    return round(overlap * secret_entropy_bits, 1)


# ---- the trifecta detector --------------------------------------------------

@dataclass
class TrifectaState:
    L1_private_access: bool = False
    L2_untrusted_influence: bool = False
    L3_egress: bool = False
    evidence: Dict[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return self.L1_private_access and self.L2_untrusted_influence and self.L3_egress

    def as_dict(self) -> Dict[str, bool]:
        return {
            "L1_private_access": self.L1_private_access,
            "L2_untrusted_influence": self.L2_untrusted_influence,
            "L3_egress": self.L3_egress,
        }


class Tracer:
    """Holds the provenance graph state and evaluates each outbound tool call."""

    def __init__(self, bus=None) -> None:
        self.bus = bus
        self.vault = HoneytokenVault()
        self.known_secrets: List[str] = []     # raw secret strings (for the leak meter only)
        # per-session memory of what the agent has touched
        self._touched_protected = False
        self._untrusted_seen = False

    # ---- ingestion: label a value coming back from a server -----------------

    def observe_tool_result(self, server_trusted: bool, sensitivity: Sensitivity,
                            value: str, readers=frozenset()) -> Capability:
        from .labels import Capability as Cap
        prov = Provenance.TOOL_TRUSTED if server_trusted else Provenance.TOOL_UNTRUSTED
        cap = Cap(provenance=prov, sensitivity=sensitivity,
                  readers=readers if readers else (frozenset() if sensitivity >= Sensitivity.PRIVATE
                                                   else frozenset({"*"})),
                  source_ref=next_ref())
        if cap.is_protected:
            self._touched_protected = True
        if cap.is_untrusted:
            self._untrusted_seen = True
        if self.bus:
            self.bus.emit("value", value_kind=("untrusted" if cap.is_untrusted else "tool"),
                          sensitivity=int(cap.sensitivity), ref=cap.source_ref)
        return cap

    def seed_secret(self, value: str, label: str = "secret") -> str:
        """Register a SECRET and plant a canary near it. Returns the canary."""
        self.known_secrets.append(value)
        return self.vault.mint(label)

    # ---- evaluation: is THIS call a trifecta? -------------------------------

    def evaluate(self, *, is_egress_sink: bool, arg_caps: List[Capability],
                 payload: str) -> TrifectaState:
        merged = join_all(arg_caps)
        st = TrifectaState()

        # L1 -- private/secret data is in play (this call or earlier in session)
        st.L1_private_access = merged.is_protected or self._touched_protected
        if merged.is_protected:
            st.evidence["L1"] = f"argument carries {merged.sensitivity.name}"

        # L2 -- the action is influenced by untrusted content
        st.L2_untrusted_influence = (merged.provenance == Provenance.TOOL_UNTRUSTED
                                     or self._untrusted_seen)
        if merged.provenance == Provenance.TOOL_UNTRUSTED:
            st.evidence["L2"] = "argument derived from TOOL_UNTRUSTED provenance"

        # L3 -- this is an external sink
        st.L3_egress = is_egress_sink
        if is_egress_sink:
            st.evidence["L3"] = "call targets an external sink"

        # backstops (advisory)
        canaries = self.vault.scan(payload)
        if canaries:
            st.evidence["honeytoken"] = f"canary(s) in payload: {canaries}"
        leak = max((estimate_leak_bits(s, payload) for s in self.known_secrets), default=0.0)
        if leak > 0:
            st.evidence["leak_meter"] = f"~{leak} bits of a known secret in payload"

        if self.bus and st.complete:
            self.bus.emit("trifecta", **st.as_dict(), evidence=st.evidence)
        return st

    def reader_acl_violation(self, sink: str, arg_caps: List[Capability]) -> Optional[Capability]:
        """Fail-closed sink check: return the first cap whose ACL forbids ``sink``."""
        for cap in arg_caps:
            if not cap.may_flow_to(sink):
                return cap
        return None
