"""
LabelLedger — gateway-layer provenance reconstruction.

The frozen core labels values *explicitly*: the in-process demo passes
capabilities to the gateway via ``args["_caps"]``. Real callers — an LLM tool
loop, an MCP client spawned by Claude Desktop, a benchmark harness — never do
that. They hand the gateway plain JSON arguments with no provenance attached.

The ``LabelLedger`` bridges that gap the way FIDES (arXiv:2505.23643) and CaMeL
(arXiv:2503.18813) do at the gateway layer: it records the ``Capability`` of
every value the gateway emits, then reconstructs an incoming call's
``arg_caps`` by value-substring containment. Any text it cannot attribute to a
prior tool result is treated as the user's own instruction — the USER trust
anchor (``user_instruction()``).

Honest limit: substring containment cannot see a secret that the model launders
inside its hidden chain-of-thought (e.g. "spell the key backwards, then send").
That is exactly what the honeytoken + leak-meter backstops in ``tracer.py`` exist
to catch. The deterministic capability labels remain the trust anchor; the
ledger only reconstructs what an honest transport would otherwise have to thread.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .labels import Capability, user_instruction


@dataclass
class _Entry:
    value: str
    cap: Capability


class LabelLedger:
    """Per-session memory of ``value -> Capability`` for provenance recovery."""

    def __init__(self, min_len: int = 8) -> None:
        # Only index reasonably distinctive fragments. A 1-char tool result would
        # match almost any payload and cause spurious taint; an 8+ char fragment
        # is a meaningful provenance signal.
        self._min_len = min_len
        self._entries: List[_Entry] = []
        self._by_ref: Dict[str, Capability] = {}

    def record(self, value: object, cap: Capability) -> None:
        """Remember that ``value`` carries ``cap`` (called on every tool result)."""
        if value is None:
            return
        text = str(value)
        if cap.source_ref:
            self._by_ref[cap.source_ref] = cap
        if len(text.strip()) >= self._min_len:
            self._entries.append(_Entry(value=text, cap=cap))

    def cap_for_ref(self, ref: str) -> Optional[Capability]:
        return self._by_ref.get(ref)

    def infer_caps(self, args: dict) -> List[Capability]:
        """Reconstruct the capabilities flowing into a call from its arguments.

        Every recorded value that appears (as a substring) in the call's payload
        contributes its capability. The USER trust anchor is always included so
        that an all-benign call resolves to USER/PUBLIC rather than the empty
        join — but because ``join`` taints *up*, a single attributed untrusted or
        secret fragment still dominates the merged label.
        """
        text = self._payload_text(args)
        caps: List[Capability] = []
        for entry in self._entries:
            fragment = entry.value.strip()
            if fragment and fragment in text:
                caps.append(entry.cap)
        # Un-attributable text == the user's own words (the trust anchor).
        caps.append(user_instruction())
        return caps

    @staticmethod
    def _payload_text(args: dict) -> str:
        return " ".join(
            str(v) for k, v in args.items() if not str(k).startswith("_")
        )
