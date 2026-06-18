"""
Capability labels + the security lattice.

This is the intellectual core of Cerberus. Every *value* that flows through a
tool call (a string, blob, or structured field) carries a ``Capability``. When
values combine into a tool-call argument, labels join along a lattice:

    provenance  -> most-untrusted wins   (join, "taint up")
    sensitivity -> most-sensitive wins   (join)
    readers     -> intersection          (meet, "narrow the ACL")

This is standard information-flow control (IFC). It is what separates Cerberus
from regex/LLM-classifier scanners: we do not *detect* injection, we make
exfiltration of a labelled value to a disallowed sink a structural violation.

Refs: CaMeL (arXiv:2503.18813), Microsoft FIDES (arXiv:2505.23643),
"Permissive Information-Flow Analysis for LLMs" (arXiv:2410.03055).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import FrozenSet, Optional
import itertools


class Provenance(IntEnum):
    """Who produced a value. Higher = less trusted (join takes the max)."""
    SYSTEM = 0          # Cerberus / policy itself
    USER = 1            # the human's original instruction (the trust anchor)
    TOOL_TRUSTED = 2    # output of a vetted, benign server
    TOOL_UNTRUSTED = 3  # output of an untrusted server / fetched web content


class Sensitivity(IntEnum):
    """How protected a value must be. Higher = more sensitive (join takes max)."""
    PUBLIC = 0
    PRIVATE = 1
    SECRET = 2


# Sentinel reader-set meaning "any sink is allowed".
WILDCARD = "*"


@dataclass(frozen=True)
class Capability:
    """An immutable label attached to a single value flowing through the gateway."""
    provenance: Provenance = Provenance.USER
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    readers: FrozenSet[str] = field(default_factory=lambda: frozenset({WILDCARD}))
    source_ref: Optional[str] = None       # node id for the provenance DAG / receipts
    honeytoken_id: Optional[str] = None     # canary seeded into the value, if any

    # ---- lattice operations -------------------------------------------------

    def join(self, other: "Capability", source_ref: Optional[str] = None) -> "Capability":
        """Combine two labels into the *most restrictive* result (taint join)."""
        return Capability(
            provenance=Provenance(max(self.provenance, other.provenance)),
            sensitivity=Sensitivity(max(self.sensitivity, other.sensitivity)),
            readers=_meet_readers(self.readers, other.readers),
            source_ref=source_ref,
            # preserve any canary present in either operand
            honeytoken_id=self.honeytoken_id or other.honeytoken_id,
        )

    def may_flow_to(self, sink: str) -> bool:
        """Does this value's reader-ACL permit flowing to ``sink``?"""
        return WILDCARD in self.readers or sink in self.readers

    def declassify(self, *, sensitivity: Sensitivity | None = None,
                   add_readers: FrozenSet[str] | None = None) -> "Capability":
        """Explicit, policy-authorised downgrade (e.g. user approved sending file X).

        Keeps false positives down and is a clean concept to cite. Declassification
        is the *only* sanctioned way a label gets weaker; everything else joins up.
        """
        readers = self.readers | (add_readers or frozenset())
        return replace(
            self,
            sensitivity=sensitivity if sensitivity is not None else self.sensitivity,
            readers=readers,
        )

    @property
    def is_untrusted(self) -> bool:
        return self.provenance == Provenance.TOOL_UNTRUSTED

    @property
    def is_protected(self) -> bool:
        return self.sensitivity >= Sensitivity.PRIVATE


def _meet_readers(a: FrozenSet[str], b: FrozenSet[str]) -> FrozenSet[str]:
    """Intersection on reader-ACLs, with WILDCARD acting as the top element."""
    if WILDCARD in a:
        return b
    if WILDCARD in b:
        return a
    return a & b


def join_all(caps, source_ref: Optional[str] = None) -> Capability:
    """Join an iterable of capabilities (empty -> a fully-public USER label)."""
    caps = list(caps)
    if not caps:
        return Capability(source_ref=source_ref)
    acc = caps[0]
    for c in caps[1:]:
        acc = acc.join(c)
    return acc if source_ref is None else replace(acc, source_ref=source_ref)


# ---- convenience constructors used by servers / the gateway -----------------

def secret(readers: FrozenSet[str] = frozenset(), **kw) -> Capability:
    """A SECRET value (creds, keys). Default readers = {} -> no external flow."""
    return Capability(provenance=Provenance.TOOL_TRUSTED,
                      sensitivity=Sensitivity.SECRET, readers=readers, **kw)


def private(readers: FrozenSet[str] = frozenset({"user", "internal"}), **kw) -> Capability:
    return Capability(provenance=Provenance.TOOL_TRUSTED,
                      sensitivity=Sensitivity.PRIVATE, readers=readers, **kw)


def public_untrusted(**kw) -> Capability:
    """Output of an untrusted server: untrusted provenance, but not itself secret."""
    return Capability(provenance=Provenance.TOOL_UNTRUSTED,
                      sensitivity=Sensitivity.PUBLIC,
                      readers=frozenset({WILDCARD}), **kw)


def user_instruction(**kw) -> Capability:
    return Capability(provenance=Provenance.USER, sensitivity=Sensitivity.PUBLIC,
                      readers=frozenset({WILDCARD}), **kw)


_counter = itertools.count(1)


def next_ref(prefix: str = "v") -> str:
    return f"{prefix}{next(_counter)}"
