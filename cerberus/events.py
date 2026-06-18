"""
Structured event bus + tamper-evident receipts.

Two jobs:
  1. Emit structured events to ``session.jsonl`` AND to any live subscribers
     (the dashboard SSE/WebSocket stream).
  2. Chain-hash every decision into a tamper-evident audit log. Each receipt
     embeds the previous receipt's hash, so any edit to history breaks the chain.

The receipt chain is a *first-class deliverable*, not an afterthought: it is the
"every action ships with a cryptographic receipt" artifact, and it doubles as the
audit trail that EU AI Act high-risk obligations (Aug 2026) will demand. Because
Cerberus already observes every labelled dataflow, forensic audit is nearly free.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


GENESIS = "0" * 64


@dataclass
class Event:
    kind: str                       # "tool_call" | "verdict" | "sentinel" | "trifecta" | ...
    ts: float = field(default_factory=time.time)
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Receipt:
    """A signed, chained record of one decision."""
    ts: float
    tool: str
    args_hash: str
    labels: Dict[str, Any]
    head_verdicts: Dict[str, bool]   # L1/L2/L3 trifecta legs
    decision: str                    # ALLOW | REDACT | CONFIRM | QUARANTINE | BLOCK
    reason: str
    prev_hash: str
    this_hash: str = ""

    def finalize(self) -> "Receipt":
        payload = {k: v for k, v in asdict(self).items() if k != "this_hash"}
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.this_hash = hashlib.sha256(blob).hexdigest()
        return self


class EventBus:
    """Append-only event log + receipt chain, with live fan-out to subscribers."""

    def __init__(self, session_path: str | Path = "session.jsonl"):
        self.session_path = Path(session_path)
        self._lock = threading.Lock()
        self._subscribers: List[Callable[[Event], None]] = []
        self._prev_hash = GENESIS
        self.receipts: List[Receipt] = []

    # ---- pub/sub ------------------------------------------------------------

    def subscribe(self, fn: Callable[[Event], None]) -> None:
        self._subscribers.append(fn)

    def emit(self, kind: str, **data: Any) -> Event:
        evt = Event(kind=kind, data=data)
        with self._lock:
            with self.session_path.open("a") as f:
                f.write(json.dumps({"kind": evt.kind, "ts": evt.ts, "data": evt.data},
                                   default=str) + "\n")
        for fn in list(self._subscribers):
            try:
                fn(evt)
            except Exception:  # a dead dashboard must never break enforcement
                pass
        return evt

    # ---- receipts -----------------------------------------------------------

    def issue_receipt(self, *, tool: str, args_hash: str, labels: Dict[str, Any],
                      head_verdicts: Dict[str, bool], decision: str,
                      reason: str) -> Receipt:
        with self._lock:
            r = Receipt(
                ts=time.time(), tool=tool, args_hash=args_hash, labels=labels,
                head_verdicts=head_verdicts, decision=decision, reason=reason,
                prev_hash=self._prev_hash,
            ).finalize()
            self._prev_hash = r.this_hash
            self.receipts.append(r)
        self.emit("verdict", **asdict(r))
        return r

    def verify_chain(self) -> bool:
        """Re-hash every receipt and confirm the chain is intact (demo: tamper check)."""
        prev = GENESIS
        for r in self.receipts:
            recomputed = Receipt(**{**asdict(r), "this_hash": ""}).finalize().this_hash
            if r.prev_hash != prev or r.this_hash != recomputed:
                return False
            prev = r.this_hash
        return True


def args_digest(args: Any) -> str:
    blob = json.dumps(args, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]
