"""
cerberus-verify — re-hash a session's receipt chain and report tamper status.

    python -m cerberus.cli session.jsonl
    cerberus-verify session.jsonl        # via the installed entry point

Reads the ``verdict`` events from a session log, rebuilds each Receipt, and
recomputes the chain exactly as EventBus.verify_chain does. Exit code 0 = intact,
1 = broken (a byte was flipped). This is the standalone auditor a third party can
run against an exported log without trusting the process that produced it.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Tuple

from .events import GENESIS, Receipt


def load_receipts(path: str | Path) -> List[Receipt]:
    receipts: List[Receipt] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        evt = json.loads(line)
        if evt.get("kind") == "verdict":
            receipts.append(Receipt(**evt["data"]))
    return receipts


def verify_session(path: str | Path) -> Tuple[bool, int]:
    """Return ``(intact, n_receipts)`` for the receipt chain(s) in ``path``.

    A session log may concatenate several independent runs, each a fresh chain
    rooted at GENESIS. We verify every receipt's own hash and that links are
    contiguous *within* a segment; a receipt whose ``prev_hash`` is GENESIS
    legitimately starts a new segment (a new session), not a break.
    """
    receipts = load_receipts(path)
    prev = GENESIS
    for r in receipts:
        recomputed = Receipt(**{**asdict(r), "this_hash": ""}).finalize().this_hash
        if r.this_hash != recomputed:
            return False, len(receipts)            # this receipt was altered
        if r.prev_hash == GENESIS:
            prev = r.this_hash                      # start of a fresh session chain
            continue
        if r.prev_hash != prev:
            return False, len(receipts)             # a receipt was dropped/reordered
        prev = r.this_hash
    return True, len(receipts)


def main(argv: List[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass
    parser = argparse.ArgumentParser(prog="cerberus-verify",
                                     description="Verify a Cerberus receipt chain.")
    parser.add_argument("session", nargs="?", default="session.jsonl",
                        help="path to a session.jsonl log (default: ./session.jsonl)")
    args = parser.parse_args(argv)

    intact, n = verify_session(args.session)
    mark = "✓ INTACT" if intact else "✗ TAMPERED"
    print(f"{mark}  {args.session}  ({n} receipts)")
    return 0 if intact else 1


if __name__ == "__main__":
    raise SystemExit(main())
