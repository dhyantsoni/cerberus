"""Parse session.jsonl into normalized, detection-ready security records.

Field names here are the Sigma ``logsource`` schema (product: cerberus, service:
gateway) that the rules in siem/rules/ match against.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

_BITS_RE = re.compile(r"([\d.]+)\s*bits")


def load_events(path: str | Path) -> List[dict]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def normalize(evt: dict) -> Dict[str, Any]:
    """Flatten one event into a record the Sigma matcher can evaluate."""
    kind = evt.get("kind")
    data = evt.get("data", {}) or {}
    rec: Dict[str, Any] = {"kind": kind, "ts": evt.get("ts", 0)}

    if kind == "verdict":
        hv = data.get("head_verdicts", {}) or {}
        rec.update(decision=data.get("decision"), tool=data.get("tool"),
                   reason=data.get("reason", ""), this_hash=data.get("this_hash"),
                   L1=bool(hv.get("L1_private_access")),
                   L2=bool(hv.get("L2_untrusted_influence")),
                   L3=bool(hv.get("L3_egress")))
    elif kind == "trifecta":
        ev = data.get("evidence", {}) or {}
        m = _BITS_RE.search(str(ev.get("leak_meter", "")))
        rec.update(L1=bool(data.get("L1_private_access")),
                   L2=bool(data.get("L2_untrusted_influence")),
                   L3=bool(data.get("L3_egress")),
                   honeytoken="honeytoken" in ev,
                   leak_bits=float(m.group(1)) if m else 0.0)
    elif kind == "sentinel":
        rec.update(severity=data.get("severity"), code=data.get("code"),
                   server=data.get("server"), detail=data.get("detail", ""))
    elif kind == "tool_call":
        rec.update(server=data.get("server"), tool=data.get("tool"))
    elif kind == "value":
        rec.update(value_kind=data.get("value_kind"), sensitivity=data.get("sensitivity"))
    return rec
