"""A tiny Sigma-format matcher — just enough to evaluate the rules in siem/rules/
in-process. Rules stay standard Sigma YAML (portable to any real backend); we only
implement the subset the agent-abuse detections need: field/list equality, a few
modifiers (contains/gte/lte/gt/in/exists), and condition over named selections
(``sel``, ``sel1 and sel2``, ``sel1 or sel2``) plus a ``| count() >= N`` aggregator.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_COUNT_RE = re.compile(r"count\(\)\s*>=\s*(\d+)")


def _match_field(rec: Dict[str, Any], key: str, expected: Any) -> bool:
    field, _, mod = key.partition("|")
    val = rec.get(field)
    if not mod:
        return val in expected if isinstance(expected, list) else val == expected
    if mod in ("gte", "lte", "gt", "lt"):
        if val is None:
            return False
        v, e = float(val), float(expected)
        return {"gte": v >= e, "lte": v <= e, "gt": v > e, "lt": v < e}[mod]
    if mod == "contains":
        return val is not None and str(expected) in str(val)
    if mod == "in":
        opts = expected if isinstance(expected, list) else [expected]
        return val in opts
    if mod == "exists":
        return (val is not None) == bool(expected)
    return False


def match_selection(selection: Dict[str, Any], rec: Dict[str, Any]) -> bool:
    return all(_match_field(rec, k, v) for k, v in selection.items())


def matches(detection: Dict[str, Any], rec: Dict[str, Any]) -> bool:
    """True if ``rec`` satisfies the rule's per-event selection + condition."""
    selections = {k: v for k, v in detection.items() if k != "condition"}
    cond = str(detection.get("condition", "selection")).split("|")[0].strip()
    results = {name: match_selection(sel, rec) for name, sel in selections.items()}
    if " and " in cond:
        return all(results.get(n.strip(), False) for n in cond.split(" and "))
    if " or " in cond:
        return any(results.get(n.strip(), False) for n in cond.split(" or "))
    return results.get(cond, False)


def count_threshold(detection: Dict[str, Any]) -> Optional[int]:
    """Return N if the condition is an aggregation ``... | count() >= N``, else None."""
    m = _COUNT_RE.search(str(detection.get("condition", "")))
    return int(m.group(1)) if m else None


def evaluate(detection: Dict[str, Any], records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Records matching the rule. For aggregation rules, returns the matched set only
    if it meets the count threshold (otherwise empty)."""
    hits = [r for r in records if matches(detection, r)]
    thresh = count_threshold(detection)
    if thresh is not None and len(hits) < thresh:
        return []
    return hits
