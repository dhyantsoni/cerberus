"""Run the Sigma rules over a parsed session and emit OWASP-mapped detections."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .mappings import owasp_for
from .parser import normalize
from .sigma_eval import evaluate

RULES_DIR = Path(__file__).parent / "rules"


@dataclass
class Detection:
    rule_id: str
    title: str
    level: str
    owasp: str
    count: int
    evidence: List[str] = field(default_factory=list)   # receipt hashes, when present
    description: str = ""


def load_rules(rules_dir: Path = RULES_DIR) -> List[Dict[str, Any]]:
    rules = []
    for p in sorted(rules_dir.glob("*.yml")):
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        if doc and "detection" in doc:
            rules.append(doc)
    return rules


def analyze(events: List[dict], rules_dir: Path = RULES_DIR) -> List[Detection]:
    """Evaluate every rule against the session; return fired detections (highest first)."""
    records = [normalize(e) for e in events]
    detections: List[Detection] = []
    for rule in load_rules(rules_dir):
        hits = evaluate(rule["detection"], records)
        if not hits:
            continue
        detections.append(Detection(
            rule_id=rule.get("id", rule.get("title", "?")),
            title=rule.get("title", "untitled"),
            level=rule.get("level", "medium"),
            owasp=owasp_for(rule),
            count=len(hits),
            evidence=[h["this_hash"] for h in hits if h.get("this_hash")],
            description=rule.get("description", ""),
        ))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    detections.sort(key=lambda d: order.get(d.level, 5))
    return detections
