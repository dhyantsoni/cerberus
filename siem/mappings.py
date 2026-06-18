"""Map Sigma rule tags to the OWASP Top-10 for Agentic Applications (2025)."""
from __future__ import annotations

from typing import Dict

OWASP_AGENTIC: Dict[str, str] = {
    "asi01": "ASI01: Agent Authorization & Control Hijacking",
    "asi02": "ASI02: Tool Misuse",
    "asi03": "ASI03: Privilege Compromise",
    "asi04": "ASI04: Resource Overload",
    "asi05": "ASI05: Cascading Hallucination",
    "asi06": "ASI06: Memory & Tool-Definition Poisoning",
    "asi07": "ASI07: Misalignment & Deception",
    "asi08": "ASI08: Repudiation & Untraceability",
    "asi09": "ASI09: Identity Spoofing",
    "asi10": "ASI10: Overwhelming Human Oversight",
}


def owasp_for(rule: dict) -> str:
    for tag in rule.get("tags", []) or []:
        if str(tag).startswith("owasp."):
            key = str(tag).split(".", 1)[1].lower()
            return OWASP_AGENTIC.get(key, key.upper())
    return "—"
