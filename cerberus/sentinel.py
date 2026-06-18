"""
Sentinel — registration-time defenses against malicious servers.

Catches the attacks that happen *before* any data flows:
  * manifest pinning + rug-pull drift  (a server mutates its tool defs after approval)
  * poisoned-description scan           (hidden instructions in a tool description)
  * typosquat                           (a server name impersonating a trusted one)
  * cross-server shadowing              (a server's description references another tool)

Refs: Invariant Labs "Tool Poisoning Attacks" (April 2025) -> OWASP MCP03:2025;
Trail of Bits "line jumping"; CVE-2025-54136 "MCPoison" (Cursor manifest swap).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    from rapidfuzz import fuzz
except Exception:  # rapidfuzz is optional; fall back to a stdlib ratio
    from difflib import SequenceMatcher

    class fuzz:  # type: ignore
        @staticmethod
        def ratio(a: str, b: str) -> float:
            return SequenceMatcher(None, a, b).ratio() * 100


# Patterns that have no business appearing in a *tool description*.
_INJECTION_PATTERNS = [
    r"<\s*important\s*>", r"<\s*system\s*>", r"ignore (the |all )?previous",
    r"\.aws/credentials", r"\.ssh/id_rsa", r"do not (tell|mention|inform)",
    r"before (answering|responding).{0,40}(read|fetch|include)",
    r"POST .{0,40}https?://", r"exfiltrat",
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE | re.DOTALL)


@dataclass
class ServerManifest:
    name: str
    tools: Dict[str, str]              # tool_name -> description
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            blob = "\n".join(f"{k}:{v}" for k, v in sorted(self.tools.items()))
            self.fingerprint = hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class Finding:
    severity: str                     # INFO | WARN | BLOCK
    code: str                         # POISONED_DESC | RUG_PULL | TYPOSQUAT | SHADOWING
    server: str
    detail: str


class Sentinel:
    def __init__(self, trusted_names: Optional[List[str]] = None, bus=None):
        self.bus = bus
        self.trusted_names = trusted_names or ["filesystem", "weather"]
        self._pinned: Dict[str, str] = {}          # server -> pinned fingerprint
        self._all_tool_names: List[str] = []

    def register(self, manifest: ServerManifest) -> List[Finding]:
        findings: List[Finding] = []

        # 1) poisoned description scan
        for tool, desc in manifest.tools.items():
            m = _INJECTION_RE.search(desc or "")
            if m:
                findings.append(Finding("BLOCK", "POISONED_DESC", manifest.name,
                                        f"tool '{tool}' description matches injection "
                                        f"pattern: {m.group(0)!r}"))

        # 2) typosquat against trusted names
        for trusted in self.trusted_names:
            if manifest.name != trusted and fuzz.ratio(manifest.name, trusted) >= 80:
                findings.append(Finding("WARN", "TYPOSQUAT", manifest.name,
                                        f"name resembles trusted server '{trusted}'"))

        # 3) cross-server shadowing (description references another server's tool)
        for tool, desc in manifest.tools.items():
            for other in self._all_tool_names:
                if other not in manifest.tools and re.search(rf"\b{re.escape(other)}\b", desc or ""):
                    findings.append(Finding("WARN", "SHADOWING", manifest.name,
                                            f"tool '{tool}' references foreign tool '{other}'"))

        # 4) pin the manifest for later drift detection
        self._pinned[manifest.name] = manifest.fingerprint
        self._all_tool_names.extend(manifest.tools.keys())

        for f in findings:
            if self.bus:
                self.bus.emit("sentinel", **f.__dict__)
        return findings

    def check_drift(self, manifest: ServerManifest) -> Optional[Finding]:
        """Re-registration check: did the manifest change after we pinned it? (rug pull)"""
        pinned = self._pinned.get(manifest.name)
        if pinned and pinned != manifest.fingerprint:
            f = Finding("BLOCK", "RUG_PULL", manifest.name,
                        "manifest fingerprint changed since approval (rug pull)")
            if self.bus:
                self.bus.emit("sentinel", **f.__dict__)
            return f
        return None
