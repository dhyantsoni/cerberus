"""
Cerberus SIEM / audit-observability layer.

Turns the signed ``session.jsonl`` receipt log into security detections and a
forensic incident report. Detections are authored as real Sigma-format YAML
(``siem/rules/``) so they are standard + portable, and evaluated in-process by a
tiny matcher (no SIEM backend needed). Findings map to the OWASP Top-10 for
Agentic Applications, and a signed incident report (NIST SP 800-61 / PICERL
shaped) frames the chain as the EU AI Act Art. 12 audit artifact.

Authored with the cybersecurity skills 12-log-analysis (Sigma rules + correlation)
and 07-incident-response (PICERL report structure).
"""

from .correlate import Detection, analyze
from .parser import load_events, normalize
from .report import build_report

__all__ = ["analyze", "Detection", "load_events", "normalize", "build_report"]
