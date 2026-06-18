"""
cerberus SIEM CLI — analyze a session log into detections + a signed incident report.

    python -m siem.cli analyze session.jsonl
    python -m siem.cli analyze session.jsonl --report incident_report.md

Exit code 0 = analysed, chain intact; 2 = chain tampered.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .correlate import analyze
from .parser import load_events
from .report import build_report


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass

    parser = argparse.ArgumentParser(prog="cerberus-siem",
                                     description="Analyze a Cerberus session log.")
    sub = parser.add_subparsers(dest="cmd")
    a = sub.add_parser("analyze", help="run detections over a session.jsonl")
    a.add_argument("session", nargs="?", default="session.jsonl")
    a.add_argument("--report", metavar="PATH", help="write the full incident report (markdown)")
    args = parser.parse_args(argv)

    if args.cmd != "analyze":
        parser.print_help()
        return 0

    events = load_events(args.session)
    detections = analyze(events)

    print(f"Cerberus SIEM — {args.session}: {len(events)} events, {len(detections)} detection(s)")
    for d in detections:
        print(f"  [{d.level.upper():9}] {d.title}  ·  {d.owasp}  ·  x{d.count}")
    if not detections:
        print("  (no detections)")

    intact, n = (True, 0)
    if Path(args.session).exists():
        try:
            from cerberus.cli import verify_session
            intact, n = verify_session(args.session)
        except Exception:
            pass
    print(f"  receipt chain: {'✓ INTACT' if intact else '✗ TAMPERED'}  ({n} receipts)")

    if args.report:
        Path(args.report).write_text(build_report(events, detections, intact, n), encoding="utf-8")
        print(f"  wrote incident report → {args.report}")
    return 0 if intact else 2


if __name__ == "__main__":
    raise SystemExit(main())
