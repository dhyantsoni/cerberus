"""
Dashboard server — relays the gateway event stream to the browser via SSE.

Serves ``index.html`` (Cytoscape.js DAG) and an ``/events`` SSE endpoint that
re-emits everything written to ``session.jsonl``. Two modes:
  * live    — tail session.jsonl as the gateway writes it
  * replay  — re-emit a saved session.jsonl along a timeline (the replay scrubber)

    pip install fastapi uvicorn
    uvicorn dashboard.app:app --reload --port 8000

This is the glamour layer. The block is far more convincing when the judge can SEE
the trifecta legs snap into place and the sink edge flash red. Protect time for it.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, StreamingResponse
except Exception:  # keep the repo importable without the optional dep installed
    FastAPI = None  # type: ignore

SESSION = Path("session.jsonl")
INDEX = Path(__file__).parent / "index.html"

if FastAPI is not None:
    app = FastAPI(title="Cerberus Dashboard")

    @app.get("/")
    def index() -> "HTMLResponse":
        # read as UTF-8 explicitly — the file has em-dashes etc., and Windows
        # would otherwise decode it as cp1252 and corrupt them.
        return HTMLResponse(INDEX.read_text(encoding="utf-8"))

    @app.get("/events")
    async def events() -> "StreamingResponse":
        async def gen():
            pos = 0
            while True:
                if SESSION.exists():
                    text = SESSION.read_text(encoding="utf-8")
                    if len(text) > pos:
                        for line in text[pos:].splitlines():
                            if line.strip():
                                yield f"data: {line}\n\n"
                        pos = len(text)
                await asyncio.sleep(0.25)
        return StreamingResponse(gen(), media_type="text/event-stream")


def replay(path: str = "session.jsonl"):
    """CLI replay: print each event with its relative timestamp (forensic view)."""
    events = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
              if line.strip()]
    t0 = events[0]["ts"] if events else 0
    for e in events:
        print(f"+{e['ts'] - t0:6.2f}s  {e['kind']:10s}  {json.dumps(e['data'])[:100]}")


if __name__ == "__main__":
    replay()
