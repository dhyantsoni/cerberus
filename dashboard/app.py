"""
Dashboard server — the glamour layer. Relays the gateway event stream to the
browser via SSE and lets a judge DRIVE the demo live (toggle Cerberus, run the
scenario, approve/deny a CONFIRM, tamper the log, replay).

    pip install -e ".[dashboard]"
    uvicorn dashboard.app:app --port 8000     # open http://127.0.0.1:8000

The block lands far harder when the judge SEES the trifecta legs snap into place and
the sink edge lock red. The capability core is untouched (frozen): the backend only
drives ``host.agent.build_gateway``/``drive_attack`` and exposes a few control
endpoints; the trifecta legs are derived in the browser from the existing events.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from pathlib import Path

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
except Exception:  # keep the repo importable without the optional dep installed
    FastAPI = None  # type: ignore

SESSION = Path("session.jsonl")
HERE = Path(__file__).parent
INDEX = HERE / "index.html"
STATIC = HERE / "static"

# Pending CONFIRM gates keyed by run_id (the web-backed confirm_fn waits on these).
_confirm_gates: dict[str, dict] = {}


def _reset_session() -> None:
    SESSION.write_text("", encoding="utf-8")
    from servers import exfil_server
    exfil_server.received.clear()


def _run_scenario(enabled: bool, mode: str | None, run_id: str) -> None:
    """Drive the scripted attack against a freshly built gateway, in a worker thread
    so SSE keeps streaming. CONFIRM mode blocks here until /api/confirm answers."""
    from host.agent import build_gateway, drive_attack
    from servers import exfil_server

    confirm_fn = None
    if mode == "CONFIRM":
        gate = {"event": threading.Event(), "approve": False}
        _confirm_gates[run_id] = gate

        def confirm_fn(prompt: str) -> bool:
            # surface the request to the browser via the event stream, then wait
            with SESSION.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"kind": "confirm_request", "ts": time.time(),
                                    "data": {"prompt": prompt, "run_id": run_id}}) + "\n")
            gate["event"].wait(timeout=120)
            return bool(gate.get("approve", False))

    gw, findings = build_gateway(enabled, confirm_fn=confirm_fn, session_path=str(SESSION))
    if mode:
        gw.warden.policy["trifecta_mode"] = mode    # in-memory override (no YAML edit)
    exfil_server.received.clear()
    for fnd in findings:
        gw.bus.emit("sentinel", severity=fnd.severity, code=fnd.code,
                    server=fnd.server, detail=fnd.detail)
    try:
        drive_attack(gw)
    finally:
        # Deterministic final-state event: fires after the run completes (and after
        # the start-of-run reset), so the UI shows the OFF leak / ON empty correctly
        # even when there is no verdict event (OFF mode emits none).
        gw.bus.emit("sink_state", received=list(exfil_server.received))
        _confirm_gates.pop(run_id, None)


if FastAPI is not None:
    app = FastAPI(title="Cerberus Dashboard")
    if STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    @app.get("/")
    def index() -> "HTMLResponse":
        # explicit UTF-8: the file has em-dashes etc.; Windows would otherwise
        # decode it as cp1252 and corrupt them.
        return HTMLResponse(INDEX.read_text(encoding="utf-8"))

    @app.get("/events")
    async def events() -> "StreamingResponse":
        async def gen():
            pos = 0
            while True:
                if SESSION.exists():
                    text = SESSION.read_text(encoding="utf-8")
                    if len(text) < pos:                 # file was reset/truncated
                        pos = 0
                        yield "event: reset\ndata: {}\n\n"
                    if len(text) > pos:
                        for line in text[pos:].splitlines():
                            if line.strip():
                                yield f"data: {line}\n\n"
                        pos = len(text)
                await asyncio.sleep(0.2)
        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/api/run")
    async def api_run(req: Request) -> "JSONResponse":
        body = await req.json()
        enabled = bool(body.get("enabled", True))
        mode = body.get("mode") or None                 # "BLOCK" | "CONFIRM" | None
        run_id = uuid.uuid4().hex[:8]
        _reset_session()
        threading.Thread(target=_run_scenario, args=(enabled, mode, run_id),
                         daemon=True).start()
        return JSONResponse({"run_id": run_id, "enabled": enabled, "mode": mode})

    @app.post("/api/confirm")
    async def api_confirm(req: Request) -> "JSONResponse":
        body = await req.json()
        gate = _confirm_gates.get(body.get("run_id"))
        if gate:
            gate["approve"] = bool(body.get("approve"))
            gate["event"].set()
        return JSONResponse({"ok": True})

    @app.post("/api/reset")
    async def api_reset() -> "JSONResponse":
        _reset_session()
        return JSONResponse({"ok": True})

    @app.get("/api/sink")
    def api_sink() -> "JSONResponse":
        from servers import exfil_server
        return JSONResponse({"received": list(exfil_server.received)})

    @app.get("/api/verify")
    def api_verify() -> "JSONResponse":
        from cerberus.cli import verify_session
        intact, n = verify_session(SESSION) if SESSION.exists() else (True, 0)
        return JSONResponse({"intact": intact, "receipts": n})

    @app.post("/api/tamper")
    def api_tamper() -> "JSONResponse":
        """Demo move: flip one BLOCK->ALLOW in the log so verify_chain shows tampered."""
        if not SESSION.exists():
            return JSONResponse({"ok": False, "reason": "no session"})
        out, flipped = [], False
        for line in SESSION.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            evt = json.loads(line)
            if (not flipped and evt.get("kind") == "verdict"
                    and evt["data"].get("decision") == "BLOCK"):
                evt["data"]["decision"] = "ALLOW"
                flipped = True
            out.append(json.dumps(evt))
        SESSION.write_text("\n".join(out) + "\n", encoding="utf-8")
        return JSONResponse({"ok": True, "flipped": flipped})

    @app.get("/api/session")
    def api_session() -> "JSONResponse":
        if not SESSION.exists():
            return JSONResponse({"events": []})
        evts = [json.loads(line) for line in SESSION.read_text(encoding="utf-8").splitlines()
                if line.strip()]
        return JSONResponse({"events": evts})


def replay(path: str = "session.jsonl"):
    """CLI replay: print each event with its relative timestamp (forensic view)."""
    events = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()
              if line.strip()]
    t0 = events[0]["ts"] if events else 0
    for e in events:
        print(f"+{e['ts'] - t0:6.2f}s  {e['kind']:10s}  {json.dumps(e['data'])[:100]}")


if __name__ == "__main__":
    replay()
