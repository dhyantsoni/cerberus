"""WS-F: the dashboard backend that drives the live demo. Exercised through
FastAPI's TestClient; skipped automatically if the dashboard extras aren't installed."""
from __future__ import annotations

import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from dashboard.app import app  # noqa: E402


def _wait_verdict(c, count=3, timeout=8.0):
    """Wait until the async run has issued all ``count`` receipts, then return the
    last (the egress decision). Returning on the first verdict races the worker
    thread and yields an early ALLOW before the terminal BLOCK is written."""
    end = time.time() + timeout
    while time.time() < end:
        evts = c.get("/api/session").json()["events"]
        verdicts = [e for e in evts if e["kind"] == "verdict"]
        if len(verdicts) >= count:
            return verdicts[-1]
        time.sleep(0.05)
    return None


def test_dashboard_serves_ui_and_assets():
    c = TestClient(app)
    home = c.get("/")
    assert home.status_code == 200 and "CERB" in home.text
    assert c.get("/static/app.js").status_code == 200
    assert c.get("/static/styles.css").status_code == 200


def test_run_blocks_exfil_and_chain_verifies():
    c = TestClient(app)
    c.post("/api/reset")
    assert c.post("/api/run", json={"enabled": True, "mode": "BLOCK"}).json()["run_id"]
    v = _wait_verdict(c)
    assert v is not None and v["data"]["decision"] == "BLOCK"
    assert c.get("/api/sink").json()["received"] == []     # nothing exfiltrated
    assert c.get("/api/verify").json()["intact"] is True


def test_tamper_endpoint_breaks_the_chain():
    c = TestClient(app)
    c.post("/api/reset")
    c.post("/api/run", json={"enabled": True, "mode": "BLOCK"})
    assert _wait_verdict(c) is not None
    c.post("/api/tamper")
    assert c.get("/api/verify").json()["intact"] is False
