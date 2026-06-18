"""WS-E: the SIEM/audit layer turns a session log into OWASP-mapped detections
and a signed incident report."""
from __future__ import annotations

from host.agent import build_gateway, drive_attack
from servers import exfil_server
from siem import analyze, build_report, load_events


def _run(session_path):
    exfil_server.received.clear()
    gw, _ = build_gateway(enabled=True, session_path=str(session_path))
    drive_attack(gw)                       # registration emits the POISONED_DESC sentinel event
    return load_events(session_path)


def test_detects_trifecta_and_poisoning(session_path):
    dets = analyze(_run(session_path))
    ids = {d.rule_id for d in dets}
    owasps = " ".join(d.owasp for d in dets)
    assert "cerb-0001" in ids                 # lethal trifecta formation
    assert "cerb-0003" in ids                 # poisoned tool description
    assert "ASI02" in owasps and "ASI06" in owasps


def test_honeytoken_and_leak_meter_fire(session_path):
    ids = {d.rule_id for d in analyze(_run(session_path))}
    assert "cerb-0002" in ids                 # honeytoken canary in payload
    assert "cerb-0004" in ids                 # leak-meter bits detected


def test_signed_incident_report(session_path):
    events = _run(session_path)
    report = build_report(events, analyze(events), intact=True, n_receipts=3)
    assert "Cerberus — Security Incident Report" in report
    assert "Integrity attestation" in report
    assert "OWASP" in report
    assert "EU AI Act" in report
