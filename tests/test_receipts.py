"""The receipt chain is the audit deliverable — tamper must be detectable."""
from __future__ import annotations

import json
from dataclasses import replace

from cerberus.cli import verify_session
from cerberus.events import EventBus


def _issue(bus, decision):
    bus.issue_receipt(tool="post", args_hash="abc", labels={"provenance": 3},
                      head_verdicts={"L1": True, "L2": True, "L3": True},
                      decision=decision, reason="test")


def test_chain_is_intact_after_issuing(tmp_path):
    bus = EventBus(tmp_path / "session.jsonl")
    _issue(bus, "ALLOW")
    _issue(bus, "BLOCK")
    assert bus.verify_chain()
    assert len(bus.receipts) == 2
    # each receipt embeds the previous hash
    assert bus.receipts[1].prev_hash == bus.receipts[0].this_hash


def test_tampered_receipt_breaks_chain(tmp_path):
    bus = EventBus(tmp_path / "session.jsonl")
    _issue(bus, "BLOCK")
    _issue(bus, "ALLOW")
    assert bus.verify_chain()
    # flip a decision in place without re-finalizing the hash -> chain must fail
    bus.receipts[0] = replace(bus.receipts[0], decision="ALLOW")
    assert not bus.verify_chain()


def test_cli_verify_reads_session_log(tmp_path):
    path = tmp_path / "session.jsonl"
    bus = EventBus(path)
    _issue(bus, "ALLOW")
    _issue(bus, "BLOCK")
    intact, n = verify_session(path)
    assert intact and n == 2


def test_cli_verify_accepts_concatenated_sessions(tmp_path):
    """Two independent runs appended to one log are each a valid GENESIS-rooted
    chain; the auditor must not flag the segment boundary as tampering."""
    path = tmp_path / "session.jsonl"
    EventBus(path)  # ensure parent exists
    for _ in range(2):  # two separate sessions writing to the same file
        bus = EventBus(path)
        _issue(bus, "ALLOW")
        _issue(bus, "BLOCK")
    intact, n = verify_session(path)
    assert intact and n == 4


def test_cli_verify_detects_tampered_log(tmp_path):
    path = tmp_path / "session.jsonl"
    bus = EventBus(path)
    _issue(bus, "ALLOW")
    _issue(bus, "BLOCK")

    # rewrite the log with one decision flipped (the /api/tamper demo move)
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        evt = json.loads(line)
        if evt.get("kind") == "verdict" and evt["data"]["decision"] == "BLOCK":
            evt["data"]["decision"] = "ALLOW"
        out.append(json.dumps(evt))
    path.write_text("\n".join(out) + "\n", encoding="utf-8")

    intact, _ = verify_session(path)
    assert not intact
