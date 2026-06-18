"""Warden graded modes — focus on REDACT actually redacting (fail-closed otherwise)."""
from __future__ import annotations

from cerberus.gateway import DownstreamServer, Gateway, ToolResult
from cerberus.labels import Capability, Provenance, Sensitivity
from cerberus.sentinel import ServerManifest


def _redact_gateway(session_path):
    sink = []

    def call(tool, args):
        sink.append(str(args.get("body", "")))
        return ToolResult(value="posted")

    gw = Gateway(enabled=True, session_path=str(session_path), auto_label=False)
    gw.warden.policy["trifecta_mode"] = "REDACT"
    gw.register(DownstreamServer("egress", True,
                                 ServerManifest(name="egress", tools={"post": "post"}),
                                 call, is_egress=True))
    return gw, sink


def _caps():
    return [Capability(provenance=Provenance.TOOL_TRUSTED,
                       sensitivity=Sensitivity.SECRET, readers=frozenset()),
            Capability(provenance=Provenance.TOOL_UNTRUSTED)]


def test_redact_strips_the_secret_before_egress(session_path):
    gw, sink = _redact_gateway(session_path)
    creds = "AKIASECRET-XYZ wJalrLEAKKEY"
    canary = gw.tracer.seed_secret(creds, "k")
    res = gw.handle_call("egress", "post",
                         {"body": f"{creds} {canary}", "_sink": "https://evil",
                          "_caps": _caps()})
    assert res["mode"] == "REDACT"
    assert sink, "REDACT should let the (scrubbed) call proceed"
    assert "AKIASECRET" not in sink[0], "the secret must not reach the sink"
    assert canary not in sink[0], "the honeytoken must not reach the sink"
    assert "[REDACTED]" in sink[0]
    assert res["redacted"] >= 1


def test_redact_fails_closed_when_secret_is_unredactable(session_path):
    """A protected value heading to egress that the gateway can't scrub verbatim
    (e.g. it was never seeded) must fail-closed under REDACT, never leak."""
    gw, sink = _redact_gateway(session_path)
    # no seed_secret -> known_secrets empty -> nothing to scrub with
    res = gw.handle_call("egress", "post",
                         {"body": "some-unseeded-secret-blob", "_sink": "https://evil",
                          "_caps": _caps()})
    assert res.get("blocked") is True
    assert not sink


def test_redact_default_policy_still_blocks_via_trifecta(session_path):
    """Sanity: the default BLOCK policy is unaffected by the REDACT path."""
    gw, sink = _redact_gateway(session_path)
    gw.warden.policy["trifecta_mode"] = "BLOCK"
    res = gw.handle_call("egress", "post",
                         {"body": "AKIASECRET-XYZ", "_sink": "https://evil",
                          "_caps": _caps()})
    assert res.get("blocked") is True
    assert not sink
