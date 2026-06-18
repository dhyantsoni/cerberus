"""The trifecta detector: all three legs in one call -> complete, never 'two of three'."""
from __future__ import annotations

from cerberus.events import EventBus
from cerberus.labels import Capability, Provenance, Sensitivity, user_instruction
from cerberus.tracer import Tracer


def _tracer(tmp_path):
    return Tracer(bus=EventBus(tmp_path / "session.jsonl"))


def test_each_leg_alone_is_incomplete(tmp_path):
    tr = _tracer(tmp_path)
    secret = Capability(sensitivity=Sensitivity.SECRET, readers=frozenset())
    untrusted = Capability(provenance=Provenance.TOOL_UNTRUSTED)

    # L1 only (private data, non-egress, trusted)
    st = tr.evaluate(is_egress_sink=False, arg_caps=[secret], payload="x")
    assert st.L1_private_access and not st.complete

    tr = _tracer(tmp_path)
    # L2 only (untrusted, non-egress)
    st = tr.evaluate(is_egress_sink=False, arg_caps=[untrusted], payload="x")
    assert st.L2_untrusted_influence and not st.complete

    tr = _tracer(tmp_path)
    # L3 only (egress with clean public user data)
    st = tr.evaluate(is_egress_sink=True, arg_caps=[user_instruction()], payload="x")
    assert st.L3_egress and not st.complete


def test_two_of_three_stays_incomplete(tmp_path):
    tr = _tracer(tmp_path)
    secret = Capability(sensitivity=Sensitivity.SECRET, readers=frozenset())
    untrusted = Capability(provenance=Provenance.TOOL_UNTRUSTED)
    # L1 + L2 but no egress
    st = tr.evaluate(is_egress_sink=False, arg_caps=[secret, untrusted], payload="x")
    assert st.L1_private_access and st.L2_untrusted_influence
    assert not st.L3_egress and not st.complete


def test_full_assembly_completes_and_emits(tmp_path):
    bus = EventBus(tmp_path / "session.jsonl")
    seen = []
    bus.subscribe(lambda e: seen.append(e.kind))
    tr = Tracer(bus=bus)
    secret = Capability(sensitivity=Sensitivity.SECRET, readers=frozenset())
    untrusted = Capability(provenance=Provenance.TOOL_UNTRUSTED)
    st = tr.evaluate(is_egress_sink=True, arg_caps=[secret, untrusted], payload="creds")
    assert st.complete
    assert "trifecta" in seen


def test_session_memory_arms_legs_across_calls(tmp_path):
    """Touching a secret earlier still arms L1 on a later clean egress call."""
    tr = _tracer(tmp_path)
    tr.observe_tool_result(True, Sensitivity.SECRET, "AKIA...")          # arms L1 memory
    tr.observe_tool_result(False, Sensitivity.PUBLIC, "injected text")   # arms L2 memory
    st = tr.evaluate(is_egress_sink=True, arg_caps=[user_instruction()], payload="x")
    assert st.L1_private_access and st.L2_untrusted_influence and st.L3_egress
    assert st.complete
