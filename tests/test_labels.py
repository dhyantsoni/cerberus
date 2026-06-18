"""The lattice is the trust anchor — these properties must hold or the model is wrong."""
from __future__ import annotations

from cerberus.labels import (
    Capability, Provenance, Sensitivity, WILDCARD, join_all, user_instruction,
)


def test_join_taints_provenance_up():
    user = Capability(provenance=Provenance.USER)
    untrusted = Capability(provenance=Provenance.TOOL_UNTRUSTED)
    assert user.join(untrusted).provenance == Provenance.TOOL_UNTRUSTED
    # join is commutative on provenance
    assert untrusted.join(user).provenance == Provenance.TOOL_UNTRUSTED


def test_join_takes_max_sensitivity():
    public = Capability(sensitivity=Sensitivity.PUBLIC)
    secret = Capability(sensitivity=Sensitivity.SECRET)
    assert public.join(secret).sensitivity == Sensitivity.SECRET


def test_meet_narrows_readers():
    a = Capability(readers=frozenset({"x", "y"}))
    b = Capability(readers=frozenset({"y", "z"}))
    assert a.join(b).readers == frozenset({"y"})


def test_wildcard_is_top_for_readers():
    wild = Capability(readers=frozenset({WILDCARD}))
    narrow = Capability(readers=frozenset({"internal"}))
    # meeting with wildcard yields the other operand's ACL
    assert wild.join(narrow).readers == frozenset({"internal"})


def test_secret_cannot_flow_externally_by_default():
    secret = Capability(sensitivity=Sensitivity.SECRET, readers=frozenset())
    assert not secret.may_flow_to("https://exfil.evil/collect")
    assert secret.is_protected


def test_join_is_monotone_never_weakens():
    """Joining never lowers provenance or sensitivity, and never widens readers."""
    a = Capability(provenance=Provenance.TOOL_TRUSTED, sensitivity=Sensitivity.PRIVATE,
                   readers=frozenset({"a", "b"}))
    b = Capability(provenance=Provenance.TOOL_UNTRUSTED, sensitivity=Sensitivity.SECRET,
                   readers=frozenset({"b", "c"}))
    j = a.join(b)
    assert j.provenance >= max(a.provenance, b.provenance)
    assert j.sensitivity >= max(a.sensitivity, b.sensitivity)
    assert j.readers <= (a.readers | b.readers)


def test_declassify_is_the_only_weakening():
    secret = Capability(sensitivity=Sensitivity.SECRET, readers=frozenset())
    down = secret.declassify(sensitivity=Sensitivity.PUBLIC, add_readers=frozenset({"status_page"}))
    assert down.sensitivity == Sensitivity.PUBLIC
    assert down.may_flow_to("status_page")


def test_join_all_empty_is_user_public():
    cap = join_all([])
    assert cap.provenance == Provenance.USER
    assert cap.sensitivity == Sensitivity.PUBLIC


def test_join_all_carries_untrusted_and_secret():
    caps = [user_instruction(),
            Capability(provenance=Provenance.TOOL_UNTRUSTED),
            Capability(sensitivity=Sensitivity.SECRET, readers=frozenset())]
    merged = join_all(caps)
    assert merged.provenance == Provenance.TOOL_UNTRUSTED
    assert merged.sensitivity == Sensitivity.SECRET
