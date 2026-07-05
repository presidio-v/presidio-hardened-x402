"""Tests for capability certificates (``presidio-hardened/capability-grant@1``).

Covers: golden issue -> verify roundtrip, a 3-hop delegation happy path, every
attenuation-violation class (budget raised, window widened, window_seconds
widened, prefix broadened, sibling-prefix injection), tampered signature, expired
grant, wrong trust-store key, exercise-time checks against the chain (amount over
a hop's cap; URL outside the intersection), float-amount rejection, determinism of
the canonical signing bytes, and the ``PolicyConfig`` bridge.

Ed25519 keys are generated per-test via ``cryptography`` (the ``[evidence]``
extra), mirroring the pattern in ``test_mica.py`` / ``test_evidence_conformance``.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402.capability import (
    CAPABILITY_SCHEMA_ID,
    CapabilityError,
    _signing_preimage,
    delegate_grant,
    issue_grant,
    policy_config_from_chain,
    verify_chain,
)

# ---------------------------------------------------------------------------
# Key + trust-store helpers
# ---------------------------------------------------------------------------


def _keypair() -> tuple[str, str]:
    """Return (private_hex, public_hex) for a fresh Ed25519 keypair."""
    sk = ed25519.Ed25519PrivateKey.generate()
    return (
        sk.private_bytes_raw().hex(),
        sk.public_key().public_bytes_raw().hex(),
    )


def _trust_store(operator_id: str, operator_pub: str) -> dict:
    return {operator_id: {"alg": "ed25519", "public_key": operator_pub}}


@pytest.fixture
def operator() -> tuple[str, str, str]:
    priv, pub = _keypair()
    return ("acme-operator", priv, pub)


# ---------------------------------------------------------------------------
# 1. Golden roundtrip: issue -> verify
# ---------------------------------------------------------------------------


def test_issue_verify_roundtrip(operator):
    op_id, op_priv, op_pub = operator
    agent_priv, agent_pub = _keypair()
    grant = issue_grant(
        subject="agent-root",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=agent_pub,
        caveats={
            "max_per_call_usd": "0.05",
            "daily_limit_usd": "2.00",
            "endpoint_prefixes": ["https://api.foo.com/inference"],
        },
    )
    assert grant["schema"] == CAPABILITY_SCHEMA_ID
    assert grant["parent_hash"] is None
    assert len(bytes.fromhex(grant["signature"])) == 64

    vc = verify_chain([grant], _trust_store(op_id, op_pub))
    assert vc.subject == "agent-root"
    assert str(vc.effective.max_per_call_usd) == "0.05"
    assert vc.effective.endpoint_prefixes == ("https://api.foo.com/inference",)


def test_issue_with_integer_micro_usd(operator):
    op_id, op_priv, op_pub = operator
    # 50_000 micro-USD == 0.05 USD
    grant = issue_grant(
        subject="agent",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"max_per_call_usd": 50_000},
    )
    vc = verify_chain([grant], _trust_store(op_id, op_pub))
    from decimal import Decimal

    assert vc.effective.max_per_call_usd == Decimal("0.05")


# ---------------------------------------------------------------------------
# 2. Three-hop delegation happy path
# ---------------------------------------------------------------------------


def _three_hop(op_id, op_priv):
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    c_priv, c_pub = _keypair()
    root = issue_grant(
        subject="agent-A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={
            "max_per_call_usd": "1.00",
            "daily_limit_usd": "10.00",
            "window_seconds": 86_400,
            "endpoint_prefixes": ["https://api.foo.com/"],
        },
    )
    child = delegate_grant(
        root,
        parent_private_key=a_priv,
        subject="agent-B",
        subject_public_key=b_pub,
        caveats={
            "max_per_call_usd": "0.50",
            "daily_limit_usd": "5.00",
            "window_seconds": 86_400,
            "endpoint_prefixes": ["https://api.foo.com/inference"],
        },
    )
    grand = delegate_grant(
        child,
        parent_private_key=b_priv,
        subject="agent-C",
        subject_public_key=c_pub,
        caveats={
            # Must carry through every axis the parent constrains (dropping one
            # would be a broadening — see test_reject_unbounded_child_when_parent_caps).
            "max_per_call_usd": "0.10",
            "daily_limit_usd": "5.00",
            "window_seconds": 86_400,
            "endpoint_prefixes": ["https://api.foo.com/inference/v2"],
        },
    )
    return [root, child, grand]


def test_three_hop_delegation_happy_path(operator):
    op_id, op_priv, op_pub = operator
    chain = _three_hop(op_id, op_priv)
    vc = verify_chain(chain, _trust_store(op_id, op_pub))
    assert vc.subject == "agent-C"
    # Effective = intersection: tightest cap 0.10, tightest daily 5.00 (from B),
    # tightest rolling budget window 86400, deepest prefix set.
    assert str(vc.effective.max_per_call_usd) == "0.10"
    assert str(vc.effective.daily_limit_usd) == "5.00"
    assert vc.effective.window_seconds == 86_400
    assert vc.effective.endpoint_prefixes == ("https://api.foo.com/inference/v2",)
    vc.check_payment(resource_url="https://api.foo.com/inference/v2/chat", amount_usd="0.05")


# ---------------------------------------------------------------------------
# 3. Attenuation-violation classes — every one must FAIL closed
# ---------------------------------------------------------------------------


def test_reject_budget_raised(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"max_per_call_usd": "0.10"},
    )
    with pytest.raises(CapabilityError, match="exceeds parent"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={"max_per_call_usd": "0.50"},  # raised — must fail
        )


def test_reject_unbounded_child_when_parent_caps(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"max_per_call_usd": "0.10"},
    )
    with pytest.raises(CapabilityError, match="unbounded"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={"daily_limit_usd": "1.00"},  # drops the per-call cap
        )


def test_reject_validity_window_widened(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-02-01T00:00:00Z",
        },
    )
    with pytest.raises(CapabilityError, match="valid_until"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-03-01T00:00:00Z",  # widened later
            },
        )
    assert now  # window fixture sanity


def test_reject_window_seconds_shortened(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"window_seconds": 86_400},
    )
    with pytest.raises(CapabilityError, match="window_seconds"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={"window_seconds": 3_600},  # shorter window evicts spend sooner
        )


def test_reject_prefix_broadened_shortening(operator):
    """Canonical broadening: parent .../inference, child .../ must FAIL."""
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"endpoint_prefixes": ["https://api.foo.com/inference"]},
    )
    with pytest.raises(CapabilityError, match="does not extend"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={"endpoint_prefixes": ["https://api.foo.com/"]},
        )


def test_reject_sibling_prefix_injection(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"endpoint_prefixes": ["https://api.foo.com/inference"]},
    )
    with pytest.raises(CapabilityError, match="does not extend"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={
                "endpoint_prefixes": [
                    "https://api.foo.com/inference/ok",  # legit
                    "https://api.foo.com/admin",  # injected sibling — must fail whole set
                ]
            },
        )


def test_reject_prefix_segment_confusion(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"endpoint_prefixes": ["https://api.foo.com/inference"]},
    )
    with pytest.raises(CapabilityError, match="does not extend"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={"endpoint_prefixes": ["https://api.foo.com/inference-evil"]},
        )


def test_reject_prefix_host_confusion(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"endpoint_prefixes": ["https://api.foo.com"]},
    )
    with pytest.raises(CapabilityError, match="does not extend"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={"endpoint_prefixes": ["https://api.foo.com.evil/inference"]},
        )


def test_reject_prefix_dropped_when_parent_restricts(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"endpoint_prefixes": ["https://api.foo.com/inference"]},
    )
    with pytest.raises(CapabilityError, match="drops them"):
        delegate_grant(
            root,
            parent_private_key=a_priv,
            subject="B",
            caveats={"max_per_call_usd": "0.01"},  # no prefixes -> unrestricted
        )


# ---------------------------------------------------------------------------
# 4. Tampered signature / broken chain / expired / wrong key
# ---------------------------------------------------------------------------


def test_tampered_signature_rejected(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"max_per_call_usd": "0.10"},
    )
    tampered = copy.deepcopy(grant)
    # Flip one hex nibble of the signature.
    sig = tampered["signature"]
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    tampered["signature"] = flipped
    with pytest.raises(CapabilityError, match="does not verify"):
        verify_chain([tampered], _trust_store(op_id, op_pub))


def test_tampered_caveat_after_signing_rejected(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"max_per_call_usd": "0.10"},
    )
    tampered = copy.deepcopy(grant)
    tampered["caveats"]["max_per_call_usd"] = "9.99"  # raise cap post-signature
    with pytest.raises(CapabilityError, match="does not verify"):
        verify_chain([tampered], _trust_store(op_id, op_pub))


def test_child_hash_link_broken_rejected(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"max_per_call_usd": "1.00"},
    )
    child = delegate_grant(
        root,
        parent_private_key=a_priv,
        subject="B",
        caveats={"max_per_call_usd": "0.10"},
    )
    child_bad = copy.deepcopy(child)
    child_bad["parent_hash"] = "aa" * 32  # points at nothing
    with pytest.raises(CapabilityError, match="does not verify|parent_hash"):
        verify_chain([root, child_bad], _trust_store(op_id, op_pub))


def test_expired_grant_rejected(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"valid_until": "2026-01-01T00:00:00Z"},
    )
    with pytest.raises(CapabilityError, match="expired"):
        verify_chain(
            [grant],
            _trust_store(op_id, op_pub),
            at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )


def test_not_yet_valid_rejected(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"valid_from": "2026-06-01T00:00:00Z"},
    )
    with pytest.raises(CapabilityError, match="not yet valid"):
        verify_chain(
            [grant],
            _trust_store(op_id, op_pub),
            at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_wrong_trust_store_key_rejected(operator):
    op_id, op_priv, _op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"max_per_call_usd": "0.10"},
    )
    _, other_pub = _keypair()  # a different operator's public key
    with pytest.raises(CapabilityError, match="does not verify"):
        verify_chain([grant], _trust_store(op_id, other_pub))


def test_unknown_issuer_rejected(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"max_per_call_usd": "0.10"},
    )
    with pytest.raises(CapabilityError, match="not in the trust store"):
        verify_chain([grant], _trust_store("someone-else", op_pub))


def test_leaf_cannot_delegate(operator):
    op_id, op_priv, _ = operator
    leaf = issue_grant(  # no subject_public_key
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"max_per_call_usd": "0.10"},
    )
    a_priv, _ = _keypair()
    with pytest.raises(CapabilityError, match="cannot be delegated"):
        delegate_grant(
            leaf, parent_private_key=a_priv, subject="B", caveats={"max_per_call_usd": "0.01"}
        )


def test_unknown_schema_rejected(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A", issuer=op_id, issuer_private_key=op_priv, caveats={"max_per_call_usd": "0.10"}
    )
    grant["schema"] = "presidio-hardened/capability-grant@99"
    with pytest.raises(CapabilityError, match="unsupported grant schema"):
        verify_chain([grant], _trust_store(op_id, op_pub))


def test_bad_hex_signature_rejected(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A", issuer=op_id, issuer_private_key=op_priv, caveats={"max_per_call_usd": "0.10"}
    )
    grant["signature"] = "zz" * 64
    with pytest.raises(CapabilityError, match="hex"):
        verify_chain([grant], _trust_store(op_id, op_pub))


# ---------------------------------------------------------------------------
# 5. Exercise-time checks against the chain
# ---------------------------------------------------------------------------


def test_exercise_amount_over_hop_cap_fails(operator):
    op_id, op_priv, op_pub = operator
    chain = _three_hop(op_id, op_priv)
    vc = verify_chain(chain, _trust_store(op_id, op_pub))
    # Deepest cap is 0.10; 0.50 would pass the root+child but not the grandchild.
    with pytest.raises(CapabilityError, match="max_per_call_usd"):
        vc.check_payment(resource_url="https://api.foo.com/inference/v2/x", amount_usd="0.50")


def test_exercise_url_outside_intersection_fails(operator):
    op_id, op_priv, op_pub = operator
    chain = _three_hop(op_id, op_priv)
    vc = verify_chain(chain, _trust_store(op_id, op_pub))
    # /inference (child scope) is inside root but OUTSIDE grandchild's /inference/v2.
    with pytest.raises(CapabilityError, match="outside the granted endpoint prefixes"):
        vc.check_payment(resource_url="https://api.foo.com/inference/other", amount_usd="0.05")


def test_exercise_url_segment_confusion_fails(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"endpoint_prefixes": ["https://api.foo.com/inference"]},
    )
    vc = verify_chain([grant], _trust_store(op_id, op_pub))
    with pytest.raises(CapabilityError, match="outside the granted endpoint prefixes"):
        vc.check_payment(resource_url="https://api.foo.com/inference-evil", amount_usd="0.05")


def test_exercise_expired_at_fails(operator):
    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"valid_until": "2026-02-01T00:00:00Z"},
    )
    vc = verify_chain(
        [grant], _trust_store(op_id, op_pub), at=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    with pytest.raises(CapabilityError, match="expired"):
        vc.check_payment(
            resource_url="https://x",
            amount_usd="0.01",
            at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )


# ---------------------------------------------------------------------------
# 6. Float rejection + determinism
# ---------------------------------------------------------------------------


def test_float_amount_rejected(operator):
    op_id, op_priv, _ = operator
    with pytest.raises(CapabilityError, match="never a float"):
        issue_grant(
            subject="A",
            issuer=op_id,
            issuer_private_key=op_priv,
            caveats={"max_per_call_usd": 0.05},  # a float — must reject
        )


def test_signing_preimage_is_byte_stable():
    """Canonical signing bytes must not depend on input key order."""
    a = {
        "schema": CAPABILITY_SCHEMA_ID,
        "issuer": "op",
        "subject": "A",
        "caveats": {"daily_limit_usd": "2.00", "max_per_call_usd": "0.05"},
        "parent_hash": None,
        "issued_at": "2026-01-01T00:00:00Z",
        "grant_id": "x",
        "signature": "ignored",
    }
    b = {k: a[k] for k in reversed(list(a.keys()))}
    b["caveats"] = {"max_per_call_usd": "0.05", "daily_limit_usd": "2.00"}
    assert _signing_preimage(a) == _signing_preimage(b)
    # And the signature field is excluded from the preimage.
    assert b"ignored" not in _signing_preimage(a)


def test_issue_is_deterministic_given_issued_at(operator):
    op_id, op_priv, op_pub = operator
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    kwargs = {
        "subject": "A",
        "issuer": op_id,
        "issuer_private_key": op_priv,
        "caveats": {"max_per_call_usd": "0.10"},
        "issued_at": ts,
    }
    g1 = issue_grant(**kwargs)
    g2 = issue_grant(**kwargs)
    # Ed25519 is deterministic — identical inputs yield identical signatures.
    assert g1 == g2


# ---------------------------------------------------------------------------
# 7. PolicyConfig bridge
# ---------------------------------------------------------------------------


def test_policy_config_bridge_uses_intersection(operator):
    op_id, op_priv, op_pub = operator
    chain = _three_hop(op_id, op_priv)
    vc = verify_chain(chain, _trust_store(op_id, op_pub))
    pc = policy_config_from_chain(vc)
    # Bridge converts the exact Decimal caps to float at the runtime-config
    # boundary (grant wire form stays float-free; PolicyConfig fields are float).
    assert pc.max_per_call_usd == pytest.approx(0.10)
    assert pc.daily_limit_usd == pytest.approx(5.00)
    assert pc.window_seconds == 86_400
    assert pc.agent_id == "agent-C"
    # Endpoint scope becomes a per-endpoint cap at the effective per-call cap.
    assert pc.per_endpoint == {"https://api.foo.com/inference/v2": pytest.approx(0.10)}


def test_policy_config_bridge_feeds_policy_engine(operator):
    """The bridged config drives a real PolicyEngine with no floats."""
    from presidio_x402.policy_engine import PolicyEngine

    op_id, op_priv, op_pub = operator
    grant = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        caveats={"max_per_call_usd": "0.05", "daily_limit_usd": "0.10"},
    )
    vc = verify_chain([grant], _trust_store(op_id, op_pub))
    engine = PolicyEngine(policy_config_from_chain(vc))
    engine.check_and_record(resource_url="https://api.foo.com/x", amount_usd=0.04)
    from presidio_x402.exceptions import PolicyViolationError

    with pytest.raises(PolicyViolationError):
        engine.check_and_record(resource_url="https://api.foo.com/x", amount_usd=0.06)


def test_empty_chain_rejected(operator):
    op_id, _, op_pub = operator
    with pytest.raises(CapabilityError, match="non-empty"):
        verify_chain([], _trust_store(op_id, op_pub))


def test_second_grant_as_root_rejected(operator):
    op_id, op_priv, op_pub = operator
    a_priv, a_pub = _keypair()
    root = issue_grant(
        subject="A",
        issuer=op_id,
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={"max_per_call_usd": "1.00"},
    )
    # A second independent root (parent_hash None) is not a valid child.
    other_root = issue_grant(
        subject="B", issuer=op_id, issuer_private_key=op_priv, caveats={"max_per_call_usd": "0.10"}
    )
    with pytest.raises(CapabilityError, match="has no parent"):
        verify_chain([root, other_root], _trust_store(op_id, op_pub))
