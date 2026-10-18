"""ADR-0002 provenance-parents conformance for ``payment-decision@1`` (issue #141).

The family provenance-parents convention requires lineage to live in a
**top-level** ``parents`` array of the signed content (P1), each entry a
lowercase-hex content hash ``^[0-9a-f]{8,128}$`` (P2), omitted when empty (P3).
A generic consumer walks ``content["parents"]`` and resolves each hash to the
upstream payload; it knows nothing about x402's ``provenance{}`` block or its
``capability-grant:`` labels. These tests drive that generic walk.
"""

from __future__ import annotations

import re

from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402.decision_ref import (
    REASON_HASH_MISMATCH,
    DecisionRefError,
    build_decision_evidence,
    capability_parents,
    verify_decision_ref,
)
from presidio_x402.mica import sha256_hex

from .test_decision_ref import _content, _controls, _real_chain

_PARENT_RE = re.compile(r"^[0-9a-f]{8,128}$")


def _keypair() -> tuple[str, str]:
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def _signer():
    priv, pub = _keypair()
    signer = "presidio-hardened-x402-policy"
    return signer, priv, {signer: {"alg": "ed25519", "public_key": pub}}


def adr0002_walk(start: str, store: dict[str, dict]) -> list[str]:
    """A generic ADR-0002 consumer: follow top-level ``parents`` hashes only.

    Fails closed on a malformed entry (P2) or a non-list ``parents`` (P3).
    Returns every reachable node hash, ``start`` first.
    """
    seen: list[str] = []
    frontier = [start]
    while frontier:
        node = frontier.pop(0)
        if node in seen:
            continue
        seen.append(node)
        payload = store.get(node)
        if payload is None:
            continue
        parents = payload.get("parents", [])
        assert isinstance(parents, list) and (parents or "parents" not in payload)
        for parent in parents:
            assert isinstance(parent, str) and _PARENT_RE.fullmatch(parent), parent
            frontier.append(parent)
    return seen


def test_walk_reaches_capability_grant_from_payment_node():
    chain = _real_chain()
    signer, priv, trust = _signer()
    env = build_decision_evidence(
        _content(_controls()),
        signing_key=priv,
        signer=signer,
        parents=capability_parents(chain),
    )
    assert verify_decision_ref(env, trust).ok
    content = env["payment_decision"]
    payment_hash = env["evidence"][0]["content_hash"]
    grant = chain.grants[-1]
    store = {payment_hash: content, grant.grant_hash: {"grant": "terminal"}}

    reached = adr0002_walk(payment_hash, store)
    assert reached == [payment_hash, grant.grant_hash]
    # P1: inside the hashed content (top level), so it is covered by the signature.
    assert content["parents"] == [grant.grant_hash]
    assert sha256_hex(content) == payment_hash


def test_walk_reaches_payment_node_from_downstream_child():
    """The final hop of a storyline: a downstream payload names the payment node."""
    chain = _real_chain()
    signer, priv, _trust = _signer()
    env = build_decision_evidence(
        _content(_controls()), signing_key=priv, signer=signer, parents=capability_parents(chain)
    )
    payment_hash = env["evidence"][0]["content_hash"]
    child = {"schema": "example/downstream@1", "parents": [payment_hash]}
    child_hash = sha256_hex(child)
    store = {child_hash: child, payment_hash: env["payment_decision"]}
    assert adr0002_walk(child_hash, store) == [
        child_hash,
        payment_hash,
        chain.grants[-1].grant_hash,
    ]


def test_parents_omitted_when_empty():
    signer, priv, trust = _signer()
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    assert "parents" not in env["payment_decision"]
    assert verify_decision_ref(env, trust).ok


def test_bare_hex_parent_accepted_and_provenance_mirror_kept():
    signer, priv, trust = _signer()
    cert = "e" * 64
    labelled = "capability-grant:" + "d" * 64
    env = build_decision_evidence(
        _content(_controls()), signing_key=priv, signer=signer, parents=[labelled, cert]
    )
    content = env["payment_decision"]
    assert content["parents"] == ["d" * 64, cert]
    assert content["provenance"]["parents"] == [labelled, cert]
    # Either spelling satisfies a required parent.
    assert verify_decision_ref(env, trust, require_parents=[labelled, "d" * 64, cert]).ok


def test_malformed_parent_fails_closed():
    signer, priv, _trust = _signer()
    for bad in ("capability-grant:XYZ", "D" * 64, "abc", "capability-grant:", "a:b:" + "d" * 64):
        try:
            build_decision_evidence(
                _content(_controls()), signing_key=priv, signer=signer, parents=[bad]
            )
        except DecisionRefError:
            continue
        raise AssertionError(f"malformed parent {bad!r} was emitted")


def test_top_level_parent_tamper_fails_hash():
    signer, priv, trust = _signer()
    env = build_decision_evidence(
        _content(_controls()),
        signing_key=priv,
        signer=signer,
        parents=["capability-grant:" + "d" * 64],
    )
    env["payment_decision"]["parents"] = ["f" * 64]
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_HASH_MISMATCH


def test_legacy_record_without_top_level_parents_still_verifies():
    """Records signed before #141 carry lineage only under provenance{}."""
    signer, priv, trust = _signer()
    env = build_decision_evidence(
        _content(_controls()),
        signing_key=priv,
        signer=signer,
        parents=["capability-grant:" + "d" * 64],
    )
    # Re-sign a legacy-shaped content (no top-level parents) the old way.
    from presidio_x402.decision_ref import artifact_hash, compute_decision_ref
    from presidio_x402.mica import sign_evidence

    legacy = dict(env["payment_decision"])
    legacy.pop("parents")
    a_hash = artifact_hash(legacy)
    env["payment_decision"] = legacy
    env["artifact_hash"] = a_hash
    env["evidence"][0]["content_hash"] = a_hash
    env["evidence"][0]["signature"] = sign_evidence(a_hash, signer, algorithm="ed25519", key=priv)
    d_ref = compute_decision_ref(
        artifact_hash=a_hash, policy_version=legacy["policy_version"], verdict=legacy["verdict"]
    )
    env["decision_ref"] = d_ref
    result = verify_decision_ref(env, trust, require_parents=["capability-grant:" + "d" * 64])
    assert result.ok, result
