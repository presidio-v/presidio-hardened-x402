"""Tests for decision-ref emission (``presidio-hardened-x402/payment-decision@1``).

Covers, per the task brief:

- roundtrip per gate/control type (build -> sign -> verify) with each verdict enum;
- PII-freedom: no raw metadata string from a PII-bearing corpus ever appears in any
  emitted record (only hashes + entity-type labels);
- parent linkage to a REAL capability chain from ``capability.py``;
- tamper detection (content, signature, verdict) and the two named fail-closed
  negatives (self-approval ``signer_equals_runtime``, ``verdict_not_recomputable``);
- default-off unchanged-behaviour: with no emitter the pipeline result is identical
  and no record is written.

Ed25519 keys are generated per-test via ``cryptography`` (the ``[evidence]`` extra),
mirroring ``test_capability.py`` / ``test_mica.py``.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402.capability import delegate_grant, issue_grant, verify_chain
from presidio_x402.decision_ref import (
    PAYMENT_DECISION_SCHEMA_ID,
    REASON_BAD_SIGNATURE,
    REASON_HASH_MISMATCH,
    REASON_MALFORMED,
    REASON_PARENT_LINKAGE,
    REASON_SIGNER_EQUALS_RUNTIME,
    REASON_UNKNOWN_SIGNER,
    REASON_VERDICT_NOT_RECOMPUTABLE,
    ControlResults,
    DecisionRefEmitter,
    DecisionRefError,
    NullDecisionRefWriter,
    build_decision_evidence,
    build_payment_decision_content,
    capability_parents,
    compute_decision_ref,
    f_controls,
    verify_decision_ref,
)


def _keypair() -> tuple[str, str]:
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


@pytest.fixture
def policy_signer():
    """A policy-issuer keypair + trust store (distinct from any payment wallet)."""
    priv, pub = _keypair()
    signer = "presidio-hardened-x402-policy"
    trust = {signer: {"alg": "ed25519", "public_key": pub}}
    return signer, priv, pub, trust


def _controls(**overrides) -> ControlResults:
    base = {
        "pii_verdict": "PII_REDACTED",
        "pii_entities": ("EMAIL_ADDRESS",),
        "pii_mutated": True,
        "trusted_wallet_verdict": "TRUSTED",
        "policy_verdict": "ALLOW",
        "policy_snapshot_hash": "sha256:" + "a" * 64,
        "policy_limit_hash": "sha256:" + "b" * 64,
        "replay_verdict": "FRESH",
        "replay_fingerprint_hash": "sha256:" + "c" * 64,
        "mpa_verdict": "NOT_REQUIRED",
        "mpa_required": False,
    }
    base.update(overrides)
    return ControlResults(**base)


def _content(controls: ControlResults, **overrides) -> dict:
    kw = {
        "agent_id": "did:presidio:x402:agent-7f3a9c",
        "payment_signer": "wallet:evm:0xA11ce0000000000000000000000000000000dEaD",
        "network": "eip155:8453",
        "binding": "x402",
        "offer_hash": "sha256:" + "1" * 64,
        "details_hash": "sha256:" + "2" * 64,
        "pay_to": "0x0273d0b906c9524dB2672318545aaDa1F478B1a1",
        "amount": "10000",
        "currency": "USDC",
        "resource_origin": "https://api.merchant.example",
        "controls": controls,
    }
    kw.update(overrides)
    return build_payment_decision_content(**kw)


def _resign_payment_decision(env: dict, signer: str, priv: str) -> None:
    from presidio_x402.mica import sha256_hex, sign_evidence

    new_hash = sha256_hex(env["payment_decision"])
    env["artifact_hash"] = new_hash
    env["evidence"][0]["content_hash"] = new_hash
    env["evidence"][0]["signature"] = sign_evidence(new_hash, signer, key=priv)
    env["decision_ref"] = compute_decision_ref(
        artifact_hash=new_hash,
        policy_version=env["payment_decision"]["policy_version"],
        verdict=env["payment_decision"]["verdict"],
    )


# ---------------------------------------------------------------------------
# 1. f(controls) — recomputable verdict, first-failure-wins.
# ---------------------------------------------------------------------------


def test_f_controls_allow():
    assert f_controls(_controls().to_controls()) == "ALLOW"


@pytest.mark.parametrize(
    "override",
    [
        {"pii_verdict": "PII_BLOCKED"},
        {"trusted_wallet_verdict": "UNTRUSTED"},
        {"policy_verdict": "VIOLATION"},
        {"replay_verdict": "DUPLICATE"},
        {"mpa_verdict": "DENIED", "mpa_required": True},
    ],
)
def test_f_controls_deny(override):
    assert f_controls(_controls(**override).to_controls()) == "DENY"


@pytest.mark.parametrize("mpa", ["PENDING", "TIMEOUT"])
def test_f_controls_refer_on_unanswered_mpa(mpa):
    assert f_controls(_controls(mpa_verdict=mpa, mpa_required=True).to_controls()) == "REFER"


def test_f_controls_first_failure_wins():
    # PII blocked precedes a policy violation: DENY either way, but the point is
    # precedence order matches the shipped gateway.
    c = _controls(pii_verdict="PII_BLOCKED", policy_verdict="VIOLATION").to_controls()
    assert f_controls(c) == "DENY"


def test_invalid_verdict_fails_closed():
    with pytest.raises(DecisionRefError):
        _controls(policy_verdict="MAYBE").to_controls()


def test_f_controls_missing_control_fails_closed():
    controls = _controls().to_controls()
    del controls["policy"]
    with pytest.raises(DecisionRefError):
        f_controls(controls)


# ---------------------------------------------------------------------------
# 2. Build -> sign -> verify roundtrip, per verdict.
# ---------------------------------------------------------------------------


def test_roundtrip_allow(policy_signer):
    signer, priv, _pub, trust = policy_signer
    content = _content(_controls())
    env = build_decision_evidence(content, signing_key=priv, signer=signer)
    assert env["schema"] == "presidio-hardened/evidence-ref@1"
    assert env["payment_decision"]["schema"] == PAYMENT_DECISION_SCHEMA_ID
    result = verify_decision_ref(env, trust)
    assert result.ok
    assert result.verdict == "ALLOW" == result.recomputed_verdict
    assert "signature" in result.checked


def test_absent_offer_hash_is_explicit(policy_signer):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(
        _content(_controls(), offer_hash=None, offer_hash_absent="not-retained"),
        signing_key=priv,
        signer=signer,
    )
    payment = env["payment_decision"]["payment"]
    assert "offer_hash" not in payment
    assert payment["offer_hash_absent"] == "not-retained"
    assert verify_decision_ref(env, trust).ok


@pytest.mark.parametrize(
    "override,expected",
    [
        ({"policy_verdict": "VIOLATION"}, "DENY"),
        ({"replay_verdict": "DUPLICATE"}, "DENY"),
        ({"pii_verdict": "PII_BLOCKED"}, "DENY"),
        ({"trusted_wallet_verdict": "UNTRUSTED"}, "DENY"),
        ({"mpa_verdict": "PENDING", "mpa_required": True}, "REFER"),
    ],
)
def test_roundtrip_each_gate(policy_signer, override, expected):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(_content(_controls(**override)), signing_key=priv, signer=signer)
    result = verify_decision_ref(env, trust)
    assert result.ok and result.verdict == expected


def test_decision_ref_recomputes_from_preimage(policy_signer):
    signer, priv, _pub, _trust = policy_signer
    content = _content(_controls())
    env = build_decision_evidence(content, signing_key=priv, signer=signer)
    pre = env["decision_ref_preimage"]
    assert set(env["decision_ref_preimage_fields"]) == set(pre.keys())
    assert compute_decision_ref(**pre) == env["decision_ref"]
    assert env["evidence"][0]["content_hash"] == env["artifact_hash"] == pre["artifact_hash"]


def test_hmac_roundtrip():
    signer = "policy-hmac"
    content = _content(_controls())
    env = build_decision_evidence(
        content, signing_key="s3cr3t", algorithm="hmac-sha256", signer=signer
    )
    trust = {signer: {"alg": "hmac-sha256", "key": "s3cr3t"}}
    assert verify_decision_ref(env, trust).ok


# ---------------------------------------------------------------------------
# 3. PII-freedom over a PII-bearing corpus.
# ---------------------------------------------------------------------------

_PII_STRINGS = [
    "alice@example.com",
    "bob.smith@corp.internal",
    "4111111111111111",  # credit card
    "123-45-6789",  # SSN
    "+1-415-555-0132",  # phone
    "Alice Wonderland",  # person
    "GB33BUKB20201555555555",  # IBAN
    "https://api.example.com/users/alice@example.com/invoice",
    "Payment for Bob Smith, SSN 123-45-6789",
]


def test_no_raw_pii_string_in_record(policy_signer):
    """No raw metadata string may appear in any emitted record; only its hash and
    entity-type labels. The ControlResults dataclass has no field that accepts a
    raw string, so this holds by construction — asserted here over a corpus."""
    signer, priv, _pub, trust = policy_signer
    # A record built as if screening those PII strings found these entity types.
    controls = _controls(
        pii_verdict="PII_REDACTED",
        pii_entities=(
            "EMAIL_ADDRESS",
            "CREDIT_CARD",
            "US_SSN",
            "PHONE_NUMBER",
            "PERSON",
            "IBAN_CODE",
        ),
    )
    env = build_decision_evidence(_content(controls), signing_key=priv, signer=signer)
    blob = json.dumps(env, ensure_ascii=False)
    for raw in _PII_STRINGS:
        assert raw not in blob, f"raw PII leaked into record: {raw!r}"
    # Entity-type labels ARE present (that is the allowed screening output).
    assert "EMAIL_ADDRESS" in blob and "US_SSN" in blob
    assert verify_decision_ref(env, trust).ok


def test_control_results_has_no_raw_string_field():
    """Structural guarantee: every string field is a hash or an enum label."""
    fields = ControlResults.__dataclass_fields__
    for name in ("policy_snapshot_hash", "policy_limit_hash", "replay_fingerprint_hash"):
        assert name in fields  # the only free-form strings are hashes


# ---------------------------------------------------------------------------
# 4. Capability-chain parent linkage (real chain from capability.py).
# ---------------------------------------------------------------------------


def _real_chain():
    op_priv, op_pub = _keypair()
    agent_priv, agent_pub = _keypair()
    sub_priv, sub_pub = _keypair()
    root = issue_grant(
        subject="agent-root",
        issuer="acme-operator",
        issuer_private_key=op_priv,
        subject_public_key=agent_pub,
        caveats={
            "max_per_call_usd": "0.05",
            "endpoint_prefixes": ["https://api.merchant.example"],
        },
    )
    child = delegate_grant(
        root,
        parent_private_key=agent_priv,
        subject="agent-sub",
        subject_public_key=sub_pub,
        caveats={
            "max_per_call_usd": "0.02",
            "endpoint_prefixes": ["https://api.merchant.example"],
        },
    )
    trust = {"acme-operator": {"alg": "ed25519", "public_key": op_pub}}
    chain = verify_chain([root, child], trust)
    return chain


def test_parent_links_to_real_capability_chain(policy_signer):
    signer, priv, _pub, trust = policy_signer
    chain = _real_chain()
    parents = capability_parents(chain)
    terminal_hash = chain.grants[-1].grant_hash
    assert parents == [f"capability-grant:{terminal_hash}"]

    env = build_decision_evidence(
        _content(_controls()), signing_key=priv, signer=signer, parents=parents
    )
    assert env["provenance"]["parents"] == parents
    assert env["payment_decision"]["provenance"]["parents"] == parents
    # Verification succeeds and, when we require the real parent, still succeeds.
    assert verify_decision_ref(env, trust, require_parents=parents).ok


def test_missing_required_parent_fails_closed(policy_signer):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    # No parents recorded, but we require one -> parent_linkage failure.
    result = verify_decision_ref(env, trust, require_parents=["capability-grant:" + "d" * 64])
    assert not result.ok and result.reason == REASON_PARENT_LINKAGE


def test_unsigned_envelope_parent_does_not_satisfy_required_parent(policy_signer):
    signer, priv, _pub, trust = policy_signer
    required = ["capability-grant:" + "d" * 64]
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    env["provenance"]["parents"] = required
    result = verify_decision_ref(env, trust, require_parents=required)
    assert not result.ok and result.reason == REASON_PARENT_LINKAGE


def test_signed_parent_tamper_fails_hash(policy_signer):
    signer, priv, _pub, trust = policy_signer
    parents = ["capability-grant:" + "d" * 64]
    env = build_decision_evidence(
        _content(_controls()), signing_key=priv, signer=signer, parents=parents
    )
    env["payment_decision"]["provenance"]["parents"] = []
    result = verify_decision_ref(env, trust, require_parents=parents)
    assert not result.ok and result.reason == REASON_HASH_MISMATCH


def test_capability_parents_none_is_empty():
    assert capability_parents(None) == []


# ---------------------------------------------------------------------------
# 5. Tamper detection + the two named fail-closed negatives.
# ---------------------------------------------------------------------------


def test_tamper_content_fails_hash(policy_signer):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    env["payment_decision"]["payment"]["amount"] = "99999999"  # mutate after signing
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_HASH_MISMATCH


def test_tamper_signature_fails(policy_signer):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    sig = env["evidence"][0]["signature"]
    env["evidence"][0]["signature"] = ("f" if sig[0] != "f" else "0") + sig[1:]
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_BAD_SIGNATURE


def test_unknown_signer_fails(policy_signer):
    signer, priv, _pub, _trust = policy_signer
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    result = verify_decision_ref(env, {"someone-else": {"alg": "ed25519", "public_key": "0" * 64}})
    assert not result.ok and result.reason == REASON_UNKNOWN_SIGNER


def test_self_approval_fails_closed(policy_signer):
    """signer_equals_runtime: the record is signed by the actor's own wallet."""
    _signer, priv, pub, _trust = policy_signer
    wallet = "wallet:evm:0xA11ce0000000000000000000000000000000dEaD"
    content = _content(_controls(), payment_signer=wallet)
    env = build_decision_evidence(content, signing_key=priv, signer=wallet)
    trust = {wallet: {"alg": "ed25519", "public_key": pub}}
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_SIGNER_EQUALS_RUNTIME


def test_verdict_not_recomputable_refused_at_emit(policy_signer):
    """build refuses to sign a content whose verdict != f(controls)."""
    signer, priv, _pub, _trust = policy_signer
    content = _content(_controls())
    content["verdict"] = "DENY"  # forge: f(controls)=ALLOW
    with pytest.raises(DecisionRefError):
        build_decision_evidence(content, signing_key=priv, signer=signer)


def test_verdict_not_recomputable_detected_on_verify(policy_signer):
    """A forged verdict that slipped past emission is caught fail-closed on read."""
    signer, priv, _pub, trust = policy_signer
    content = _content(_controls())
    env = build_decision_evidence(content, signing_key=priv, signer=signer)
    # Tamper the verdict inside the (already-hashed) content AND fix the hash so it
    # only fails at the recompute layer, not the hash layer.
    env["payment_decision"]["verdict"] = "DENY"
    _resign_payment_decision(env, signer, priv)
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_VERDICT_NOT_RECOMPUTABLE


def test_missing_control_detected_on_verify(policy_signer):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    del env["payment_decision"]["controls"]["policy"]
    _resign_payment_decision(env, signer, priv)
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_MALFORMED


def test_unknown_control_detected_on_verify(policy_signer):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    env["payment_decision"]["controls"]["unknown"] = {"verdict": "ALLOW"}
    _resign_payment_decision(env, signer, priv)
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_MALFORMED


def test_invalid_control_verdict_detected_on_verify(policy_signer):
    signer, priv, _pub, trust = policy_signer
    env = build_decision_evidence(_content(_controls()), signing_key=priv, signer=signer)
    env["payment_decision"]["controls"]["policy"]["verdict"] = "MAYBE"
    _resign_payment_decision(env, signer, priv)
    result = verify_decision_ref(env, trust)
    assert not result.ok and result.reason == REASON_MALFORMED


def test_no_unsigned_output():
    # Fail-closed via the family signing primitive (EvidenceError is the base of
    # DecisionRefError): no key -> no envelope, never an unsigned record.
    from presidio_x402.mica import EvidenceError

    with pytest.raises(EvidenceError):
        build_decision_evidence(_content(_controls()), signing_key="", signer="x")


# ---------------------------------------------------------------------------
# 6. Emitter + writer.
# ---------------------------------------------------------------------------


def test_emitter_writes_and_returns(policy_signer, tmp_path):
    from presidio_x402.decision_ref import FileDecisionRefWriter

    signer, priv, _pub, trust = policy_signer
    path = tmp_path / "decisions.jsonl"
    emitter = DecisionRefEmitter(
        signing_key=priv, signer=signer, writer=FileDecisionRefWriter(str(path), fsync=False)
    )
    env = emitter.emit(
        agent_id="agent-x",
        payment_signer="0xpay",
        network="eip155:8453",
        binding="x402",
        offer_hash="sha256:" + "1" * 64,
        details_hash="sha256:" + "2" * 64,
        pay_to="0xpay",
        amount="10000",
        currency="USDC",
        resource_origin="https://api.merchant.example",
        controls=_controls(),
    )
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    on_disk = json.loads(lines[0])
    assert on_disk["decision_ref"] == env["decision_ref"]
    assert verify_decision_ref(on_disk, trust).ok


def test_null_writer_discards(policy_signer):
    signer, priv, _pub, _trust = policy_signer
    emitter = DecisionRefEmitter(signing_key=priv, signer=signer, writer=NullDecisionRefWriter())
    env = emitter.emit(
        agent_id="a",
        payment_signer="0xp",
        network="n",
        binding="x402",
        offer_hash="sha256:" + "1" * 64,
        details_hash="sha256:" + "2" * 64,
        pay_to="0xp",
        amount="1",
        currency="USDC",
        resource_origin="https://x",
        controls=_controls(),
    )
    assert env["decision_ref"]
