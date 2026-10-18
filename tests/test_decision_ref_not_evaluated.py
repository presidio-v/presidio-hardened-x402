"""NOT_EVALUATED: a partial gate records the controls it skipped instead of pass values.

A single MCP tool, for example, runs only the policy or only the replay control.
Recording TRUSTED/FRESH/NOT_REQUIRED for the rest would sign a claim that those
checks happened. NOT_EVALUATED never fails the decision, and a record that
evaluates nothing at all is rejected.
"""

from __future__ import annotations

import logging

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402 import NOT_EVALUATED
from presidio_x402.decision_ref import (
    ControlResults,
    DecisionRefError,
    build_decision_evidence,
    build_payment_decision_content,
    f_controls,
    verify_decision_ref,
)
from presidio_x402.exceptions import PolicyViolationError
from presidio_x402.policy_engine import PolicyConfig, PolicyEngine

_SKIPPED = {
    "pii_verdict": NOT_EVALUATED,
    "trusted_wallet_verdict": NOT_EVALUATED,
    "policy_verdict": NOT_EVALUATED,
    "replay_verdict": NOT_EVALUATED,
    "mpa_verdict": NOT_EVALUATED,
}


@pytest.fixture
def policy_signer():
    sk = ed25519.Ed25519PrivateKey.generate()
    priv, pub = sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()
    signer = "presidio-hardened-x402-policy"
    return signer, priv, pub, {signer: {"alg": "ed25519", "public_key": pub}}


def _content(controls: ControlResults) -> dict:
    return build_payment_decision_content(
        agent_id="did:presidio:x402:agent-7f3a9c",
        payment_signer="wallet:evm:0xA11ce0000000000000000000000000000000dEaD",
        network="eip155:8453",
        binding="x402",
        offer_hash="sha256:" + "1" * 64,
        details_hash="sha256:" + "2" * 64,
        pay_to="0x0273d0b906c9524dB2672318545aaDa1F478B1a1",
        amount="10000",
        currency="USDC",
        resource_origin="https://api.merchant.example",
        controls=controls,
    )


def test_replay_only_gate_roundtrips(policy_signer):
    signer, priv, _pub, trust = policy_signer
    controls = ControlResults(
        **{**_SKIPPED, "replay_verdict": "FRESH", "replay_fingerprint_hash": "sha256:" + "c" * 64}
    )
    content = _content(controls)
    assert "policy_snapshot_hash" not in content["controls"]["policy"]
    env = build_decision_evidence(content, signing_key=priv, signer=signer)
    result = verify_decision_ref(env, trust)
    assert result.ok
    assert result.verdict == "ALLOW"


def test_not_evaluated_never_masks_a_failure():
    controls = ControlResults(**{**_SKIPPED, "replay_verdict": "DUPLICATE"}).to_controls()
    assert f_controls(controls) == "DENY"


def test_evaluated_policy_still_requires_snapshot_hash():
    controls = ControlResults(**{**_SKIPPED, "policy_verdict": "ALLOW"}).to_controls()
    controls["policy"]["policy_snapshot_hash"] = ""
    with pytest.raises(DecisionRefError, match="policy_snapshot_hash"):
        f_controls(controls)


def test_record_that_evaluates_nothing_fails_closed():
    with pytest.raises(DecisionRefError, match="evaluates no control"):
        _content(ControlResults(**_SKIPPED))


def test_policy_violation_log_names_host_not_url(caplog):
    engine = PolicyEngine(PolicyConfig(max_per_call_usd=0.01))
    url = "https://api.merchant.example/u/alice@example.com/pay?ssn=123-45-6789"
    with (
        caplog.at_level(logging.WARNING, logger="presidio_x402.policy_engine"),
        pytest.raises(PolicyViolationError),
    ):
        engine.check_and_record(resource_url=url, amount_usd=1.0)
    text = caplog.text
    assert "api.merchant.example" in text
    assert "alice" not in text and "123-45-6789" not in text
