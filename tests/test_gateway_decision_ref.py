"""Gateway wiring of decision-ref emission (opt-in; default OFF).

Asserts:
- with no emitter, no decision-ref record is produced and the 402 flow is
  unchanged (default-off, byte-identical behaviour);
- with an emitter, exactly one signed payment-decision@1 record is emitted per
  paid payment, it verifies against the policy trust store, and it carries no raw
  metadata string (PII-freedom on the live path).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402 import HardenedX402Client
from presidio_x402._types import PaymentDetails, PaymentResponse
from presidio_x402.audit_log import NullAuditWriter
from presidio_x402.decision_ref import (
    DecisionRefEmitter,
    offer_hash,
    verify_decision_ref,
)

# A 402 offer whose resource URL and description carry PII (email + person).
_PII_OFFER = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "0.01",
                "resource": "https://api.example.com/users/alice@example.com/data",
                "description": "Invoice for Alice Wonderland",
                "reason": "research",
                "mimeType": "application/json",
                "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                "requiredDeadlineSeconds": 300,
                "extra": {},
            }
        ]
    }
)


async def _mock_signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="mock-signed-token", details=details)  # noqa: S106


def _keypair():
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


class _ListWriter:
    def __init__(self):
        self.records = []

    def write(self, envelope):
        self.records.append(dict(envelope))


@pytest.mark.asyncio
async def test_default_off_emits_nothing():
    """No emitter configured -> no record, payment still completes."""
    with respx.mock:
        route = respx.get("https://api.example.com/users/alice@example.com/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": _PII_OFFER}),
            httpx.Response(200, text="paid"),
        ]
        client = HardenedX402Client(payment_signer=_mock_signer, audit_writer=NullAuditWriter())
        # No _decision_emitter attribute leakage into behaviour:
        assert client._pipeline._decision_emitter is None
        async with client:
            resp = await client.get("https://api.example.com/users/alice@example.com/data")
        assert resp.status_code == 200 and resp.text == "paid"


@pytest.mark.asyncio
async def test_emitter_produces_one_verifiable_pii_free_record():
    priv, pub = _keypair()
    signer = "presidio-hardened-x402-policy"
    trust = {signer: {"alg": "ed25519", "public_key": pub}}
    writer = _ListWriter()
    emitter = DecisionRefEmitter(signing_key=priv, signer=signer, writer=writer)

    with respx.mock:
        route = respx.get("https://api.example.com/users/alice@example.com/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": _PII_OFFER}),
            httpx.Response(200, text="paid"),
        ]
        client = HardenedX402Client(
            payment_signer=_mock_signer,
            audit_writer=NullAuditWriter(),
            agent_id="did:presidio:x402:agent-1",
            decision_ref_emitter=emitter,
            pii_action="redact",
        )
        async with client:
            await client.get("https://api.example.com/users/alice@example.com/data")

    assert len(writer.records) == 1
    env = writer.records[0]
    result = verify_decision_ref(env, trust)
    assert result.ok, result.reason
    assert result.verdict == "ALLOW"
    # PII from the offer must not survive into the record.
    blob = json.dumps(env, ensure_ascii=False)
    assert "alice@example.com" not in blob
    assert "Alice Wonderland" not in blob
    assert _PII_OFFER not in blob
    payment = env["payment_decision"]["payment"]
    assert payment["offer_hash"] == offer_hash(_PII_OFFER.encode("utf-8"))
    assert payment["offer_hash"] != payment["details_hash"]
    assert "offer_hash_absent" not in payment
    # The redaction verdict + entity label is what is recorded instead.
    assert env["payment_decision"]["controls"]["pii"]["verdict"] == "PII_REDACTED"
    assert "EMAIL_ADDRESS" in env["payment_decision"]["controls"]["pii"]["entities"]


@pytest.mark.asyncio
async def test_emit_failure_does_not_break_payment():
    """A failing emitter must not undo a payment the gateway already decided."""

    class _BoomWriter:
        def write(self, envelope):
            raise RuntimeError("sink down")

    priv, _pub = _keypair()
    emitter = DecisionRefEmitter(signing_key=priv, writer=_BoomWriter())
    with respx.mock:
        route = respx.get("https://api.example.com/v1/data")
        route.side_effect = [
            httpx.Response(
                402,
                headers={
                    "X-PAYMENT": json.dumps(
                        {
                            "accepts": [
                                {
                                    "scheme": "exact",
                                    "network": "base-sepolia",
                                    "maxAmountRequired": "0.01",
                                    "resource": "https://api.example.com/v1/data",
                                    "description": "clean",
                                    "reason": "r",
                                    "mimeType": "application/json",
                                    "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                                    "requiredDeadlineSeconds": 300,
                                    "extra": {},
                                }
                            ]
                        }
                    )
                },
            ),
            httpx.Response(200, text="paid"),
        ]
        client = HardenedX402Client(
            payment_signer=_mock_signer,
            audit_writer=NullAuditWriter(),
            decision_ref_emitter=emitter,
        )
        async with client:
            resp = await client.get("https://api.example.com/v1/data")
        assert resp.status_code == 200
