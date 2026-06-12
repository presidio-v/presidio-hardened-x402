"""Tests for the v0.5.0 binding-layer refactor (session-3 T2).

Proves the two architectural claims:
1. Everything x402-specific lives in ``bindings.x402`` and satisfies the
   ``PaymentProtocolBinding`` protocol.
2. The screening core is rail-agnostic — a different rail (different status
   code, different header, different offer format) reuses the full pipeline
   unchanged, including redaction, policy, and replay guarantees.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from presidio_x402 import (
    HardenedX402Client,
    PaymentProtocolBinding,
    ScreeningPipeline,
    X402Binding,
)
from presidio_x402._types import PaymentDetails, PaymentResponse
from presidio_x402.audit_log import AuditLog, NullAuditWriter
from presidio_x402.exceptions import (
    PolicyViolationError,
    ReplayDetectedError,
    X402PaymentError,
)
from presidio_x402.pii_filter import PIIFilter
from presidio_x402.policy_engine import PolicyEngine
from presidio_x402.replay_guard import ReplayGuard

# ---------------------------------------------------------------------------
# X402Binding
# ---------------------------------------------------------------------------

OFFER = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "0.01",
                "resource": "https://api.example.com/v1/data",
                "description": "API data access",
                "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                "requiredDeadlineSeconds": 300,
            }
        ]
    }
)


def test_x402_binding_satisfies_protocol():
    assert isinstance(X402Binding(), PaymentProtocolBinding)


def test_x402_binding_constants():
    b = X402Binding()
    assert b.name == "x402"
    assert b.payment_required_status == 402
    assert b.header_name == "X-PAYMENT"


def test_payment_offer_extraction():
    b = X402Binding()
    assert b.payment_offer(200, {"X-PAYMENT": OFFER}) is None  # not payment-required
    assert b.payment_offer(402, {}) is None  # missing header
    assert b.payment_offer(402, {"X-PAYMENT": OFFER}) == OFFER


def test_parse_payment_required_round_trip():
    details = X402Binding().parse_payment_required(OFFER)
    assert details.pay_to == "0xabcdef1234567890abcdef1234567890abcdef12"
    assert details.amount == "0.01"
    assert details.network == "base-sepolia"


def test_parse_payment_required_fails_closed():
    with pytest.raises(X402PaymentError):
        X402Binding().parse_payment_required("not json")


def test_token_headers():
    assert X402Binding().token_headers("tok") == {"X-PAYMENT": "tok"}


def test_back_compat_import_paths_survive_refactor():
    """The pre-v0.5.0 gateway import surface still works (SEMVER.md)."""
    from presidio_x402 import gateway

    assert gateway._HEADER_PAYMENT == "X-PAYMENT"
    assert gateway._SUPPORTED_SCHEME == "exact"
    assert gateway._parse_402_header is not None
    assert gateway._amount_to_usd("0.5", "USDC") == 0.5


# ---------------------------------------------------------------------------
# ScreeningPipeline standalone (no HTTP, no binding — rail-agnostic by construction)
# ---------------------------------------------------------------------------


def _details(**overrides) -> PaymentDetails:
    base = {
        "resource_url": "https://api.example.com/v1/data",
        "pay_to": "0xabcdef1234567890abcdef1234567890abcdef12",
        "amount": "0.01",
        "currency": "USDC",
        "network": "base-sepolia",
        "deadline_seconds": 300,
        "description": "",
        "reason": "",
    }
    base.update(overrides)
    return PaymentDetails(**base)


def _pipeline(**overrides) -> ScreeningPipeline:
    defaults = {
        "pii_filter": PIIFilter(),
        "policy": PolicyEngine(overrides.pop("policy_config", None)),
        "replay": ReplayGuard(ttl=300),
        "audit": AuditLog(NullAuditWriter()),
    }
    defaults.update(overrides)
    return ScreeningPipeline(**defaults)


@pytest.mark.asyncio
async def test_pipeline_redacts_pii_without_any_rail():
    pipeline = _pipeline()
    details = _details(description="contact alice@example.com for access")
    secure, fingerprint = await pipeline.apply(details)
    assert "alice@example.com" not in secure.description
    assert "<REDACTED>" in secure.description
    assert len(fingerprint) == 64  # HMAC-SHA256 hex


@pytest.mark.asyncio
async def test_pipeline_policy_violation_blocks():
    pipeline = _pipeline(policy_config={"max_per_call_usd": 0.001})
    with pytest.raises(PolicyViolationError):
        await pipeline.apply(_details())


@pytest.mark.asyncio
async def test_pipeline_replay_blocks_second_identical_payment():
    pipeline = _pipeline()
    await pipeline.apply(_details())
    with pytest.raises(ReplayDetectedError):
        await pipeline.apply(_details())


@pytest.mark.asyncio
async def test_pipeline_rollback_frees_budget_and_fingerprint():
    pipeline = _pipeline(policy_config={"daily_limit_usd": 0.01})
    secure, fingerprint = await pipeline.apply(_details())
    pipeline.rollback(resource_url=secure.resource_url, amount_usd=0.01, fingerprint=fingerprint)
    # After rollback the same payment passes again: budget refunded, slot freed.
    await pipeline.apply(_details())


# ---------------------------------------------------------------------------
# Rail-agnosticism end-to-end: a non-x402 rail through the unchanged core
# ---------------------------------------------------------------------------


class FakeRailBinding:
    """A hypothetical rail: HTTP 419 + ``X-FAKEPAY`` header, flat JSON offer."""

    name = "fakerail"
    payment_required_status = 419
    header_name = "X-FAKEPAY"

    def payment_offer(self, status_code: int, headers) -> str | None:
        if status_code != self.payment_required_status:
            return None
        return headers.get(self.header_name)

    def parse_payment_required(self, offer: str) -> PaymentDetails:
        try:
            data = json.loads(offer)
            return PaymentDetails(
                resource_url=data["url"],
                pay_to=data["to"],
                amount=data["amt"],
                currency=data.get("ccy", "USDC"),
                network=data.get("net", "fake-net"),
                deadline_seconds=int(data.get("ttl", 300)),
                description=data.get("desc", ""),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise X402PaymentError("Invalid fakerail offer") from exc

    def token_headers(self, token: str) -> dict[str, str]:
        return {self.header_name: token}


FAKE_OFFER = json.dumps(
    {
        "url": "https://api.fakerail.test/res",
        "to": "0x1111111111111111111111111111111111111111",
        "amt": "0.02",
        "desc": "reach bob@example.com",
    }
)


async def _mock_signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="fake-signed", details=details)  # noqa: S106


def test_fake_rail_satisfies_protocol():
    assert isinstance(FakeRailBinding(), PaymentProtocolBinding)


@pytest.mark.asyncio
async def test_full_pipeline_runs_on_a_different_rail():
    """The complete client flow — detection, parsing, PII redaction, signing,
    token retry — works on a rail that shares nothing with x402's wire format."""
    signed_descriptions: list[str] = []

    async def capturing_signer(details: PaymentDetails) -> PaymentResponse:
        signed_descriptions.append(details.description)
        return PaymentResponse(token="fake-signed", details=details)  # noqa: S106

    captured_headers: dict[str, str] = {}

    def _capture_retry(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, text="paid")

    with respx.mock:
        route = respx.get("https://api.fakerail.test/res")
        route.side_effect = [
            httpx.Response(419, headers={"X-FAKEPAY": FAKE_OFFER}),
            _capture_retry,
        ]
        async with HardenedX402Client(
            payment_signer=capturing_signer, binding=FakeRailBinding()
        ) as client:
            resp = await client.get("https://api.fakerail.test/res")

    assert resp.status_code == 200
    # The screening core ran unchanged: PII was redacted before signing.
    assert signed_descriptions == ["reach <REDACTED>"]
    # The token travelled on the fake rail's header, not X-PAYMENT.
    assert captured_headers.get("x-fakepay") == "fake-signed"
    assert "x-payment" not in {k.lower() for k in captured_headers}


@pytest.mark.asyncio
async def test_fake_rail_replay_blocked_like_x402():
    """Replay protection is a core guarantee, independent of the rail."""
    with respx.mock:
        route = respx.get("https://api.fakerail.test/res")
        route.side_effect = [
            httpx.Response(419, headers={"X-FAKEPAY": FAKE_OFFER}),
            httpx.Response(200, text="paid"),
            httpx.Response(419, headers={"X-FAKEPAY": FAKE_OFFER}),
        ]
        async with HardenedX402Client(
            payment_signer=_mock_signer, binding=FakeRailBinding()
        ) as client:
            await client.get("https://api.fakerail.test/res")
            with pytest.raises(ReplayDetectedError):
                await client.get("https://api.fakerail.test/res")


# ---------------------------------------------------------------------------
# PIIFilter.scan_fields (rail-agnostic field mapping)
# ---------------------------------------------------------------------------


def test_scan_fields_arbitrary_mapping():
    f = PIIFilter()
    redacted, entities = f.scan_fields(
        {"memo": "ssn 078-05-1120", "note": "clean", "ref": "call 030-1234567"}
    )
    assert list(redacted) == ["memo", "note", "ref"]
    assert redacted["note"] == "clean"
    assert "078-05-1120" not in redacted["memo"]
    assert entities  # at least the SSN detected


def test_scan_fields_empty_mapping():
    assert PIIFilter().scan_fields({}) == ({}, [])
