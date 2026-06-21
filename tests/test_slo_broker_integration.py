"""Thin 402 integration test for the SLO broker (v0.7.0).

Where ``test_slo_broker.py`` injects a fake provider, this exercises the one seam the
unit tests stub: ``X402CapacityProvider`` driving a **real** ``HardenedX402Client``
through an actual 402 → pay → 200 flow (respx-mocked endpoint). It proves the broker's
default provider correctly settles a capacity payment and that the gateway's own
controls run on it — the genuine code-risk in the broker→client→402-rail path.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from presidio_x402._types import PaymentDetails, PaymentResponse
from presidio_x402.arch_translucency_adapter import SLOTrigger
from presidio_x402.audit_log import NullAuditWriter
from presidio_x402.gateway import HardenedX402Client
from presidio_x402.slo_broker import SLOPaymentBroker, X402CapacityProvider
from presidio_x402.slo_policy import SLOPaymentPolicy

CAPACITY_URL = "https://compute.local/v1/capacity"

CAPACITY_OFFER = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "0.01",
                "resource": CAPACITY_URL,
                "description": "capacity upgrade",
                "reason": "slo",
                "mimeType": "application/json",
                "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                "requiredDeadlineSeconds": 300,
                "extra": {},
            }
        ]
    }
)


async def _signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="signed-capacity-token", details=details)  # noqa: S106


def _trigger() -> SLOTrigger:
    return SLOTrigger(
        slo="p99_latency_ms",
        value=420,
        threshold=200,
        window="5m",
        signer="presidio-hardened-arch-translucency",
        content_hash="ab" * 16,
        observed_at="2026-06-21T10:00:00+00:00",
    )


def _broker(client: HardenedX402Client) -> SLOPaymentBroker:
    return SLOPaymentBroker(
        client=client,
        slo_policy=SLOPaymentPolicy(max_per_call_usd=0.05),
        provider=X402CapacityProvider("compute-local", CAPACITY_URL, client),
        base_event_usd=0.01,
    )


@pytest.mark.asyncio
async def test_degrade_to_paid_drives_real_402_flow():
    captured: dict[str, str] = {}

    def _retry(request: httpx.Request) -> httpx.Response:
        captured.update({k.lower(): v for k, v in request.headers.items()})
        return httpx.Response(200, text="upgraded")

    with respx.mock:
        route = respx.post(CAPACITY_URL)
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": CAPACITY_OFFER}),
            _retry,
        ]
        async with HardenedX402Client(payment_signer=_signer, audit_writer=NullAuditWriter()) as c:
            decision = await _broker(c).handle_trigger(_trigger())

    assert decision.action == "paid"
    assert decision.receipt is not None and decision.receipt.ok
    # The capacity payment really went through the gateway's 402 settle + retry.
    assert captured.get("x-payment") == "signed-capacity-token"


@pytest.mark.asyncio
async def test_provider_error_blocks_without_payment():
    with respx.mock:
        respx.post(CAPACITY_URL).mock(return_value=httpx.Response(500, text="provider down"))
        async with HardenedX402Client(payment_signer=_signer, audit_writer=NullAuditWriter()) as c:
            decision = await _broker(c).handle_trigger(_trigger())

    # 5xx (no 402 offer) → no payment, provider declines, broker blocks fail-closed.
    assert decision.action == "blocked"
