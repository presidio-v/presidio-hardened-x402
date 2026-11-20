"""Regression tests for the 2026-11-01 security-audit findings (medium).

* ``offer-resource-not-bound-to-requested-url``: controls were keyed on the
  server-asserted offer ``resource``; a server at an allowlisted, pinned or
  budgeted origin could name another origin or path and escape them.
* ``slo-caps-not-bound-to-signed-payment``: the SLO broker's caps reached the
  capacity server only as advisory JSON; the signed amount was whatever the
  server offered, and the ledger recorded the cap instead of the payment.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from presidio_x402 import HardenedX402Client
from presidio_x402._types import AuditEvent, PaymentDetails, PaymentResponse
from presidio_x402.arch_translucency_adapter import SLOTrigger
from presidio_x402.audit_log import NullAuditWriter
from presidio_x402.exceptions import PolicyViolationError, X402PaymentError
from presidio_x402.slo_broker import SLOPaymentBroker, X402CapacityProvider
from presidio_x402.slo_policy import SLOPaymentPolicy

URL = "https://api.example.com/v1/data"
LEGIT = "0x1111111111111111111111111111111111111111"
ATTACKER = "0x9999999999999999999999999999999999999999"


class _Recorder:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


def _offer(resource: str = URL, pay_to: str = LEGIT, amount: str = "0.01") -> str:
    return json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": amount,
                    "resource": resource,
                    "description": "API data access",
                    "payTo": pay_to,
                    "requiredDeadlineSeconds": 300,
                }
            ]
        }
    )


def _capturing_signer(signed: list[PaymentDetails]):
    async def _sign(details: PaymentDetails) -> PaymentResponse:
        signed.append(details)
        return PaymentResponse(token="signed", details=details)  # noqa: S106

    return _sign


# --------------------------------------------------------------- offer binding
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resource",
    [
        "https://attacker.example/x",  # another host
        "https://api.example.com:8443/v1/data",  # same host, another port
        "http://api.example.com/v1/data",  # downgraded scheme
    ],
)
async def test_offer_naming_another_origin_is_refused_before_signing(resource):
    signed: list[PaymentDetails] = []
    audit = _Recorder()
    with respx.mock:
        respx.get(URL).mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": _offer(resource, ATTACKER)})
        )
        client = HardenedX402Client(
            payment_signer=_capturing_signer(signed),
            audit_writer=audit,
            trusted_wallets={"https://api.example.com": {LEGIT}},
        )
        try:
            with pytest.raises(X402PaymentError, match="different origin"):
                await client.get(URL)
        finally:
            await client.aclose()
    assert signed == []
    blocked = [e for e in audit.events if e.event_type == "PAYMENT_ERROR"]
    assert blocked and blocked[0].outcome == "blocked"
    assert "requested origin" in (blocked[0].error_message or "")


@pytest.mark.asyncio
async def test_canonical_spelling_of_the_same_origin_is_accepted():
    signed: list[PaymentDetails] = []
    with respx.mock:
        route = respx.get(URL)
        route.side_effect = [
            httpx.Response(
                402, headers={"X-PAYMENT": _offer("https://API.Example.com:443/v1/data")}
            ),
            httpx.Response(200, text="ok"),
        ]
        client = HardenedX402Client(
            payment_signer=_capturing_signer(signed),
            trusted_wallets={"https://api.example.com": {LEGIT}},
        )
        try:
            resp = await client.get(URL)
        finally:
            await client.aclose()
    assert resp.status_code == 200 and len(signed) == 1
    assert resp.extensions["presidio_x402_paid_usd"] == pytest.approx(0.01)


@pytest.mark.asyncio
async def test_per_endpoint_ledger_keys_on_the_requested_url_not_the_offer_path():
    """A same-origin offer that names another path must still hit the ledger of the
    URL actually requested (previously no prefix matched and nothing was charged)."""
    signed: list[PaymentDetails] = []
    with respx.mock:
        route = respx.get(URL)
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": _offer(URL)}),
            httpx.Response(200, text="ok"),
            httpx.Response(
                402, headers={"X-PAYMENT": _offer("https://api.example.com/elsewhere")}
            ),
        ]
        client = HardenedX402Client(
            payment_signer=_capturing_signer(signed),
            policy={"per_endpoint": {URL: 0.015}},
        )
        try:
            await client.get(URL)
            with pytest.raises(PolicyViolationError):
                await client.get(URL)
        finally:
            await client.aclose()
    assert len(signed) == 1


# ---------------------------------------------------------- per-request cap
@pytest.mark.asyncio
async def test_max_amount_usd_blocks_a_larger_offer_before_signing():
    signed: list[PaymentDetails] = []
    with respx.mock:
        respx.post(URL).mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": _offer(amount="500")})
        )
        client = HardenedX402Client(
            payment_signer=_capturing_signer(signed), audit_writer=NullAuditWriter()
        )
        try:
            with pytest.raises(PolicyViolationError) as exc_info:
                await client.post(URL, json={}, max_amount_usd=0.5)
        finally:
            await client.aclose()
    assert exc_info.value.reason == "request_cap"
    assert signed == []


# ------------------------------------------------------------- SLO broker
CAPACITY_URL = "https://compute.local/v1/capacity"


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
        slo_policy=SLOPaymentPolicy(max_per_slo_event_usd=0.50, max_daily_slo_usd=1.00),
        provider=X402CapacityProvider("compute-local", CAPACITY_URL, client),
        base_event_usd=0.10,
    )


@pytest.mark.asyncio
async def test_slo_cap_binds_the_signed_payment():
    """The audit's reproduction: a 500 USDC offer under a 0.50 per-event cap."""
    signed: list[PaymentDetails] = []
    with respx.mock:
        respx.post(CAPACITY_URL).mock(
            return_value=httpx.Response(
                402, headers={"X-PAYMENT": _offer(CAPACITY_URL, amount="500")}
            )
        )
        async with HardenedX402Client(
            payment_signer=_capturing_signer(signed), audit_writer=NullAuditWriter()
        ) as c:
            decision = await _broker(c).handle_trigger(_trigger())
    assert decision.action == "blocked"
    assert "client policy blocked" in decision.reason
    assert signed == []


@pytest.mark.asyncio
async def test_slo_ledger_records_the_amount_actually_signed():
    signed: list[PaymentDetails] = []
    with respx.mock:
        route = respx.post(CAPACITY_URL)
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": _offer(CAPACITY_URL, amount="0.03")}),
            httpx.Response(200, text="upgraded"),
        ]
        async with HardenedX402Client(
            payment_signer=_capturing_signer(signed), audit_writer=NullAuditWriter()
        ) as c:
            decision = await _broker(c).handle_trigger(_trigger())
    assert decision.action == "paid"
    # The broker authorised up to 0.10; the server asked for and was paid 0.03.
    assert decision.amount_usd == pytest.approx(0.03)
    assert decision.receipt is not None and decision.receipt.amount_usd == pytest.approx(0.03)
