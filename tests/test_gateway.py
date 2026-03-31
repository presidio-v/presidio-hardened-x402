"""Tests for HardenedX402Client — end-to-end gateway behavior."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from presidio_x402 import HardenedX402Client
from presidio_x402._types import PaymentDetails, PaymentResponse
from presidio_x402.audit_log import NullAuditWriter
from presidio_x402.exceptions import (
    PIIBlockedError,
    PolicyViolationError,
    ReplayDetectedError,
    X402PaymentError,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

PAYMENT_DETAILS = PaymentDetails(
    resource_url="https://api.example.com/v1/data",
    pay_to="0xabcdef1234567890abcdef1234567890abcdef12",
    amount="0.01",
    currency="USDC",
    network="base-sepolia",
    deadline_seconds=300,
    description="API data access",
    reason="research",
)

PAYMENT_HEADER_VALUE = json.dumps({
    "accepts": [{
        "scheme": "exact",
        "network": "base-sepolia",
        "maxAmountRequired": "0.01",
        "resource": "https://api.example.com/v1/data",
        "description": "API data access",
        "reason": "research",
        "mimeType": "application/json",
        "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
        "requiredDeadlineSeconds": 300,
        "extra": {},
    }]
})


async def _mock_signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="mock-signed-token", details=details)  # noqa: S106


def _make_client(**kwargs) -> HardenedX402Client:
    defaults: dict = {
        "payment_signer": _mock_signer,
        "audit_writer": NullAuditWriter(),
    }
    defaults.update(kwargs)
    return HardenedX402Client(**defaults)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_402_response_returned_directly():
    """Non-402 responses are returned without touching payment logic."""
    with respx.mock:
        respx.get("https://api.example.com/free").mock(
            return_value=httpx.Response(200, text="free content")
        )
        async with _make_client() as client:
            resp = await client.get("https://api.example.com/free")
        assert resp.status_code == 200
        assert resp.text == "free content"


@pytest.mark.asyncio
async def test_402_flow_completes_with_payment():
    """A 402 response triggers payment and the retry returns 200."""
    with respx.mock:
        route = respx.get("https://api.example.com/v1/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
            httpx.Response(200, text="paid content"),
        ]
        async with _make_client() as client:
            resp = await client.get("https://api.example.com/v1/data")
        assert resp.status_code == 200
        assert resp.text == "paid content"


@pytest.mark.asyncio
async def test_payment_token_sent_in_retry_header():
    """The retry request includes the signed payment token in X-PAYMENT header."""
    captured_headers = {}

    def _capture_retry(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, text="ok")

    with respx.mock:
        route = respx.get("https://api.example.com/v1/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
            _capture_retry,
        ]
        async with _make_client() as client:
            await client.get("https://api.example.com/v1/data")

    assert "x-payment" in {k.lower() for k in captured_headers}
    assert captured_headers.get("x-payment") == "mock-signed-token"


# ---------------------------------------------------------------------------
# Missing / malformed X-PAYMENT header
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_402_without_payment_header_returned_as_is():
    """A 402 with no X-PAYMENT header is returned without raising."""
    with respx.mock:
        respx.get("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(402)
        )
        async with _make_client() as client:
            resp = await client.get("https://api.example.com/v1/data")
        assert resp.status_code == 402


@pytest.mark.asyncio
async def test_malformed_x_payment_header_raises_x402_error():
    with respx.mock:
        respx.get("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(
                402, headers={"X-PAYMENT": "not-valid-json"}
            )
        )
        async with _make_client() as client:
            with pytest.raises(X402PaymentError, match="Invalid X-PAYMENT header JSON"):
                await client.get("https://api.example.com/v1/data")


@pytest.mark.asyncio
async def test_unsupported_scheme_raises_x402_error():
    header = json.dumps({
        "accepts": [{"scheme": "unknown-scheme", "network": "base-sepolia"}]
    })
    with respx.mock:
        respx.get("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": header})
        )
        async with _make_client() as client:
            with pytest.raises(X402PaymentError, match="No supported payment scheme"):
                await client.get("https://api.example.com/v1/data")


# ---------------------------------------------------------------------------
# PII blocking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_action_block_raises_pii_blocked_error():
    """pii_action='block' raises PIIBlockedError when PII found in metadata."""
    pii_header = json.dumps({
        "accepts": [{
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": "0.01",
            "resource": "https://api.example.com/user/alice@example.com",
            "description": "Data for alice@example.com",
            "payTo": "0xabc",
            "requiredDeadlineSeconds": 300,
        }]
    })
    with respx.mock:
        respx.get("https://api.example.com/user/alice@example.com").mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": pii_header})
        )
        async with _make_client(pii_action="block") as client:
            with pytest.raises(PIIBlockedError) as exc_info:
                await client.get("https://api.example.com/user/alice@example.com")
        assert "EMAIL_ADDRESS" in exc_info.value.entities


@pytest.mark.asyncio
async def test_pii_action_redact_does_not_raise():
    """pii_action='redact' redacts PII and proceeds with payment."""
    pii_header = json.dumps({
        "accepts": [{
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": "0.01",
            "resource": "https://api.example.com/user/alice@example.com",
            "description": "user alice@example.com",
            "payTo": "0xabc",
            "requiredDeadlineSeconds": 300,
        }]
    })
    with respx.mock:
        route = respx.get("https://api.example.com/user/alice@example.com")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": pii_header}),
            httpx.Response(200, text="ok"),
        ]
        async with _make_client(pii_action="redact") as client:
            resp = await client.get("https://api.example.com/user/alice@example.com")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_policy_violation_raises_policy_violation_error():
    """Per-call policy limit blocks a payment that exceeds the limit."""
    with respx.mock:
        respx.get("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE})
        )
        async with _make_client(policy={"max_per_call_usd": 0.005}) as client:
            with pytest.raises(PolicyViolationError, match="per-call limit"):
                await client.get("https://api.example.com/v1/data")


@pytest.mark.asyncio
async def test_policy_respected_accumulates_across_calls():
    """Daily limit blocks subsequent payments after budget exhausted."""
    with respx.mock:
        route = respx.get("https://api.example.com/v1/data")
        # First call: 402 then 200; second call: 402 then blocked by policy
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
            httpx.Response(200, text="ok"),
            httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
        ]
        async with _make_client(policy={"daily_limit_usd": 0.015}) as client:
            resp = await client.get("https://api.example.com/v1/data")
            assert resp.status_code == 200
            with pytest.raises(PolicyViolationError):
                await client.get("https://api.example.com/v1/data")


# ---------------------------------------------------------------------------
# Replay detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_detection_blocks_duplicate_payment():
    """Second identical payment within TTL window raises ReplayDetectedError."""
    with respx.mock:
        route = respx.get("https://api.example.com/v1/data")
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
            httpx.Response(200, text="ok"),
            httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
        ]
        async with _make_client(replay_ttl=60) as client:
            resp = await client.get("https://api.example.com/v1/data")
            assert resp.status_code == 200
            with pytest.raises(ReplayDetectedError):
                await client.get("https://api.example.com/v1/data")


# ---------------------------------------------------------------------------
# Signer failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signer_failure_raises_x402_payment_error():
    async def failing_signer(details):
        raise RuntimeError("wallet error")

    with respx.mock:
        respx.get("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE})
        )
        async with _make_client(payment_signer=failing_signer) as client:
            with pytest.raises(X402PaymentError, match="Payment signing failed"):
                await client.get("https://api.example.com/v1/data")


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_context_manager_closes_client():
    """async with closes the underlying httpx client."""
    async with _make_client() as client:
        assert not client._httpx.is_closed
    assert client._httpx.is_closed


# ---------------------------------------------------------------------------
# HTTP method delegation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_method_works():
    with respx.mock:
        respx.post("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(200, text="posted")
        )
        async with _make_client() as client:
            resp = await client.post("https://api.example.com/v1/data")
        assert resp.status_code == 200
