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

PAYMENT_HEADER_VALUE = json.dumps(
    {
        "accepts": [
            {
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
            }
        ]
    }
)


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
        respx.get("https://api.example.com/v1/data").mock(return_value=httpx.Response(402))
        async with _make_client() as client:
            resp = await client.get("https://api.example.com/v1/data")
        assert resp.status_code == 402


@pytest.mark.asyncio
async def test_malformed_x_payment_header_raises_x402_error():
    with respx.mock:
        respx.get("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": "not-valid-json"})
        )
        async with _make_client() as client:
            with pytest.raises(X402PaymentError, match="Invalid X-PAYMENT header JSON"):
                await client.get("https://api.example.com/v1/data")


@pytest.mark.asyncio
async def test_unsupported_scheme_raises_x402_error():
    header = json.dumps({"accepts": [{"scheme": "unknown-scheme", "network": "base-sepolia"}]})
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
    pii_header = json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": "0.01",
                    "resource": "https://api.example.com/user/alice@example.com",
                    "description": "Data for alice@example.com",
                    "payTo": "0xabc",
                    "requiredDeadlineSeconds": 300,
                }
            ]
        }
    )
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
    pii_header = json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": "0.01",
                    "resource": "https://api.example.com/user/alice@example.com",
                    "description": "user alice@example.com",
                    "payTo": "0xabc",
                    "requiredDeadlineSeconds": 300,
                }
            ]
        }
    )
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


# ---------------------------------------------------------------------------
# Amount validation — F1 regression (audit 2026-04-26)
# ---------------------------------------------------------------------------


def _amount_header(amount: str) -> str:
    return json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": amount,
                    "resource": "https://api.example.com/v1/data",
                    "description": "API data access",
                    "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                    "requiredDeadlineSeconds": 300,
                }
            ]
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_amount", ["nan", "NaN", "inf", "-inf", "Infinity", "-1.0"])
async def test_non_finite_or_negative_amount_rejected(bad_amount):
    """Non-finite / negative amounts must not silently bypass policy limits.

    `float("nan") > limit` is False under IEEE 754, which previously let NaN /
    inf payments pass per-call, daily, and per-endpoint comparison checks.
    Audit 2026-04-26 finding F1.
    """
    with respx.mock:
        respx.get("https://api.example.com/v1/data").mock(
            return_value=httpx.Response(402, headers={"X-PAYMENT": _amount_header(bad_amount)})
        )
        async with _make_client(policy={"max_per_call_usd": 0.01}) as client:
            with pytest.raises(X402PaymentError, match="finite non-negative"):
                await client.get("https://api.example.com/v1/data")


# ---------------------------------------------------------------------------
# resource_url redaction — F2 regression (audit 2026-04-26)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redact_strips_pii_from_resource_url_before_signer():
    """In pii_action='redact' mode, the signer must receive the redacted URL,
    not the original PII-bearing one. Audit 2026-04-26 finding F2.
    """
    captured: dict[str, PaymentDetails] = {}

    async def capturing_signer(details: PaymentDetails) -> PaymentResponse:
        captured["details"] = details
        return PaymentResponse(token="signed", details=details)  # noqa: S106

    pii_url = "https://api.example.com/user/alice@example.com/pay"
    pii_header = json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": "0.01",
                    "resource": pii_url,
                    "description": "user alice@example.com",
                    "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                    "requiredDeadlineSeconds": 300,
                }
            ]
        }
    )
    with respx.mock:
        route = respx.get(pii_url)
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": pii_header}),
            httpx.Response(200, text="ok"),
        ]
        async with _make_client(payment_signer=capturing_signer, pii_action="redact") as client:
            await client.get(pii_url)

    assert "details" in captured, "signer was not invoked"
    signed_url = captured["details"].resource_url
    assert "alice@example.com" not in signed_url, signed_url
    # Some redaction marker must be present — exact token depends on PIIFilter
    # config (e.g. "<REDACTED>" for resource_url path, "<EMAIL_ADDRESS>" elsewhere).
    assert "<" in signed_url and ">" in signed_url, signed_url


# ---------------------------------------------------------------------------
# extra-field PII redaction — F-A regression (audit 2026-05-03)
# ---------------------------------------------------------------------------


def _header_with_extra(extra: dict) -> str:
    return json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": "0.01",
                    "resource": "https://api.example.com/v1/data",
                    "description": "API data access",
                    "reason": "research",
                    "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                    "requiredDeadlineSeconds": 300,
                    "extra": extra,
                }
            ]
        }
    )


@pytest.mark.asyncio
async def test_extra_field_pii_redacted_before_signer():
    """PII smuggled in the extra dict must not reach the signer (F-A 2026-05-03)."""
    captured: dict[str, PaymentDetails] = {}

    async def capturing_signer(details: PaymentDetails) -> PaymentResponse:
        captured["details"] = details
        return PaymentResponse(token="signed", details=details)  # noqa: S106

    url = "https://api.example.com/v1/data"
    header = _header_with_extra({"user_id": "alice@example.com", "tier": "gold"})
    with respx.mock:
        route = respx.get(url)
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": header}),
            httpx.Response(200, text="ok"),
        ]
        async with _make_client(payment_signer=capturing_signer, pii_action="redact") as client:
            await client.get(url)

    signed_extra = captured["details"].extra
    assert "alice@example.com" not in str(signed_extra), signed_extra
    assert signed_extra["tier"] == "gold"


@pytest.mark.asyncio
async def test_extra_field_pii_blocks_when_pii_action_block():
    """PII in extra triggers PIIBlockedError when pii_action='block' (F-A 2026-05-03)."""
    url = "https://api.example.com/v1/data"
    header = _header_with_extra({"customer_email": "victim@example.com"})
    with respx.mock:
        respx.get(url).mock(return_value=httpx.Response(402, headers={"X-PAYMENT": header}))
        async with _make_client(pii_action="block") as client:
            with pytest.raises(PIIBlockedError):
                await client.get(url)


@pytest.mark.asyncio
async def test_extra_field_without_pii_passes_through_unchanged():
    """An extra dict with no PII is forwarded verbatim — no false redaction."""
    captured: dict[str, PaymentDetails] = {}

    async def capturing_signer(details: PaymentDetails) -> PaymentResponse:
        captured["details"] = details
        return PaymentResponse(token="signed", details=details)  # noqa: S106

    url = "https://api.example.com/v1/data"
    header = _header_with_extra({"tier": "gold", "rate_limit": 100})
    with respx.mock:
        route = respx.get(url)
        route.side_effect = [
            httpx.Response(402, headers={"X-PAYMENT": header}),
            httpx.Response(200, text="ok"),
        ]
        async with _make_client(payment_signer=capturing_signer) as client:
            await client.get(url)

    assert captured["details"].extra == {"tier": "gold", "rate_limit": 100}
