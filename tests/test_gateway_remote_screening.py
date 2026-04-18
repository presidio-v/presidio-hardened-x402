"""Gateway integration tests for ``remote_screening=True``.

Verifies that when a :class:`ScreeningClient` is supplied, the gateway offloads
payment-metadata PII scanning to the remote service and applies the returned
redactions + entity list identically to the local-filter path.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from presidio_x402 import HardenedX402Client, ScreeningClient
from presidio_x402._types import PaymentDetails, PaymentResponse
from presidio_x402.audit_log import NullAuditWriter
from presidio_x402.exceptions import (
    PIIBlockedError,
    ScreeningAuthError,
    ScreeningUnavailableError,
)

RESOURCE = "https://api.example.com/user/alice@example.com"
BASE = "https://screen.presidio-group.eu"
SCREEN_URL = f"{BASE}/v1/screen"
API_KEY = "k" * 43

PAYMENT_HEADER_VALUE = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "0.01",
                "resource": RESOURCE,
                "description": "Inference request for alice@example.com",
                "reason": "",
                "mimeType": "application/json",
                "payTo": "0xabcdef1234567890abcdef1234567890abcdef12",
                "requiredDeadlineSeconds": 300,
                "extra": {},
            }
        ]
    }
)

SCREEN_RESPONSE = {
    "redacted_resource_url": "https://api.example.com/user/<EMAIL_ADDRESS>",
    "redacted_description": "Inference request for <EMAIL_ADDRESS>",
    "redacted_reason": "",
    "entities_found": [
        {"entity_type": "EMAIL_ADDRESS", "field": "resource_url", "count": 1},
        {"entity_type": "EMAIL_ADDRESS", "field": "description", "count": 1},
    ],
    "screening_id": "sc_01HW8ZABCDE",
    "tier": "free",
    "audit_token": None,
    "screened_at": "2026-04-18T12:00:00.123Z",
}


async def _mock_signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="signed-token", details=details)  # noqa: S106


def _make_client(**kwargs) -> HardenedX402Client:
    defaults: dict = {
        "payment_signer": _mock_signer,
        "audit_writer": NullAuditWriter(),
    }
    defaults.update(kwargs)
    return HardenedX402Client(**defaults)


class TestConstructorGuards:
    def test_remote_screening_requires_client(self) -> None:
        with pytest.raises(ValueError, match="requires a screening_client"):
            _make_client(remote_screening=True)

    def test_screening_client_without_flag_is_inert(self) -> None:
        # Passing a screening_client but leaving remote_screening=False
        # keeps the local PIIFilter path active. Should not raise.
        client = _make_client(
            screening_client=ScreeningClient(BASE, API_KEY),
            remote_screening=False,
        )
        assert client._remote_screening is False


class TestRemoteScreeningHappyPath:
    @pytest.mark.asyncio
    async def test_redacts_via_service_and_completes_payment(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(200, json=SCREEN_RESPONSE))
            route = respx.get(RESOURCE)
            route.side_effect = [
                httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
                httpx.Response(200, text="paid content"),
            ]
            screening = ScreeningClient(BASE, API_KEY)
            try:
                async with _make_client(
                    screening_client=screening, remote_screening=True
                ) as client:
                    resp = await client.get(RESOURCE)
            finally:
                await screening.aclose()
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_block_mode_raises_on_remote_detected_pii(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(200, json=SCREEN_RESPONSE))
            respx.get(RESOURCE).mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE})
            )
            screening = ScreeningClient(BASE, API_KEY)
            try:
                async with _make_client(
                    screening_client=screening,
                    remote_screening=True,
                    pii_action="block",
                ) as client:
                    with pytest.raises(PIIBlockedError) as excinfo:
                        await client.get(RESOURCE)
            finally:
                await screening.aclose()
        assert "EMAIL_ADDRESS" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_forwards_entities_allowlist_to_service(self) -> None:
        with respx.mock:
            screen_route = respx.post(SCREEN_URL).mock(
                return_value=httpx.Response(200, json=SCREEN_RESPONSE)
            )
            respx.get(RESOURCE).side_effect = [
                httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE}),
                httpx.Response(200, text="ok"),
            ]
            screening = ScreeningClient(BASE, API_KEY)
            try:
                async with _make_client(
                    screening_client=screening,
                    remote_screening=True,
                    pii_entities=["EMAIL_ADDRESS", "US_SSN"],
                ) as client:
                    await client.get(RESOURCE)
            finally:
                await screening.aclose()
        sent_body = json.loads(screen_route.calls.last.request.read().decode())
        assert sent_body["entities"] == ["EMAIL_ADDRESS", "US_SSN"]


class TestRemoteScreeningFailures:
    @pytest.mark.asyncio
    async def test_service_401_surfaces_auth_error(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(401, json={}))
            respx.get(RESOURCE).mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE})
            )
            screening = ScreeningClient(BASE, API_KEY)
            try:
                async with _make_client(
                    screening_client=screening, remote_screening=True
                ) as client:
                    with pytest.raises(ScreeningAuthError):
                        await client.get(RESOURCE)
            finally:
                await screening.aclose()

    @pytest.mark.asyncio
    async def test_service_5xx_retry_exhausted_surfaces_unavailable(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(500, json={}))
            respx.get(RESOURCE).mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": PAYMENT_HEADER_VALUE})
            )
            screening = ScreeningClient(BASE, API_KEY)
            try:
                async with _make_client(
                    screening_client=screening, remote_screening=True
                ) as client:
                    with pytest.raises(ScreeningUnavailableError):
                        await client.get(RESOURCE)
            finally:
                await screening.aclose()
