"""Tests for :class:`~presidio_x402.screening_client.ScreeningClient`.

Covers the v0.4.0 wire contract: happy path, 401/429 mapping, 5xx single retry,
network-error retry, and per-attempt behaviour around ``Retry-After``.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from presidio_x402.exceptions import (
    ScreeningAuthError,
    ScreeningRateLimitError,
    ScreeningUnavailableError,
)
from presidio_x402.screening_client import ScreeningClient

BASE = "https://screen.presidio-group.eu"
SCREEN_URL = f"{BASE}/v1/screen"
API_KEY = "k" * 43  # 32-byte base64url ≈ 43 chars


def _ok_body(
    redacted_url: str = "https://api.example.com/u/<EMAIL_ADDRESS>",
    redacted_desc: str = "payment for <EMAIL_ADDRESS>",
    redacted_reason: str = "",
    entities: list[dict] | None = None,
) -> dict:
    return {
        "redacted_resource_url": redacted_url,
        "redacted_description": redacted_desc,
        "redacted_reason": redacted_reason,
        "entities_found": entities
        or [
            {"entity_type": "EMAIL_ADDRESS", "field": "resource_url", "count": 1},
            {"entity_type": "EMAIL_ADDRESS", "field": "description", "count": 1},
        ],
        "screening_id": "sc_01HW8ZABCDE",
        "tier": "free",
        "audit_token": None,
        "screened_at": "2026-04-18T12:00:00.123Z",
    }


class TestInit:
    def test_requires_base_url(self) -> None:
        with pytest.raises(ValueError, match="base_url"):
            ScreeningClient(base_url="", api_key=API_KEY)

    def test_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="api_key"):
            ScreeningClient(base_url=BASE, api_key="")

    def test_base_url_trailing_slash_stripped(self) -> None:
        c = ScreeningClient(base_url=f"{BASE}/", api_key=API_KEY)
        # Not public, but the stripped prefix is what matters for URL concat.
        assert c._base_url == BASE

    def test_http_base_url_rejected_by_default(self) -> None:
        """Audit 2026-04-26 finding F4: a typo'd http:// base_url must not
        silently transmit the X-API-Key header in cleartext.
        """
        with pytest.raises(ValueError, match="cleartext|allow_insecure"):
            ScreeningClient(base_url="http://screen.presidio-group.eu", api_key=API_KEY)

    def test_http_base_url_allowed_with_allow_insecure(self) -> None:
        """allow_insecure=True opt-in is honoured for local development."""
        c = ScreeningClient(
            base_url="http://localhost:8080",
            api_key=API_KEY,
            allow_insecure=True,
        )
        assert c._base_url == "http://localhost:8080"

    def test_unknown_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="https://"):
            ScreeningClient(base_url="ftp://example.com", api_key=API_KEY)


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_200_response_returns_redacted_tuple(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(200, json=_ok_body()))
            async with ScreeningClient(BASE, API_KEY) as c:
                url, desc, reason, entities = await c.scan_payment_fields(
                    "https://api.example.com/u/alice@example.com",
                    "payment for alice@example.com",
                    "",
                )
        assert url == "https://api.example.com/u/<EMAIL_ADDRESS>"
        assert desc == "payment for <EMAIL_ADDRESS>"
        assert reason == ""
        assert len(entities) == 2
        assert all(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    @pytest.mark.asyncio
    async def test_sends_api_key_header(self) -> None:
        with respx.mock:
            route = respx.post(SCREEN_URL).mock(return_value=httpx.Response(200, json=_ok_body()))
            async with ScreeningClient(BASE, API_KEY) as c:
                await c.scan_payment_fields("https://x", "", "")
        assert route.called
        sent = route.calls.last.request
        assert sent.headers["X-API-Key"] == API_KEY
        assert sent.headers["Content-Type"].startswith("application/json")

    @pytest.mark.asyncio
    async def test_entities_allowlist_forwarded(self) -> None:
        with respx.mock:
            route = respx.post(SCREEN_URL).mock(return_value=httpx.Response(200, json=_ok_body()))
            async with ScreeningClient(BASE, API_KEY) as c:
                await c.scan_payment_fields(
                    "https://x", "", "", entities=["EMAIL_ADDRESS", "US_SSN"]
                )
        body = route.calls.last.request.read().decode()
        assert "EMAIL_ADDRESS" in body
        assert "US_SSN" in body

    @pytest.mark.asyncio
    async def test_count_expands_to_multiple_entity_results(self) -> None:
        body = _ok_body(
            entities=[{"entity_type": "EMAIL_ADDRESS", "field": "description", "count": 3}]
        )
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(200, json=body))
            async with ScreeningClient(BASE, API_KEY) as c:
                _, _, _, entities = await c.scan_payment_fields("https://x", "y", "z")
        assert len(entities) == 3


class TestErrorMapping:
    @pytest.mark.asyncio
    async def test_401_raises_screening_auth_error(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(401, json={}))
            async with ScreeningClient(BASE, API_KEY) as c:
                with pytest.raises(ScreeningAuthError):
                    await c.scan_payment_fields("https://x", "", "")

    @pytest.mark.asyncio
    async def test_401_is_not_retried(self) -> None:
        with respx.mock:
            route = respx.post(SCREEN_URL).mock(return_value=httpx.Response(401, json={}))
            async with ScreeningClient(BASE, API_KEY) as c:
                with pytest.raises(ScreeningAuthError):
                    await c.scan_payment_fields("https://x", "", "")
        assert route.call_count == 1

    @pytest.mark.asyncio
    async def test_429_raises_rate_limit_error_with_retry_after(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(
                return_value=httpx.Response(429, headers={"Retry-After": "1800"}, json={})
            )
            async with ScreeningClient(BASE, API_KEY) as c:
                with pytest.raises(ScreeningRateLimitError) as excinfo:
                    await c.scan_payment_fields("https://x", "", "")
        assert excinfo.value.retry_after == 1800

    @pytest.mark.asyncio
    async def test_429_without_retry_after_header(self) -> None:
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(429, json={}))
            async with ScreeningClient(BASE, API_KEY) as c:
                with pytest.raises(ScreeningRateLimitError) as excinfo:
                    await c.scan_payment_fields("https://x", "", "")
        assert excinfo.value.retry_after is None

    @pytest.mark.asyncio
    async def test_other_4xx_raises_unavailable(self) -> None:
        # 400 is non-retriable per contract — client surfaces as unavailable.
        with respx.mock:
            respx.post(SCREEN_URL).mock(return_value=httpx.Response(400, json={}))
            async with ScreeningClient(BASE, API_KEY) as c:
                with pytest.raises(ScreeningUnavailableError):
                    await c.scan_payment_fields("https://x", "", "")


class TestRetry:
    @pytest.mark.asyncio
    async def test_500_then_200_succeeds(self) -> None:
        with respx.mock:
            route = respx.post(SCREEN_URL)
            route.side_effect = [
                httpx.Response(500, json={}),
                httpx.Response(200, json=_ok_body()),
            ]
            async with ScreeningClient(BASE, API_KEY) as c:
                url, _, _, _ = await c.scan_payment_fields("https://x", "", "")
        assert url == "https://api.example.com/u/<EMAIL_ADDRESS>"
        assert route.call_count == 2

    @pytest.mark.asyncio
    async def test_500_twice_raises_unavailable(self) -> None:
        with respx.mock:
            route = respx.post(SCREEN_URL).mock(return_value=httpx.Response(503, json={}))
            async with ScreeningClient(BASE, API_KEY) as c:
                with pytest.raises(ScreeningUnavailableError):
                    await c.scan_payment_fields("https://x", "", "")
        assert route.call_count == 2

    @pytest.mark.asyncio
    async def test_network_error_then_200_succeeds(self) -> None:
        with respx.mock:
            route = respx.post(SCREEN_URL)
            route.side_effect = [
                httpx.ConnectError("connection refused"),
                httpx.Response(200, json=_ok_body()),
            ]
            async with ScreeningClient(BASE, API_KEY) as c:
                url, _, _, _ = await c.scan_payment_fields("https://x", "", "")
        assert url == "https://api.example.com/u/<EMAIL_ADDRESS>"
        assert route.call_count == 2

    @pytest.mark.asyncio
    async def test_network_error_twice_raises_unavailable(self) -> None:
        with respx.mock:
            route = respx.post(SCREEN_URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            async with ScreeningClient(BASE, API_KEY) as c:
                with pytest.raises(ScreeningUnavailableError):
                    await c.scan_payment_fields("https://x", "", "")
        assert route.call_count == 2
