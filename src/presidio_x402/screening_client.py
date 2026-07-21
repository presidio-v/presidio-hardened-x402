# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Remote PII screening client — call the Presidio screening service instead of
running the local :class:`~presidio_x402.pii_filter.PIIFilter`.

The client speaks the v0.4.0 wire contract (see ``plan/v040-wire-contract.md``
in the private repo). It is a drop-in replacement for
:meth:`PIIFilter.scan_payment_fields` — same signature and return shape — so the
gateway can switch between local and remote screening without branching on the
hot path.

Transport rules (v0.4.0, free tier):
  * HTTPS only for prod base URLs; ``http://`` allowed for local dev
  * ``X-API-Key`` header carries the opaque token issued by ``/v1/register``
  * 10 s total timeout (3 s connect), single retry on 5xx / network error
  * ``429`` → :class:`ScreeningRateLimitError` (with ``retry_after``)
  * ``401`` → :class:`ScreeningAuthError` (no retry)
  * repeated 5xx / network → :class:`ScreeningUnavailableError`

Typical use — supplied to :class:`~presidio_x402.HardenedX402Client` via the
``screening_client`` kwarg::

    screening = ScreeningClient(
        base_url="https://screen.presidio-group.eu",
        api_key=os.environ["PRESIDIO_SCREENING_KEY"],
    )
    client = HardenedX402Client(
        payment_signer=signer,
        screening_client=screening,
        remote_screening=True,
    )
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from .exceptions import (
    ScreeningAuthError,
    ScreeningRateLimitError,
    ScreeningUnavailableError,
)

if TYPE_CHECKING:
    from .pii_filter import EntityResult

logger = logging.getLogger("presidio_x402.screening_client")

_DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=3.0)
_RETRY_BACKOFF_SECONDS = 0.5

# Max size of a screening response body before JSON parsing. A compromised or
# misconfigured screening endpoint could otherwise return a huge body and force
# memory-heavy parsing in the agent process (F4 local audit, 2026-06-03). 1 MiB
# is far above any legitimate screening result.
_SCREENING_RESPONSE_MAX_BYTES = 1_048_576
_SCREENING_MAX_ENTITY_RESULTS = 256
_SCREENING_MAX_ENTITY_COUNT = 32
_SCREENING_MAX_REDACTED_FIELD_BYTES = 16_384
_SCREENING_MAX_ENTITY_TYPE_CHARS = 128


def _is_loopback_host(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _response_string(data: dict[str, Any], name: str, fallback: str) -> str:
    value = data.get(name, fallback)
    if not isinstance(value, str):
        raise ScreeningUnavailableError(f"Screening response field {name} must be a string")
    if len(value.encode("utf-8")) > _SCREENING_MAX_REDACTED_FIELD_BYTES:
        raise ScreeningUnavailableError(f"Screening response field {name} is too large")
    return value


def _entity_type(value: object) -> str:
    if value is None:
        return "UNKNOWN"
    if not isinstance(value, str) or not value:
        raise ScreeningUnavailableError("Screening response has invalid entity_type")
    if len(value) > _SCREENING_MAX_ENTITY_TYPE_CHARS or "\x00" in value:
        raise ScreeningUnavailableError("Screening response has invalid entity_type")
    return value


class ScreeningClient:
    """HTTPS client for the Presidio screening service.

    Parameters
    ----------
    base_url:
        Service root, e.g. ``https://screen.presidio-group.eu``. No trailing
        ``/v1`` — the client appends endpoint paths itself.
    api_key:
        Opaque token issued by ``POST /v1/register``. Sent in the ``X-API-Key``
        header on every request.
    timeout:
        Optional httpx timeout override. Defaults to 10 s total / 3 s connect.
    httpx_client:
        Optional pre-configured ``httpx.AsyncClient`` (useful for tests or for
        sharing a connection pool with the gateway).
    allow_insecure:
        Allow ``http://`` base URLs for local development. Defaults to ``False``.
        With the default, an ``http://`` ``base_url`` raises :class:`ValueError` at
        construction time so a typo cannot silently transmit the ``X-API-Key`` header
        in cleartext to a production hostname. Set to ``True`` only for ``localhost`` /
        ``127.0.0.1`` development testing.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: httpx.Timeout | float | None = None,
        httpx_client: httpx.AsyncClient | None = None,
        allow_insecure: bool = False,
    ) -> None:
        if not base_url:
            raise ValueError("ScreeningClient requires a non-empty base_url")
        if not api_key:
            raise ValueError("ScreeningClient requires a non-empty api_key")
        parsed = urlparse(base_url)
        scheme = parsed.scheme.lower()
        if scheme == "http" and not allow_insecure:
            raise ValueError(
                f"ScreeningClient base_url uses http:// ({base_url!r}); the X-API-Key "
                "header would be transmitted in cleartext. Use https:// for production, "
                "or pass allow_insecure=True to opt into plaintext for local development."
            )
        if scheme == "http" and allow_insecure:
            if not _is_loopback_host(parsed.hostname):
                raise ValueError(
                    "allow_insecure=True is limited to localhost or loopback HTTP URLs; "
                    f"got {base_url!r}"
                )
            logger.warning(
                "ScreeningClient configured with http:// base_url %r and allow_insecure=True. "
                "X-API-Key is sent in cleartext. Use only for local development.",
                base_url,
            )
        elif scheme not in {"https", "http"}:
            raise ValueError(
                f"ScreeningClient base_url must start with https:// or http://; got {base_url!r}"
            )
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout if timeout is not None else _DEFAULT_TIMEOUT
        self._owned_client = httpx_client is None
        self._httpx = httpx_client or httpx.AsyncClient(timeout=self._timeout)

    async def scan_payment_fields(
        self,
        resource_url: str,
        description: str,
        reason: str,
        *,
        entities: list[str] | None = None,
    ) -> tuple[str, str, str, list[EntityResult]]:
        """Remote equivalent of :meth:`PIIFilter.scan_payment_fields`.

        Returns ``(redacted_url, redacted_description, redacted_reason, entities)``
        where ``entities`` is a list of :class:`~presidio_x402.pii_filter.EntityResult`
        constructed from the service's ``entities_found`` array. Start/end offsets
        are not returned by the service, so they are set to ``0`` — consumers must
        not rely on them in remote-screening mode.
        """
        payload: dict[str, Any] = {
            "resource_url": resource_url,
            "description": description,
            "reason": reason,
        }
        if entities is not None:
            payload["entities"] = entities

        data = await self._post_with_retry("/v1/screen", payload)

        from .pii_filter import EntityResult

        results: list[EntityResult] = []
        entities_found = data.get("entities_found", [])
        if not isinstance(entities_found, list):
            raise ScreeningUnavailableError("Screening response has invalid entities_found shape")
        for item in entities_found:
            if not isinstance(item, dict):
                raise ScreeningUnavailableError("Screening response has invalid entity item")
            entity_type = _entity_type(item.get("entity_type", "UNKNOWN"))
            try:
                count = int(item.get("count", 1))
            except (TypeError, ValueError) as exc:
                raise ScreeningUnavailableError(
                    "Screening response has invalid entity count"
                ) from exc
            if count < 0:
                raise ScreeningUnavailableError("Screening response has negative entity count")
            if count > _SCREENING_MAX_ENTITY_COUNT:
                raise ScreeningUnavailableError("Screening response entity count too large")
            if len(results) + count > _SCREENING_MAX_ENTITY_RESULTS:
                raise ScreeningUnavailableError("Screening response includes too many entities")
            for _ in range(count):
                results.append(
                    EntityResult(
                        entity_type=entity_type,
                        start=0,
                        end=0,
                        score=1.0,
                        original_text="",
                    )
                )

        return (
            _response_string(data, "redacted_resource_url", resource_url),
            _response_string(data, "redacted_description", description),
            _response_string(data, "redacted_reason", reason),
            results,
        )

    async def aclose(self) -> None:
        if self._owned_client:
            await self._httpx.aclose()

    async def __aenter__(self) -> ScreeningClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def _post_with_retry(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        headers = {"X-API-Key": self._api_key, "Content-Type": "application/json"}

        for attempt in (1, 2):
            try:
                resp = await self._httpx.post(url, json=payload, headers=headers)
            except httpx.RequestError as exc:
                if attempt == 1:
                    await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                raise ScreeningUnavailableError(
                    f"Screening service unreachable: {type(exc).__name__}"
                ) from exc

            status = resp.status_code
            if status == 200:
                if len(resp.content) > _SCREENING_RESPONSE_MAX_BYTES:
                    raise ScreeningUnavailableError("Screening response too large")
                try:
                    data = resp.json()
                except ValueError as exc:
                    raise ScreeningUnavailableError(
                        "Screening service returned non-JSON body"
                    ) from exc
                if not isinstance(data, dict):
                    raise ScreeningUnavailableError("Screening response has invalid JSON shape")
                return data
            if status == 401:
                raise ScreeningAuthError("Screening API key rejected")
            if status == 429:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                raise ScreeningRateLimitError(
                    "Screening daily quota exceeded",
                    retry_after=retry_after,
                )
            if 500 <= status < 600:
                last_exc = ScreeningUnavailableError(f"Screening service returned HTTP {status}")
                if attempt == 1:
                    await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                raise last_exc
            # 4xx other than 401/429 — non-retriable client error
            raise ScreeningUnavailableError(f"Screening service returned unexpected HTTP {status}")

        # Unreachable — loop either returns or raises on attempt 2.
        raise ScreeningUnavailableError("Screening service retry loop exited unexpectedly")


def _parse_retry_after(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        return None
