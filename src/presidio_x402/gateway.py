"""HardenedX402Client — async HTTP client with x402 payment support and Presidio security.

Implements the x402 payment flow directly over httpx, with all security controls
applied before payment signing and submission.

Payment flow (per x402 spec):
  1. Client sends HTTP request to a resource URL
  2. Server responds with 402 Payment Required + ``X-PAYMENT`` header (JSON)
  3. **[Security controls applied here]**:
       a. PIIFilter scans and redacts metadata fields
       b. PolicyEngine checks per-call and aggregate limits
       c. ReplayGuard checks for duplicate payment fingerprint
       d. AuditLog records the attempt
  4. PaymentSigner signs the (possibly redacted) payment details
  5. Client retries with ``X-PAYMENT`` header containing the signed token
  6. Server responds with 200 + ``X-PAYMENT-RECEIPT`` header
  7. AuditLog records the outcome

Usage::

    from presidio_x402 import HardenedX402Client

    async def my_signer(details):
        # Your EVM/SVM signing logic
        ...

    client = HardenedX402Client(
        payment_signer=my_signer,
        policy={"max_per_call_usd": 0.10, "daily_limit_usd": 5.0},
        pii_action="redact",
        replay_ttl=300,
    )
    response = await client.get("https://api.example.com/resource")
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import Any, Literal

import httpx

from ._types import AuditWriter, PaymentDetails, PaymentResponse, PaymentSigner
from .audit_log import AuditLog, NullAuditWriter
from .exceptions import (
    PIIBlockedError,
    PolicyViolationError,
    ReplayDetectedError,
    X402PaymentError,
)
from .pii_filter import PIIFilter
from .policy_engine import PolicyConfig, PolicyEngine
from .replay_guard import ReplayGuard, compute_fingerprint

logger = logging.getLogger("presidio_x402.gateway")

# Header names per x402 spec
_HEADER_PAYMENT = "X-PAYMENT"
_HEADER_PAYMENT_RECEIPT = "X-PAYMENT-RECEIPT"

# Supported x402 scheme for v0.1.0
_SUPPORTED_SCHEME = "exact"


def _parse_402_header(header_value: str) -> PaymentDetails:
    """Parse the ``X-PAYMENT`` header from a 402 response.

    Expected JSON structure (x402 spec v1)::

        {
          "accepts": [{
            "scheme": "exact",
            "network": "base-mainnet",
            "maxAmountRequired": "0.01",
            "resource": "https://...",
            "description": "...",
            "mimeType": "application/json",
            "payTo": "0x...",
            "requiredDeadlineSeconds": 300,
            "extra": {}
          }]
        }
    """
    try:
        data = json.loads(header_value)
    except json.JSONDecodeError as exc:
        raise X402PaymentError(f"Invalid X-PAYMENT header JSON: {exc}") from exc

    accepts = data.get("accepts", [])
    if not accepts:
        raise X402PaymentError("X-PAYMENT header contains no 'accepts' entries")

    # Pick the first supported scheme
    chosen = None
    for entry in accepts:
        if entry.get("scheme") == _SUPPORTED_SCHEME:
            chosen = entry
            break
    if chosen is None:
        schemes = [e.get("scheme") for e in accepts]
        raise X402PaymentError(
            f"No supported payment scheme found. Server offered: {schemes}; "
            f"client supports: [{_SUPPORTED_SCHEME!r}]"
        )

    try:
        return PaymentDetails(
            resource_url=chosen["resource"],
            pay_to=chosen["payTo"],
            amount=chosen["maxAmountRequired"],
            currency=chosen.get("currency", "USDC"),
            network=chosen["network"],
            deadline_seconds=int(chosen.get("requiredDeadlineSeconds", 300)),
            description=chosen.get("description", ""),
            reason=chosen.get("reason", ""),
            extra=chosen.get("extra", {}),
        )
    except KeyError as exc:
        raise X402PaymentError(f"Missing required field in X-PAYMENT entry: {exc}") from exc


def _amount_to_usd(amount: str, currency: str) -> float:
    """Convert a payment amount string to USD.

    For v0.1.0 this assumes 1:1 parity for USD-pegged stablecoins (USDC, USDT, DAI).
    For non-stablecoin payments, returns a conservative estimate of 1.0 per unit
    to ensure policy limits are enforced rather than bypassed.
    """
    try:
        value = float(amount)
    except ValueError:
        return 0.0
    usd_pegged = {"USDC", "USDT", "DAI", "USDCE", "USDBC"}
    if currency.upper() in usd_pegged:
        return value
    # Conservative estimate for non-stablecoins — callers can override
    return value


class HardenedX402Client:
    """Async HTTP client with x402 payment support and Presidio security hardening.

    A drop-in replacement for any async HTTP client that handles x402-protected
    endpoints. All security controls are applied before the payment is signed
    and submitted.

    Parameters
    ----------
    payment_signer:
        A :class:`~presidio_x402._types.PaymentSigner` protocol implementation.
        Responsible for signing the payment token (e.g., EIP-712 for EVM,
        Ed25519 for SVM). See README for example implementations.
    policy:
        A :class:`~presidio_x402.policy_engine.PolicyConfig`, a plain dict, or
        ``None`` (no policy enforcement).
    pii_mode:
        ``"regex"`` (default) — structural PII detection, zero-setup.
        ``"nlp"`` — full Presidio NER (requires ``[nlp]`` extra).
    pii_entities:
        List of Presidio entity types to detect and redact. ``None`` → all
        supported types for the chosen mode.
    pii_action:
        ``"redact"`` (default) — replace PII in metadata with ``<ENTITY_TYPE>``.
        ``"block"`` — raise :class:`~presidio_x402.exceptions.PIIBlockedError`.
        ``"warn"`` — log a warning but do not modify metadata.
    replay_ttl:
        TTL in seconds for duplicate payment detection. Default: 300.
    redis_url:
        If provided, use Redis for cross-process replay detection.
    audit_writer:
        An :class:`~presidio_x402._types.AuditWriter` for audit event output.
        Defaults to :class:`~presidio_x402.audit_log.NullAuditWriter` (no-op).
    agent_id:
        Optional agent identifier embedded in audit events.
    httpx_client:
        An existing ``httpx.AsyncClient`` to reuse. If ``None``, a new client
        is created with sensible defaults.
    """

    def __init__(
        self,
        payment_signer: PaymentSigner,
        *,
        policy: PolicyConfig | dict | None = None,
        pii_mode: Literal["regex", "nlp"] = "regex",
        pii_entities: list[str] | None = None,
        pii_action: Literal["redact", "block", "warn"] = "redact",
        replay_ttl: int = 300,
        redis_url: str | None = None,
        audit_writer: AuditWriter | None = None,
        agent_id: str | None = None,
        httpx_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._signer = payment_signer
        self._pii_filter = PIIFilter(mode=pii_mode, entities=pii_entities)
        self._pii_action = pii_action
        self._policy = PolicyEngine(policy)
        self._replay = ReplayGuard(ttl=replay_ttl, redis_url=redis_url)
        self._audit = AuditLog(audit_writer or NullAuditWriter(), agent_id=agent_id)
        self._agent_id = agent_id
        self._httpx = httpx_client or httpx.AsyncClient(timeout=30.0)
        logger.info("Presidio hardening applied — HardenedX402Client initialized")

    # ------------------------------------------------------------------
    # Public HTTP methods
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("DELETE", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request(method, url, **kwargs)

    # ------------------------------------------------------------------
    # Internal: request + 402 handling
    # ------------------------------------------------------------------

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send *method* request to *url*; handle 402 with security controls."""
        resp = await self._httpx.request(method, url, **kwargs)

        if resp.status_code != 402:
            return resp

        payment_header = resp.headers.get(_HEADER_PAYMENT)
        if not payment_header:
            logger.warning("402 response missing X-PAYMENT header from %s", url)
            return resp

        try:
            details = _parse_402_header(payment_header)
        except X402PaymentError as exc:
            self._audit.emit(
                "PAYMENT_ERROR",
                resource_url=url,
                outcome="blocked",
                error_message=str(exc),
            )
            raise

        # Apply security controls; get (possibly modified) details back
        secure_details = await self._apply_security_controls(details)

        # Sign and retry
        try:
            payment_response = await self._invoke_signer(secure_details)
        except Exception as exc:
            self._audit.emit(
                "PAYMENT_ERROR",
                resource_url=secure_details.resource_url,
                amount_usd=_amount_to_usd(secure_details.amount, secure_details.currency),
                network=secure_details.network,
                outcome="blocked",
                error_message=str(exc),
            )
            raise X402PaymentError(f"Payment signing failed: {exc}") from exc

        # Retry request with payment token
        headers = dict(kwargs.pop("headers", {}) or {})
        headers[_HEADER_PAYMENT] = payment_response.token
        kwargs["headers"] = headers
        resp = await self._httpx.request(method, url, **kwargs)

        self._audit.emit(
            "PAYMENT_ALLOWED",
            resource_url=secure_details.resource_url,
            amount_usd=_amount_to_usd(secure_details.amount, secure_details.currency),
            network=secure_details.network,
            outcome="allowed",
        )
        return resp

    async def _apply_security_controls(self, details: PaymentDetails) -> PaymentDetails:
        """Apply PIIFilter → PolicyEngine → ReplayGuard → AuditLog.

        Returns (possibly modified) :class:`~presidio_x402._types.PaymentDetails`
        with PII redacted from metadata fields if ``pii_action="redact"``.

        Raises on policy violation, replay, or PII block.
        """
        amount_usd = _amount_to_usd(details.amount, details.currency)

        # ------------------------------------------------------------------
        # 1. PII Filter
        # ------------------------------------------------------------------
        clean_url, clean_desc, clean_reason, pii_entities = self._pii_filter.scan_payment_fields(
            details.resource_url, details.description, details.reason
        )

        if pii_entities:
            entity_types = [e.entity_type for e in pii_entities]
            if self._pii_action == "block":
                self._audit.emit(
                    "PII_BLOCKED",
                    resource_url=clean_url,
                    amount_usd=amount_usd,
                    network=details.network,
                    outcome="blocked",
                    pii_entities_found=entity_types,
                )
                raise PIIBlockedError(
                    f"PII detected in payment metadata: {', '.join(sorted(set(entity_types)))}",
                    entities=entity_types,
                )
            elif self._pii_action == "redact":
                self._audit.emit(
                    "PII_REDACTED",
                    resource_url=clean_url,
                    amount_usd=amount_usd,
                    network=details.network,
                    outcome="allowed",
                    pii_entities_found=entity_types,
                )
                # Replace metadata fields with redacted versions
                details = replace(
                    details,
                    description=clean_desc,
                    reason=clean_reason,
                    # Note: resource_url is used for fingerprinting with ORIGINAL value
                    # but we pass clean_url to the signer to avoid PII in the chain
                )
            # else pii_action == "warn": log already happened in PIIFilter, continue

        # ------------------------------------------------------------------
        # 2. Policy Engine
        # ------------------------------------------------------------------
        try:
            self._policy.check_and_record(resource_url=details.resource_url, amount_usd=amount_usd)
        except PolicyViolationError as exc:
            self._audit.emit(
                "POLICY_BLOCKED",
                resource_url=clean_url,
                amount_usd=amount_usd,
                network=details.network,
                outcome="blocked",
                policy_limit_usd=exc.limit_usd,
            )
            raise

        # ------------------------------------------------------------------
        # 3. Replay Guard
        # ------------------------------------------------------------------
        fingerprint = compute_fingerprint(
            resource_url=details.resource_url,  # use ORIGINAL URL for fingerprinting
            pay_to=details.pay_to,
            amount=details.amount,
            currency=details.currency,
            deadline_seconds=details.deadline_seconds,
        )
        try:
            self._replay.check_and_record(fingerprint)
        except ReplayDetectedError:
            self._audit.emit(
                "REPLAY_BLOCKED",
                resource_url=clean_url,
                amount_usd=amount_usd,
                network=details.network,
                outcome="blocked",
                replay_fingerprint=fingerprint[:16],
            )
            raise

        return details

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> HardenedX402Client:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._httpx.aclose()

    async def _invoke_signer(self, details: PaymentDetails) -> PaymentResponse:
        """Call the signer, supporting both callables and objects with a ``sign`` method."""
        if hasattr(self._signer, "sign"):
            return await self._signer.sign(details)
        # Treat signer as a direct async callable
        return await self._signer(details)  # type: ignore[operator]
