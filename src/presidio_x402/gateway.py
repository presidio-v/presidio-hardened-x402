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
import math
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Literal

import httpx

from ._types import AuditWriter, PaymentDetails, PaymentResponse, PaymentSigner
from .audit_log import AuditLog, NullAuditWriter
from .exceptions import (
    MPADeniedError,
    MPATimeoutError,
    PIIBlockedError,
    PolicyViolationError,
    ReplayDetectedError,
    X402PaymentError,
)

if TYPE_CHECKING:
    from .metrics import MetricsCollector
    from .mpa import MPAEngine
    from .screening_client import ScreeningClient
from .pii_filter import PIIFilter
from .policy_engine import PolicyConfig, PolicyEngine
from .replay_guard import ReplayGuard, compute_fingerprint

logger = logging.getLogger("presidio_x402.gateway")

# Header names per x402 spec
_HEADER_PAYMENT = "X-PAYMENT"

# Supported x402 scheme for v0.1.0
_SUPPORTED_SCHEME = "exact"

# Max characters of an exception message retained in audit records. Exception
# text frequently carries fragments of the offending input (JSON snippets,
# signing-key material, wallet addresses) — truncation caps blast radius.
_SAFE_EXC_MESSAGE_MAX = 80


def _safe_exc_message(exc: BaseException, max_len: int = _SAFE_EXC_MESSAGE_MAX) -> str:
    msg = str(exc)
    if len(msg) > max_len:
        msg = msg[:max_len] + "...[truncated]"
    return msg


def _resource_origin(url: str) -> str:
    parsed = httpx.URL(url)
    return str(parsed.copy_with(path="", query=None, fragment=None)).rstrip("/")


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
        # Never embed the raw JSON (which may carry wallet/PII fragments) in
        # the message. Original cause remains on __cause__ for debugging.
        raise X402PaymentError("Invalid X-PAYMENT header JSON") from exc

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
    except KeyError:
        raise X402PaymentError("Missing required field in X-PAYMENT entry") from None


_USD_PEGGED = frozenset({"USDC", "USDT", "DAI", "USDCE", "USDBC"})


def _amount_to_usd(amount: str, currency: str) -> float:
    """Convert a payment amount string to USD.

    Supports USD-pegged stablecoins only (USDC, USDT, DAI, USDCE, USDBC).
    Non-stablecoin currencies raise :class:`X402PaymentError` because without a
    price oracle the USD value cannot be determined, and silently understating it
    would allow policy limits to be bypassed.
    """
    try:
        value = float(amount)
    except ValueError as exc:
        raise X402PaymentError(f"Invalid payment amount {amount!r}: not a numeric value") from exc
    if not math.isfinite(value) or value < 0:
        raise X402PaymentError(
            f"Invalid payment amount {amount!r}: must be a finite non-negative number. "
            "Non-finite values (nan, inf, -inf) bypass IEEE 754 comparison-based limit checks "
            "and are rejected to preserve policy enforcement integrity."
        )
    if currency.upper() not in _USD_PEGGED:
        raise X402PaymentError(
            f"Unsupported currency {currency!r} for policy enforcement. "
            f"Supported stablecoins: {sorted(_USD_PEGGED)}. "
            "For non-stablecoin payments configure a custom price oracle."
        )
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
    mpa_engine:
        Optional :class:`~presidio_x402.mpa.MPAEngine` for multi-party
        authorization of high-value payments. When set, payments above
        ``mpa_engine.config.min_amount_usd`` require n-of-m approvals before
        signing. For crypto-mode approvers, pass countersignatures as
        ``mpa_signatures`` in the request kwargs.
    metrics_collector:
        Optional :class:`~presidio_x402.metrics.MetricsCollector` for Prometheus
        metrics export. Requires ``pip install presidio-hardened-x402[prometheus]``.
    trusted_wallets:
        Optional per-origin ``pay_to`` allowlist. Maps a resource origin
        (scheme + host[:port]) to the set of wallet addresses the client is
        willing to pay for resources under that origin. When a 402 response
        names a ``pay_to`` not in the allowlist for its origin, the payment is
        blocked before signing. ``None`` (default) disables the check; an
        origin absent from the map is unrestricted. Example::

            trusted_wallets={
                "https://api.example.com": {"0xAbC...123"},
            }
    screening_client:
        Optional :class:`~presidio_x402.screening_client.ScreeningClient`.
        When combined with ``remote_screening=True``, payment-metadata PII
        scanning is offloaded to the remote Presidio screening service instead
        of running the local regex/NLP pipeline. The local ``PIIFilter`` is
        still used for defense-in-depth redaction of exception messages.
    remote_screening:
        Toggle for the remote PII path. ``False`` (default) runs the local
        :class:`PIIFilter`; ``True`` requires ``screening_client`` to be set
        and forwards payment metadata to the remote service.
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
        mpa_engine: MPAEngine | None = None,
        metrics_collector: MetricsCollector | None = None,
        trusted_wallets: dict[str, set[str]] | None = None,
        screening_client: ScreeningClient | None = None,
        remote_screening: bool = False,
    ) -> None:
        if remote_screening and screening_client is None:
            raise ValueError("remote_screening=True requires a screening_client instance")
        self._signer = payment_signer
        self._pii_filter = PIIFilter(mode=pii_mode, entities=pii_entities)
        self._pii_entities = pii_entities
        self._pii_action = pii_action
        self._screening_client = screening_client
        self._remote_screening = remote_screening
        self._policy = PolicyEngine(policy)
        self._replay = ReplayGuard(ttl=replay_ttl, redis_url=redis_url)
        self._audit = AuditLog(audit_writer or NullAuditWriter(), agent_id=agent_id)
        self._agent_id = agent_id
        self._httpx = httpx_client or httpx.AsyncClient(timeout=30.0)
        self._mpa = mpa_engine
        self._metrics = metrics_collector
        self._trusted_wallets: dict[str, frozenset[str]] | None = (
            {origin.rstrip("/"): frozenset(wallets) for origin, wallets in trusted_wallets.items()}
            if trusted_wallets is not None
            else None
        )
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
        # Extract MPA crypto-mode countersignatures if provided (not passed to httpx)
        mpa_signatures: dict[str, str] | None = kwargs.pop("mpa_signatures", None)

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
            safe_url, _ = self._pii_filter.scan_and_redact(url)
            safe_msg, _ = self._pii_filter.scan_and_redact(_safe_exc_message(exc))
            self._audit.emit(
                "PAYMENT_ERROR",
                resource_url=safe_url,
                outcome="blocked",
                error_message=safe_msg,
            )
            raise

        # Apply security controls; get (possibly modified) details back
        secure_details = await self._apply_security_controls(
            details, mpa_signatures=mpa_signatures
        )

        # Sign and retry
        try:
            payment_response = await self._invoke_signer(secure_details)
        except Exception as exc:
            safe_msg, _ = self._pii_filter.scan_and_redact(_safe_exc_message(exc))
            self._audit.emit(
                "PAYMENT_ERROR",
                resource_url=secure_details.resource_url,
                amount_usd=_amount_to_usd(secure_details.amount, secure_details.currency),
                network=secure_details.network,
                outcome="blocked",
                error_message=safe_msg,
            )
            raise X402PaymentError("Payment signing failed") from exc

        # Retry request with payment token
        headers = dict(kwargs.pop("headers", {}) or {})
        headers[_HEADER_PAYMENT] = payment_response.token
        kwargs["headers"] = headers
        resp = await self._httpx.request(method, url, **kwargs)

        paid_usd = _amount_to_usd(secure_details.amount, secure_details.currency)
        self._audit.emit(
            "PAYMENT_ALLOWED",
            resource_url=secure_details.resource_url,
            amount_usd=paid_usd,
            network=secure_details.network,
            outcome="allowed",
        )
        if self._metrics:
            self._metrics.record_payment_allowed(paid_usd)
        return resp

    async def _apply_security_controls(
        self,
        details: PaymentDetails,
        *,
        mpa_signatures: dict[str, str] | None = None,
    ) -> PaymentDetails:
        """Apply PIIFilter → PolicyEngine → ReplayGuard → MPAEngine → AuditLog.

        Returns (possibly modified) :class:`~presidio_x402._types.PaymentDetails`
        with PII redacted from metadata fields if ``pii_action="redact"``.

        Raises on policy violation, replay, PII block, or MPA denial/timeout.
        """
        amount_usd = _amount_to_usd(details.amount, details.currency)

        # Preserve the original resource_url for replay-guard fingerprinting.
        # In pii_action="redact" mode the URL gets rewritten with PII tokens
        # masked; using the redacted URL for fingerprinting would collide
        # distinct user-specific URLs (e.g. /user/alice@.../pay vs
        # /user/bob@.../pay both reduce to /user/<EMAIL_ADDRESS>/pay) and
        # produce false-positive ReplayDetectedError. Original URL is never
        # passed downstream to signer / MPA — only used for the local HMAC.
        original_resource_url = details.resource_url

        # ------------------------------------------------------------------
        # 1. PII Filter (local regex/NLP or remote screening service)
        # ------------------------------------------------------------------
        if self._remote_screening and self._screening_client is not None:
            (
                clean_url,
                clean_desc,
                clean_reason,
                pii_entities,
            ) = await self._screening_client.scan_payment_fields(
                details.resource_url,
                details.description,
                details.reason,
                entities=self._pii_entities,
            )
        else:
            clean_url, clean_desc, clean_reason, pii_entities = (
                self._pii_filter.scan_payment_fields(
                    details.resource_url, details.description, details.reason
                )
            )

        # The remote screening API only covers the three primary string fields.
        # The `extra` dict is arbitrary server-controlled JSON and must be
        # scanned locally for defense-in-depth — this closes REQ-1 against
        # malicious 402 servers that smuggle PII through the extra channel.
        clean_extra, extra_entities = self._pii_filter.scan_dict(details.extra)
        if extra_entities:
            pii_entities = list(pii_entities) + list(extra_entities)

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
                if self._metrics:
                    self._metrics.record_pii_detection(entity_types, "block")
                    self._metrics.record_payment_blocked("pii", amount_usd)
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
                if self._metrics:
                    self._metrics.record_pii_detection(entity_types, "redact")
                # Replace metadata fields with redacted versions.
                # resource_url is replaced AFTER replay-fingerprint computation
                # earlier in this function so the original URL still drives
                # deduplication; from this point on every downstream consumer
                # (signer, MPA webhooks, audit log post-event) sees clean_url.
                # The `extra` dict is also redacted in-place when PII is found
                # in any of its string values (REQ-1 — closes F-A 2026-05-03).
                details = replace(
                    details,
                    resource_url=clean_url,
                    description=clean_desc,
                    reason=clean_reason,
                    extra=clean_extra if extra_entities else details.extra,
                )
            elif self._metrics:
                # pii_action == "warn": log already happened in PIIFilter
                self._metrics.record_pii_detection(entity_types, "warn")

        # ------------------------------------------------------------------
        # 2. Trusted-wallet allowlist (pay_to substitution defence)
        # ------------------------------------------------------------------
        if self._trusted_wallets is not None:
            origin = _resource_origin(details.resource_url)
            allowed = self._trusted_wallets.get(origin)
            if allowed is not None and details.pay_to not in allowed:
                self._audit.emit(
                    "WALLET_BLOCKED",
                    resource_url=clean_url,
                    amount_usd=amount_usd,
                    network=details.network,
                    outcome="blocked",
                    error_message=f"pay_to {details.pay_to!r} not in allowlist for {origin!r}",
                )
                if self._metrics:
                    self._metrics.record_payment_blocked("wallet", amount_usd)
                raise X402PaymentError(
                    f"pay_to wallet {details.pay_to!r} not in trusted allowlist "
                    f"for origin {origin!r}"
                )

        # ------------------------------------------------------------------
        # 3. Policy Engine
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
            if self._metrics:
                self._metrics.record_policy_violation("limit_exceeded")
                self._metrics.record_payment_blocked("policy", amount_usd)
            raise

        # ------------------------------------------------------------------
        # 4. Replay Guard
        # ------------------------------------------------------------------
        fingerprint = compute_fingerprint(
            resource_url=original_resource_url,  # ORIGINAL URL — see top of method
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
            if self._metrics:
                self._metrics.record_replay_detection()
                self._metrics.record_payment_blocked("replay", amount_usd)
            raise

        # ------------------------------------------------------------------
        # 5. Multi-Party Authorization (if configured)
        # ------------------------------------------------------------------
        if self._mpa is not None:
            try:
                await self._mpa.request_approval(
                    details, amount_usd, provided_signatures=mpa_signatures
                )
                if self._metrics:
                    self._metrics.record_mpa_event("approved")
            except (MPADeniedError, MPATimeoutError) as exc:
                outcome = "timeout" if isinstance(exc, MPATimeoutError) else "denied"
                safe_msg, _ = self._pii_filter.scan_and_redact(_safe_exc_message(exc))
                self._audit.emit(
                    "MPA_BLOCKED",
                    resource_url=clean_url,
                    amount_usd=amount_usd,
                    network=details.network,
                    outcome="blocked",
                    error_message=safe_msg,
                )
                if self._metrics:
                    self._metrics.record_mpa_event(outcome)
                    self._metrics.record_payment_blocked(f"mpa_{outcome}", amount_usd)
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
