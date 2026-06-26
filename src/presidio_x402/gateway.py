"""HardenedX402Client — async HTTP client with x402 payment support and Presidio security.

Implements the x402 payment flow directly over httpx, with all security controls
applied before payment signing and submission.

Since v0.5.0 the client is a thin composition of two rail-separated parts
(session-3 T2 binding-layer refactor):

- :class:`~presidio_x402.core.ScreeningPipeline` — the rail-agnostic screening
  core (PII → trusted-wallet → policy → replay → MPA, with audit + rollback);
- :class:`~presidio_x402.bindings.x402.X402Binding` — everything x402-specific
  (402 status, ``X-PAYMENT`` header, accepts[] parsing).

Behaviour is byte-identical to v0.4.0; all previous import paths keep working.

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

import logging
from typing import TYPE_CHECKING, Any, Literal

import httpx

from .audit_log import AuditLog, NullAuditWriter
from .bindings.x402 import (
    HEADER_PAYMENT,
    PAYMENT_HEADER_MAX_BYTES,
    SUPPORTED_SCHEME,
    X402Binding,
    parse_402_header,
)
from .core import (
    SAFE_EXC_MESSAGE_MAX,
    ScreeningPipeline,
    amount_to_usd,
    resource_origin,
    safe_exc_message,
)
from .exceptions import X402PaymentError
from .pii_filter import PIIFilter
from .policy_engine import PolicyConfig, PolicyEngine
from .replay_guard import ReplayGuard

if TYPE_CHECKING:
    from ._types import (
        AuditWriter,
        PaymentDetails,
        PaymentProtocolBinding,
        PaymentResponse,
        PaymentSigner,
    )
    from .metrics import MetricsCollector
    from .mpa import MPAEngine
    from .screening_client import ScreeningClient

logger = logging.getLogger("presidio_x402.gateway")

# ---------------------------------------------------------------------------
# Back-compat aliases (pre-v0.5.0 module layout). New code should import from
# presidio_x402.bindings.x402 and presidio_x402.core instead. Kept so that the
# v0.4.0 import surface — including underscore names used in downstream test
# suites — survives the binding-layer refactor unchanged. Removal would be a
# breaking change (SEMVER.md); earliest at v1.0.0.
# ---------------------------------------------------------------------------
_HEADER_PAYMENT = HEADER_PAYMENT
_SUPPORTED_SCHEME = SUPPORTED_SCHEME
_PAYMENT_HEADER_MAX_BYTES = PAYMENT_HEADER_MAX_BYTES
_SAFE_EXC_MESSAGE_MAX = SAFE_EXC_MESSAGE_MAX
_parse_402_header = parse_402_header
_amount_to_usd = amount_to_usd
_safe_exc_message = safe_exc_message
_resource_origin = resource_origin


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
    binding:
        The :class:`~presidio_x402._types.PaymentProtocolBinding` translating
        the payment rail's wire format. Defaults to
        :class:`~presidio_x402.bindings.x402.X402Binding` (HTTP 402 +
        ``X-PAYMENT``). Supply a custom binding to reuse the screening core on
        a different payment rail.
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
        binding: PaymentProtocolBinding | None = None,
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
        self._binding = binding or X402Binding()
        # Store allowlisted wallet addresses lower-cased: EVM addresses are
        # case-insensitive (EIP-55 checksum casing is optional), so comparing
        # verbatim would reject a valid checksummed/lower-case variant and cause
        # an avoidable payment outage (F-06 local audit, 2026-06-03). pay_to is
        # lower-cased at comparison time to match.
        self._trusted_wallets: dict[str, frozenset[str]] | None = (
            {
                origin.rstrip("/"): frozenset(w.lower() for w in wallets)
                for origin, wallets in trusted_wallets.items()
            }
            if trusted_wallets is not None
            else None
        )
        # The rail-agnostic screening core shares the component instances above:
        # the client keeps direct references for back-compat introspection while
        # the pipeline owns the control-sequence logic.
        self._pipeline = ScreeningPipeline(
            pii_filter=self._pii_filter,
            policy=self._policy,
            replay=self._replay,
            audit=self._audit,
            pii_action=pii_action,
            pii_entities=pii_entities,
            mpa_engine=mpa_engine,
            metrics_collector=metrics_collector,
            trusted_wallets=self._trusted_wallets,
            screening_client=screening_client,
            remote_screening=remote_screening,
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

    def update_policy(self, policy: PolicyConfig | dict | None) -> PolicyConfig:
        """Hot-reload the spending policy used by this running client."""
        return self._policy.update_config(policy)

    # ------------------------------------------------------------------
    # Internal: request + payment-required handling (rail via binding)
    # ------------------------------------------------------------------

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send *method* request to *url*; handle payment-required responses
        with the screening pipeline and the configured rail binding."""
        # Extract MPA crypto-mode countersignatures if provided (not passed to httpx)
        mpa_signatures: dict[str, str] | None = kwargs.pop("mpa_signatures", None)

        resp = await self._httpx.request(method, url, **kwargs)

        if resp.status_code != self._binding.payment_required_status:
            return resp

        offer = self._binding.payment_offer(resp.status_code, resp.headers)  # type: ignore[arg-type]
        if not offer:
            safe_url, _ = self._pii_filter.scan_and_redact(url)
            logger.warning(
                "%s response missing %s header from %s",
                self._binding.payment_required_status,
                self._binding.header_name,
                safe_url,
            )
            return resp

        try:
            details = self._binding.parse_payment_required(offer)
        except X402PaymentError as exc:
            safe_url, _ = self._pii_filter.scan_and_redact(url)
            safe_msg, _ = self._pii_filter.scan_and_redact(safe_exc_message(exc))
            self._audit.emit(
                "PAYMENT_ERROR",
                resource_url=safe_url,
                outcome="blocked",
                error_message=safe_msg,
            )
            raise

        # Apply security controls; get (possibly modified) details + the replay
        # fingerprint back so a signing failure can roll the commit back.
        secure_details, fingerprint = await self._pipeline.apply(
            details, mpa_signatures=mpa_signatures
        )

        # Sign and retry
        try:
            payment_response = await self._invoke_signer(secure_details)
        except Exception as exc:
            # The spend + replay slot were committed before signing; a signer
            # failure means no payment was made, so release them (F-03) —
            # otherwise a hostile server inducing repeated signer failures could
            # drain the accounting budget and block legitimate retries.
            self._pipeline.rollback(
                resource_url=secure_details.resource_url,
                amount_usd=amount_to_usd(secure_details.amount, secure_details.currency),
                fingerprint=fingerprint,
            )
            safe_msg, _ = self._pii_filter.scan_and_redact(safe_exc_message(exc))
            self._audit.emit(
                "PAYMENT_ERROR",
                resource_url=secure_details.resource_url,
                amount_usd=amount_to_usd(secure_details.amount, secure_details.currency),
                network=secure_details.network,
                outcome="blocked",
                error_message=safe_msg,
            )
            # Drop the cause (F-07, 2026-06-03): a wallet/signer SDK exception can
            # carry key material, mnemonics, or raw payloads in its message and
            # traceback. Preserving it on __cause__ would leak that into any
            # caller that logs the exception chain — outside this library's
            # sanitised audit path. The truncated+redacted message is already in
            # the audit record above.
            raise X402PaymentError("Payment signing failed") from None

        # Retry request with payment token (header channel per binding)
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(self._binding.token_headers(payment_response.token))
        kwargs["headers"] = headers
        resp = await self._httpx.request(method, url, **kwargs)

        paid_usd = amount_to_usd(secure_details.amount, secure_details.currency)
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
