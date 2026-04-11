"""Multi-party authorization (MPA) engine for high-value x402 payments.

Enforces n-of-m approval requirements before large payments are executed.
Two approval modes are supported:

- **webhook**: Approval requests are sent to configured HTTP endpoints (POST).
  Each endpoint must return JSON ``{"approved": bool, "approver_id": "..."}``.
  Approvals are collected in parallel; the engine waits for *threshold* approvals
  within the configured timeout.

- **crypto**: Each approver pre-computes an HMAC-SHA256 countersignature over
  the canonical payment fingerprint using a shared secret. The caller provides
  the collected signatures as ``dict[approver_id, hex_signature]``. The engine
  verifies each signature against the configured shared secret and counts valid
  ones.

Usage (webhook mode)::

    from presidio_x402 import HardenedX402Client
    from presidio_x402.mpa import MPAConfig, MPAApproverConfig, MPAEngine

    mpa = MPAEngine(MPAConfig(
        threshold=2,
        min_amount_usd=1.00,
        approvers=[
            MPAApproverConfig("alice", mode="webhook",
                              webhook_url="https://approvals.internal/alice"),
            MPAApproverConfig("bob", mode="webhook",
                              webhook_url="https://approvals.internal/bob"),
            MPAApproverConfig("charlie", mode="webhook",
                              webhook_url="https://approvals.internal/charlie"),
        ],
    ))

    client = HardenedX402Client(payment_signer=signer, mpa_engine=mpa)

Usage (crypto mode)::

    import hashlib
    import hmac

    mpa = MPAEngine(MPAConfig(
        threshold=2,
        min_amount_usd=1.00,
        approvers=[
            MPAApproverConfig("alice", mode="crypto", shared_secret=b"alice-secret"),
            MPAApproverConfig("bob", mode="crypto", shared_secret=b"bob-secret"),
        ],
    ))

    # Collect countersignatures out-of-band; pass in kwargs:
    response = await client.get(url, mpa_signatures={
        "alice": hmac.new(b"alice-secret", payload, hashlib.sha256).hexdigest(),
        "bob":   hmac.new(b"bob-secret",   payload, hashlib.sha256).hexdigest(),
    })
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import httpx

from .exceptions import MPADeniedError, MPATimeoutError
from .replay_guard import compute_fingerprint

if TYPE_CHECKING:
    from ._types import PaymentDetails

logger = logging.getLogger("presidio_x402.mpa")


@dataclass(frozen=True)
class MPAApproverConfig:
    """Configuration for a single MPA approver.

    Parameters
    ----------
    approver_id:
        Unique identifier for this approver (embedded in audit events).
    mode:
        ``"webhook"`` — HTTP POST to ``webhook_url``.
        ``"crypto"`` — HMAC-SHA256 countersignature verified against ``shared_secret``.
    webhook_url:
        Approval webhook endpoint (required for ``mode="webhook"``).
    shared_secret:
        HMAC-SHA256 shared secret in bytes (required for ``mode="crypto"``).
    """

    approver_id: str
    mode: Literal["webhook", "crypto"]
    webhook_url: str | None = None
    shared_secret: bytes | None = None


@dataclass
class MPAConfig:
    """Configuration for the multi-party authorization engine.

    Parameters
    ----------
    threshold:
        Number of approvals required (*n* in *n*-of-*m*). Must be ≥ 1 and
        ≤ the number of configured approvers.
    approvers:
        List of :class:`MPAApproverConfig` objects (the *m* in *n*-of-*m*).
    min_amount_usd:
        Payments below this USD amount are exempt from MPA (default: ``0.0``,
        meaning all payments require MPA if any approvers are configured).
    timeout_seconds:
        Maximum wait time for webhook approvals (default: ``30.0`` seconds).
    """

    threshold: int
    approvers: list[MPAApproverConfig] = field(default_factory=list)
    min_amount_usd: float = 0.0
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("MPAConfig.threshold must be >= 1")
        if self.threshold > len(self.approvers):
            raise ValueError(
                f"MPAConfig.threshold ({self.threshold}) cannot exceed "
                f"number of approvers ({len(self.approvers)})"
            )


@dataclass(frozen=True)
class ApprovalRequest:
    """Payload sent to webhook approvers."""

    request_id: str
    resource_url: str
    pay_to: str
    amount: str
    currency: str
    network: str
    amount_usd: float


@dataclass(frozen=True)
class ApprovalResponse:
    """Response from a single approver."""

    approver_id: str
    approved: bool
    reason: str | None = None


def _canonical_payload(details: PaymentDetails, amount_usd: float) -> bytes:
    """Build a deterministic canonical bytes payload for HMAC countersignature."""
    canonical = json.dumps(
        {
            "resource_url": details.resource_url,
            "pay_to": details.pay_to,
            "amount": details.amount,
            "currency": details.currency,
            "network": details.network,
            "deadline_seconds": details.deadline_seconds,
            "amount_usd": f"{amount_usd:.6f}",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return canonical.encode()


class MPAEngine:
    """Multi-party authorization engine for high-value x402 payments.

    Collects *n*-of-*m* approvals before a payment is submitted. Supports
    webhook (async HTTP) and cryptographic countersignature (HMAC-SHA256) modes.

    Parameters
    ----------
    config:
        :class:`MPAConfig` specifying threshold, approvers, and timeout.
    httpx_client:
        Optional :class:`httpx.AsyncClient` reused for webhook requests. If
        not provided, a new client is created with the configured timeout.
    """

    def __init__(
        self,
        config: MPAConfig,
        *,
        httpx_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._httpx = httpx_client or httpx.AsyncClient(timeout=config.timeout_seconds)

    async def request_approval(
        self,
        details: PaymentDetails,
        amount_usd: float,
        *,
        provided_signatures: dict[str, str] | None = None,
    ) -> None:
        """Request multi-party approval for a payment.

        Payments below ``config.min_amount_usd`` are approved immediately
        without contacting any approvers.

        Parameters
        ----------
        details:
            Payment details (post-PII-redaction).
        amount_usd:
            Payment amount in USD.
        provided_signatures:
            For ``crypto``-mode approvers: mapping of
            ``approver_id`` → hex-encoded HMAC-SHA256 countersignature.
            Signatures are verified against each approver's ``shared_secret``.

        Raises
        ------
        MPADeniedError
            Fewer than ``config.threshold`` approvals were collected.
        MPATimeoutError
            Webhook approvals were not received within ``config.timeout_seconds``.
        """
        if amount_usd < self.config.min_amount_usd:
            logger.debug(
                "MPA skipped: amount %.4f USD below threshold %.4f USD",
                amount_usd,
                self.config.min_amount_usd,
            )
            return

        webhook_approvers = [a for a in self.config.approvers if a.mode == "webhook"]
        crypto_approvers = [a for a in self.config.approvers if a.mode == "crypto"]

        approved_ids: set[str] = set()

        # ------------------------------------------------------------------
        # 1. Crypto mode: verify pre-collected HMAC countersignatures
        # ------------------------------------------------------------------
        if crypto_approvers:
            payload = _canonical_payload(details, amount_usd)
            sigs = provided_signatures or {}
            for approver in crypto_approvers:
                sig = sigs.get(approver.approver_id)
                if not sig:
                    continue
                if approver.shared_secret is None:
                    logger.warning(
                        "MPA crypto approver %s has no shared_secret configured",
                        approver.approver_id,
                    )
                    continue
                expected = hmac.new(approver.shared_secret, payload, hashlib.sha256).hexdigest()
                if hmac.compare_digest(expected, sig.lower()):
                    approved_ids.add(approver.approver_id)
                    logger.info("MPA crypto approval verified: %s", approver.approver_id)
                else:
                    logger.warning(
                        "MPA crypto signature invalid for approver %s", approver.approver_id
                    )

        # ------------------------------------------------------------------
        # 2. Webhook mode: send parallel HTTP approval requests
        # ------------------------------------------------------------------
        remaining = self.config.threshold - len(approved_ids)
        if webhook_approvers and remaining > 0:
            request_id = compute_fingerprint(
                resource_url=details.resource_url,
                pay_to=details.pay_to,
                amount=details.amount,
                currency=details.currency,
                deadline_seconds=details.deadline_seconds,
            )[:16]
            request_data = ApprovalRequest(
                request_id=request_id,
                resource_url=details.resource_url,
                pay_to=details.pay_to,
                amount=details.amount,
                currency=details.currency,
                network=details.network,
                amount_usd=amount_usd,
            )
            try:
                responses = await asyncio.wait_for(
                    self._collect_webhook_approvals(webhook_approvers, request_data),
                    timeout=self.config.timeout_seconds,
                )
                for resp in responses:
                    if resp.approved:
                        approved_ids.add(resp.approver_id)
            except asyncio.TimeoutError as exc:
                logger.warning(
                    "MPA webhook timeout after %.1fs; collected %d/%d approvals",
                    self.config.timeout_seconds,
                    len(approved_ids),
                    self.config.threshold,
                )
                raise MPATimeoutError(
                    f"MPA approval timed out after {self.config.timeout_seconds}s "
                    f"({len(approved_ids)}/{self.config.threshold} approvals received)",
                    approvals_received=len(approved_ids),
                    threshold=self.config.threshold,
                ) from exc

        # ------------------------------------------------------------------
        # 3. Evaluate result
        # ------------------------------------------------------------------
        if len(approved_ids) < self.config.threshold:
            logger.warning(
                "MPA denied: %d/%d required approvals (approvers: %s, approved: %s)",
                len(approved_ids),
                self.config.threshold,
                [a.approver_id for a in self.config.approvers],
                sorted(approved_ids),
            )
            raise MPADeniedError(
                f"Multi-party authorization denied: {len(approved_ids)} of "
                f"{self.config.threshold} required approvals received",
                approvals_received=len(approved_ids),
                threshold=self.config.threshold,
            )

        logger.info(
            "MPA approved: %d/%d approvals from %s",
            len(approved_ids),
            self.config.threshold,
            sorted(approved_ids),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _collect_webhook_approvals(
        self,
        approvers: list[MPAApproverConfig],
        request_data: ApprovalRequest,
    ) -> list[ApprovalResponse]:
        """Send approval requests to all webhook approvers in parallel."""
        tasks = [self._request_single_approval(a, request_data) for a in approvers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        responses: list[ApprovalResponse] = []
        for result in results:
            if isinstance(result, ApprovalResponse):
                responses.append(result)
            else:
                logger.warning("MPA webhook approver returned exception: %s", result)
        return responses

    async def _request_single_approval(
        self,
        approver: MPAApproverConfig,
        request_data: ApprovalRequest,
    ) -> ApprovalResponse:
        """Send a single webhook approval request and parse the response."""
        payload: dict[str, Any] = {
            "request_id": request_data.request_id,
            "resource_url": request_data.resource_url,
            "pay_to": request_data.pay_to,
            "amount": request_data.amount,
            "currency": request_data.currency,
            "network": request_data.network,
            "amount_usd": request_data.amount_usd,
        }
        try:
            resp = await self._httpx.post(
                approver.webhook_url,  # type: ignore[arg-type]
                json=payload,
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return ApprovalResponse(
                approver_id=approver.approver_id,
                approved=bool(data.get("approved", False)),
                reason=data.get("reason"),
            )
        except Exception as exc:
            logger.warning("MPA webhook error for %s: %s", approver.approver_id, exc)
            return ApprovalResponse(
                approver_id=approver.approver_id,
                approved=False,
                reason=f"webhook error: {exc}",
            )
