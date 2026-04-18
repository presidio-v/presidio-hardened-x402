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
import ipaddress
import json
import logging
import socket
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

import httpx

from .exceptions import MPADeniedError, MPATimeoutError, MPAWebhookURLError
from .replay_guard import compute_fingerprint

if TYPE_CHECKING:
    from ._types import PaymentDetails

logger = logging.getLogger("presidio_x402.mpa")

# Networks that must never be reachable by an MPA webhook — SSRF defense.
# Covers loopback, RFC1918 private ranges, link-local (incl. IMDS 169.254.169.254),
# CGNAT, and IPv6 equivalents. A webhook URL resolving into any of these is refused
# both at config time (IP literals) and at request time (post-DNS).
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::/128"),
)


def _ip_is_blocked(addr_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        return False
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _validate_webhook_url(url: str) -> None:
    """Static validation of an MPA webhook URL (called at config time).

    Enforces HTTPS-only and rejects IP-literal hosts that fall in blocked ranges.
    Hostname-based URLs are not resolved here — DNS-rebinding defense runs at
    request time in :meth:`MPAEngine._request_single_approval`.
    """
    if not url:
        raise MPAWebhookURLError("MPA webhook URL must be a non-empty string")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise MPAWebhookURLError(
            f"MPA webhook URL must use https:// (got scheme {parsed.scheme!r})"
        )
    host = parsed.hostname
    if not host:
        raise MPAWebhookURLError("MPA webhook URL must include a hostname")
    if _ip_is_blocked(host):
        raise MPAWebhookURLError(f"MPA webhook URL host {host!r} is in a blocked network range")


def _resolve_and_check_host(host: str) -> None:
    """Resolve *host* and raise if any A/AAAA record falls in a blocked range.

    Defeats DNS-rebinding attacks where a public hostname briefly resolves to
    an internal IP between config time and request time.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise MPAWebhookURLError(f"DNS resolution failed for {host!r}") from exc
    for info in infos:
        addr = info[4][0]
        if _ip_is_blocked(addr):
            raise MPAWebhookURLError(f"Host {host!r} resolves to blocked address {addr!r}")


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
        HMAC-SHA256 shared secret in bytes.

        - For ``mode="crypto"``: required — used to verify pre-collected
          countersignatures.
        - For ``mode="webhook"``: optional but strongly recommended for
          production deployments. When set, the approver's HTTP response
          **must** include an ``X-MPA-HMAC`` header containing the
          HMAC-SHA256 hex digest of the raw response body, keyed with this
          secret. Responses that omit or fail the header check are treated
          as denied. Without a secret, responses are accepted on structural
          validity alone (suitable for internal trusted networks only).
    """

    approver_id: str
    mode: Literal["webhook", "crypto"]
    webhook_url: str | None = None
    shared_secret: bytes | None = None

    def __post_init__(self) -> None:
        if self.mode == "webhook":
            if not self.webhook_url:
                raise MPAWebhookURLError(
                    f"MPA approver {self.approver_id!r} in webhook mode requires webhook_url"
                )
            _validate_webhook_url(self.webhook_url)


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
    dns_rebinding_protection:
        Before every webhook request, resolve the hostname and verify no
        resolved address falls in a blocked network (RFC1918, link-local,
        loopback, IMDS, etc.). Default ``True``. Set ``False`` only in test
        fixtures that mock the HTTP transport and do not own real DNS for
        the configured approver hostnames.
    """

    threshold: int
    approvers: list[MPAApproverConfig] = field(default_factory=list)
    min_amount_usd: float = 0.0
    timeout_seconds: float = 30.0
    dns_rebinding_protection: bool = True

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
            # DNS-rebinding defense: if the URL host is a DNS name (not an IP
            # literal), re-resolve it right before sending and refuse any
            # resolved address that falls in a blocked network.
            if self.config.dns_rebinding_protection:
                host = urlparse(approver.webhook_url or "").hostname or ""
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    if host:
                        _resolve_and_check_host(host)
            resp = await self._httpx.post(
                approver.webhook_url,  # type: ignore[arg-type]
                json=payload,
            )
            resp.raise_for_status()

            # Verify response HMAC if the approver has a shared secret configured.
            # The approver must include X-MPA-HMAC: <hex(HMAC-SHA256(secret, body))>.
            if approver.shared_secret is not None:
                header_hmac = resp.headers.get("X-MPA-HMAC", "")
                expected_hmac = hmac.new(
                    approver.shared_secret, resp.content, hashlib.sha256
                ).hexdigest()
                if not header_hmac or not hmac.compare_digest(expected_hmac, header_hmac.lower()):
                    logger.warning(
                        "MPA webhook response HMAC invalid for approver %s "
                        "(header %s, expected %s…); treating as denied",
                        approver.approver_id,
                        repr(header_hmac[:8] + "…") if header_hmac else "missing",
                        expected_hmac[:8],
                    )
                    return ApprovalResponse(
                        approver_id=approver.approver_id,
                        approved=False,
                        reason="response HMAC verification failed",
                    )

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
