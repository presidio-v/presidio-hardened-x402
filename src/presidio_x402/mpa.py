# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
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

    from presidio_x402.mpa import build_countersignature

    mpa = MPAEngine(MPAConfig(
        threshold=2,
        min_amount_usd=1.00,
        approvers=[
            MPAApproverConfig("alice", mode="crypto", shared_secret=b"alice-secret"),
            MPAApproverConfig("bob", mode="crypto", shared_secret=b"bob-secret"),
        ],
    ))

    # Each approver signs the payment out-of-band with build_countersignature,
    # which embeds a freshness timestamp ("<unix_ts>:<hmac_hex>"). Pass in kwargs:
    response = await client.get(url, mpa_signatures={
        "alice": build_countersignature(b"alice-secret", details, amount_usd),
        "bob":   build_countersignature(b"bob-secret",   details, amount_usd),
    })

    # Signatures older than MPAConfig.max_signature_age_seconds are rejected, so
    # they cannot be replayed once the ReplayGuard TTL has elapsed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

import httpx

from .exceptions import MPADeniedError, MPATimeoutError, MPAWebhookURLError
from .replay_guard import compute_fingerprint

if TYPE_CHECKING:
    from ._types import PaymentDetails

logger = logging.getLogger("presidio_x402.mpa")
_MPA_RESPONSE_MAX_BYTES = 1_048_576

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


async def _resolve_and_check_host(host: str, port: int = 443) -> tuple[str, ...]:
    """Resolve *host* and raise if any A/AAAA record falls in a blocked range.

    Returns the checked address set so the caller can connect to one of those
    exact IPs instead of letting the HTTP client perform a second DNS lookup.

    Resolution runs on the event loop's executor (``loop.getaddrinfo``) rather
    than the blocking ``socket.getaddrinfo``. A slow/hostile DNS authority would
    otherwise block the entire event loop — stalling all concurrent approvals —
    and the surrounding ``asyncio.wait_for`` timeout could not fire during a
    synchronous C call (F-05, 2026-06-03).
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise MPAWebhookURLError(f"DNS resolution failed for {host!r}") from exc
    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        if _ip_is_blocked(addr):
            raise MPAWebhookURLError(f"Host {host!r} resolves to blocked address {addr!r}")
        addresses.append(addr)
    if not addresses:
        raise MPAWebhookURLError(f"DNS resolution returned no addresses for {host!r}")
    return tuple(dict.fromkeys(addresses))


def _decode_chunked_body(body: bytes) -> bytes:
    chunks: list[bytes] = []
    pos = 0
    while True:
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            raise httpx.ProtocolError("Invalid chunked MPA response")
        size_line = body[pos:line_end].split(b";", 1)[0]
        try:
            size = int(size_line, 16)
        except ValueError as exc:
            raise httpx.ProtocolError("Invalid chunk size in MPA response") from exc
        pos = line_end + 2
        if size == 0:
            return b"".join(chunks)
        chunk = body[pos : pos + size]
        if len(chunk) != size:
            raise httpx.ProtocolError("Truncated chunked MPA response")
        chunks.append(chunk)
        pos += size
        if body[pos : pos + 2] != b"\r\n":
            raise httpx.ProtocolError("Invalid chunk terminator in MPA response")
        pos += 2


async def _post_pinned_https(
    url: str,
    *,
    resolved_ips: tuple[str, ...],
    content: bytes,
    headers: dict[str, str],
) -> httpx.Response:
    """POST to an already checked IP while preserving Host/SNI identity."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise httpx.InvalidURL("MPA webhook URL must include a host")
    port = parsed.port or 443
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    request = httpx.Request("POST", url)
    last_exc: BaseException | None = None
    for ip in resolved_ips:
        try:
            return await _post_pinned_https_once(
                ip=ip,
                port=port,
                server_hostname=host,
                target=target,
                request=request,
                content=content,
                headers=headers,
            )
        except Exception as exc:  # pragma: no cover - exercised by network failures
            last_exc = exc
    raise httpx.ConnectError(
        f"Unable to connect to checked MPA webhook address for {host!r}",
        request=request,
    ) from last_exc


async def _post_pinned_https_once(
    *,
    ip: str,
    port: int,
    server_hostname: str,
    target: str,
    request: httpx.Request,
    content: bytes,
    headers: dict[str, str],
) -> httpx.Response:
    context = ssl.create_default_context()
    reader, writer = await asyncio.open_connection(
        ip,
        port,
        ssl=context,
        server_hostname=server_hostname,
    )
    try:
        host_header = server_hostname if port == 443 else f"{server_hostname}:{port}"
        wire_headers = {
            "Host": host_header,
            **headers,
            "Content-Length": str(len(content)),
            "Connection": "close",
        }
        head = "\r\n".join(
            [f"POST {target} HTTP/1.1", *(f"{k}: {v}" for k, v in wire_headers.items()), "", ""]
        ).encode("ascii")
        writer.write(head + content)
        await writer.drain()

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MPA_RESPONSE_MAX_BYTES:
                raise httpx.ProtocolError("MPA webhook response too large")
            chunks.append(chunk)
    finally:
        writer.close()
        await writer.wait_closed()

    raw = b"".join(chunks)
    header_bytes, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        raise httpx.ProtocolError("Invalid MPA webhook response")
    header_lines = header_bytes.split(b"\r\n")
    status_parts = header_lines[0].decode("iso-8859-1").split(" ", 2)
    if len(status_parts) < 2 or not status_parts[1].isdigit():
        raise httpx.ProtocolError("Invalid MPA webhook status line")
    status_code = int(status_parts[1])
    response_headers: list[tuple[str, str]] = []
    for raw_line in header_lines[1:]:
        if not raw_line:
            continue
        name, sep, value = raw_line.decode("iso-8859-1").partition(":")
        if not sep:
            raise httpx.ProtocolError("Invalid MPA webhook header line")
        response_headers.append((name.strip(), value.strip()))
    parsed_headers = httpx.Headers(response_headers)
    if "chunked" in parsed_headers.get("transfer-encoding", "").lower():
        body = _decode_chunked_body(body)
    return httpx.Response(status_code, headers=parsed_headers, content=body, request=request)


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
    max_signature_age_seconds:
        Freshness window for ``crypto``-mode countersignatures (default ``300``).
        Each countersignature embeds the approver's signing timestamp; the engine
        rejects any whose timestamp is older (or further in the future) than this
        many seconds. Without it a captured valid countersignature could be
        replayed for an identical payment once the ReplayGuard TTL expires
        (CWE-294 / F-8, 2026-06-03).
    """

    threshold: int
    approvers: list[MPAApproverConfig] = field(default_factory=list)
    min_amount_usd: float = 0.0
    timeout_seconds: float = 30.0
    dns_rebinding_protection: bool = True
    max_signature_age_seconds: int = 300

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("MPAConfig.threshold must be >= 1")
        if self.threshold > len(self.approvers):
            raise ValueError(
                f"MPAConfig.threshold ({self.threshold}) cannot exceed "
                f"number of approvers ({len(self.approvers)})"
            )
        if self.max_signature_age_seconds < 1:
            raise ValueError("MPAConfig.max_signature_age_seconds must be >= 1")


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


def _canonical_payload(details: PaymentDetails, amount_usd: float, timestamp: int) -> bytes:
    """Build a deterministic canonical bytes payload for HMAC countersignature.

    The approver's signing *timestamp* is part of the signed material so the
    engine can enforce a freshness window and reject replayed signatures (F-8).
    """
    canonical = json.dumps(
        {
            "resource_url": details.resource_url,
            "pay_to": details.pay_to,
            "amount": details.amount,
            "currency": details.currency,
            "network": details.network,
            "deadline_seconds": details.deadline_seconds,
            "amount_usd": f"{amount_usd:.6f}",
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return canonical.encode()


def build_countersignature(
    shared_secret: bytes,
    details: PaymentDetails,
    amount_usd: float,
    *,
    timestamp: int | None = None,
) -> str:
    """Produce a crypto-mode MPA countersignature for *details*.

    Returns a ``"<unix_ts>:<hmac_hex>"`` string: the approver's signing
    timestamp and an HMAC-SHA256 over the canonical payment fields *including*
    that timestamp. Approvers call this; the value is passed back to the agent
    and supplied to :meth:`MPAEngine.request_approval` via
    ``provided_signatures``. The engine rejects signatures whose timestamp is
    outside ``MPAConfig.max_signature_age_seconds`` (F-8, 2026-06-03).
    """
    ts = int(time.time()) if timestamp is None else int(timestamp)
    sig = hmac.new(shared_secret, _canonical_payload(details, amount_usd, ts), hashlib.sha256)
    return f"{ts}:{sig.hexdigest()}"


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
            For ``crypto``-mode approvers: mapping of ``approver_id`` →
            ``"<unix_ts>:<hmac_hex>"`` countersignature (produced by
            :func:`build_countersignature`). Each is verified against the
            approver's ``shared_secret`` and rejected if its timestamp is outside
            ``config.max_signature_age_seconds``.

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
            sigs = provided_signatures or {}
            now = int(time.time())
            max_age = self.config.max_signature_age_seconds
            for approver in crypto_approvers:
                raw = sigs.get(approver.approver_id)
                if not raw:
                    continue
                if approver.shared_secret is None:
                    logger.warning(
                        "MPA crypto approver %s has no shared_secret configured",
                        approver.approver_id,
                    )
                    continue
                # Wire format: "<unix_ts>:<hmac_hex>" (see build_countersignature).
                ts_str, sep, hexsig = raw.partition(":")
                if not sep or not hexsig:
                    logger.warning(
                        "MPA crypto signature for %s missing timestamp prefix",
                        approver.approver_id,
                    )
                    continue
                try:
                    ts = int(ts_str)
                except ValueError:
                    logger.warning(
                        "MPA crypto signature for %s has non-integer timestamp",
                        approver.approver_id,
                    )
                    continue
                if abs(now - ts) > max_age:
                    logger.warning(
                        "MPA crypto signature for %s is stale (age %ds, max %ds) — rejected",
                        approver.approver_id,
                        now - ts,
                        max_age,
                    )
                    continue
                expected = hmac.new(
                    approver.shared_secret,
                    _canonical_payload(details, amount_usd, ts),
                    hashlib.sha256,
                ).hexdigest()
                if hmac.compare_digest(expected, hexsig.lower()):
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
                network=details.network,
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
            # Outbound request authentication. When a shared_secret is
            # configured, sign the request body with HMAC-SHA256 so the
            # approver can verify the request originated from this MPA engine
            # (closes F-B 2026-05-03 — CWE-306). Approvers receiving a missing
            # or invalid X-MPA-REQUEST-HMAC must reject the request.
            request_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if approver.shared_secret is not None:
                request_hmac = hmac.new(
                    approver.shared_secret, request_body, hashlib.sha256
                ).hexdigest()
                headers["X-MPA-REQUEST-HMAC"] = request_hmac
            else:
                logger.warning(
                    "MPA webhook approver %s has no shared_secret; outbound "
                    "request is unauthenticated. Acceptable only on a trusted "
                    "internal network — set shared_secret in production.",
                    approver.approver_id,
                )
            resolved_ips: tuple[str, ...] | None = None
            # DNS-rebinding defense: if the URL host is a DNS name (not an IP
            # literal), resolve and validate once, then connect to one of those
            # checked IPs with the original hostname preserved for SNI and Host.
            if self.config.dns_rebinding_protection:
                parsed_url = urlparse(approver.webhook_url or "")
                host = parsed_url.hostname or ""
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    if host:
                        resolved_ips = await _resolve_and_check_host(
                            host,
                            parsed_url.port or 443,
                        )
            if resolved_ips is not None:
                resp = await _post_pinned_https(
                    approver.webhook_url or "",
                    resolved_ips=resolved_ips,
                    content=request_body,
                    headers=headers,
                )
            else:
                resp = await self._httpx.post(
                    approver.webhook_url,  # type: ignore[arg-type]
                    content=request_body,
                    headers=headers,
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
