# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Shared data types for presidio-hardened-x402."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class PaymentDetails:
    """Payment metadata extracted from an x402 402 response.

    All string fields may contain PII before passing through PIIFilter.
    """

    resource_url: str
    """The URL of the resource being paid for (may contain PII)."""

    pay_to: str
    """Recipient wallet address (EVM/SVM/etc.)."""

    amount: str
    """Payment amount as a decimal string (e.g., "0.01")."""

    currency: str
    """Token symbol or identifier (e.g., "USDC")."""

    network: str
    """Blockchain network identifier (e.g., "base-mainnet", "base-sepolia")."""

    deadline_seconds: int
    """Payment must be submitted within this many seconds."""

    description: str = ""
    """Human-readable description of the resource (may contain PII)."""

    reason: str = ""
    """Optional payment reason field (may contain PII)."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Arbitrary extra metadata from the 402 response."""


@dataclass
class PaymentResponse:
    """Signed payment token ready to submit in the X-PAYMENT header."""

    token: str
    """Signed payment token (e.g., base64-encoded EIP-712 signature)."""

    details: PaymentDetails
    """The payment details that were signed."""


@dataclass(frozen=True)
class SettlementReceipt:
    """On-chain settlement facts observed by the *client* after a paid retry.

    The x402 settlement is executed by the facilitator on the payee side; the
    paying client only ever sees what the resource server echoes back on the
    paid response (``PAYMENT-RESPONSE`` / ``X-PAYMENT-RESPONSE`` /
    ``X-PAYMENT-RECEIPT``). That echo carries the transaction hash and the
    network — it does **not** carry a block number or a log index, so those two
    fields are ``None`` unless the server volunteered them.

    This is the honest half of the correlation input: everything here was
    observed on the wire. Completing :attr:`block_number` and :attr:`log_index`
    is an operator step (a chain/indexer lookup keyed by :attr:`tx_hash`) — see
    :mod:`presidio_x402.treasury_binding`, which requires the completed tuple
    before it will sign a ``settlement-ref@1``.
    """

    network: str
    """The rail's own network identifier, verbatim as observed (e.g. ``"base-sepolia"``)."""

    chain: str | None = None
    """CAIP-2 chain id (e.g. ``"eip155:84532"``), or ``None`` if unmappable."""

    tx_hash: str | None = None
    """Settlement transaction hash, verbatim as observed."""

    block_number: int | None = None
    """Block height — ``None`` unless the server volunteered it (usually it does not)."""

    log_index: int | None = None
    """Transfer-log index within the block — ``None`` unless volunteered."""

    payer: str | None = None
    """Payer address as reported by the facilitator (may be absent)."""

    success: bool = False
    """The facilitator's own settlement outcome flag. ``False`` is not an error
    here — an unsuccessful settlement is a fact worth recording."""

    observed_at: str = ""
    """RFC3339 UTC timestamp at which the client parsed the receipt."""

    receipt_hash: str | None = None
    """``sha256:<64hex>`` over the raw receipt header bytes, binding these parsed
    facts to the exact transport bytes they came from (the header itself is not
    retained: it can carry a payer address and is therefore PII-adjacent)."""

    @property
    def is_complete(self) -> bool:
        """True iff this receipt alone identifies a settlement log entry.

        The ``(chain, tx_hash, block_number, log_index)`` tuple is what a
        downstream ledger needs to enforce "one settlement → one leg"; a receipt
        that lacks any part of it must be completed by the operator before it can
        be committed to.
        """
        return (
            bool(self.chain)
            and bool(self.tx_hash)
            and self.block_number is not None
            and self.log_index is not None
        )


@dataclass
class AuditEvent:
    """A single audit log entry for a payment attempt."""

    timestamp: datetime
    event_type: str
    """One of: PAYMENT_ALLOWED, PII_REDACTED, PII_BLOCKED, POLICY_BLOCKED,
    REPLAY_BLOCKED, PAYMENT_ERROR."""

    resource_url: str
    """Post-redaction resource URL."""

    amount_usd: float
    network: str
    agent_id: str | None
    outcome: str
    """One of: allowed, blocked."""

    pii_entities_found: list[str] = field(default_factory=list)
    policy_limit_usd: float | None = None
    replay_fingerprint: str | None = None
    error_message: str | None = None
    prev_entry_hmac: str | None = None
    """HMAC of the previous audit entry (for chain integrity)."""


@runtime_checkable
class PaymentSigner(Protocol):
    """Protocol for x402 payment signing implementations.

    Implementors are responsible for:
    - Creating the correct payment token format for the target network
    - Managing wallet keys securely
    - Handling network-specific signing requirements (EIP-712 for EVM, etc.)
    """

    async def sign(self, details: PaymentDetails) -> PaymentResponse:
        """Sign the payment details and return a PaymentResponse."""
        ...


@runtime_checkable
class AuditWriter(Protocol):
    """Protocol for audit event output destinations."""

    def write(self, event: AuditEvent) -> None:
        """Write a single audit event."""
        ...


@runtime_checkable
class PaymentProtocolBinding(Protocol):
    """Protocol for payment-rail bindings (v0.5.0 binding-layer refactor).

    A binding owns everything specific to one payment rail's wire format: how
    a payment requirement is signalled, how the rail's payment offer parses
    into the rail-agnostic :class:`PaymentDetails`, and how the signed token
    travels on the retried request. The screening core
    (:class:`~presidio_x402.core.ScreeningPipeline`) is reused unchanged across
    bindings. Reference implementation:
    :class:`~presidio_x402.bindings.x402.X402Binding`.
    """

    name: str
    """Short rail identifier (e.g. ``"x402"``)."""

    payment_required_status: int
    """HTTP status code signalling that payment is required (402 for x402)."""

    header_name: str
    """Header carrying the payment offer / signed token."""

    def payment_offer(self, status_code: int, headers: Any) -> str | None:
        """Extract the raw payment-offer payload from a response, or ``None``."""
        ...

    def parse_payment_required(self, offer: str) -> PaymentDetails:
        """Parse the rail's payment offer into :class:`PaymentDetails`.

        Must fail closed: any malformed offer raises the library's payment
        error rather than returning partial details.
        """
        ...

    def token_headers(self, token: str) -> dict[str, str]:
        """Headers carrying the signed payment token on the retried request."""
        ...

    # Optional (duck-typed, not part of the required surface): a binding MAY also
    # implement ``settlement_receipt(headers) -> SettlementReceipt | None`` to
    # expose the rail's settlement echo on the paid response. The gateway probes
    # for it with ``getattr`` and skips capture when absent, so third-party
    # bindings written against the pre-v0.10.0 protocol keep working unchanged.
