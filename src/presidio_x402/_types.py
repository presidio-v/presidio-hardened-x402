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
