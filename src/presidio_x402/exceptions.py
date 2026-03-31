"""Exceptions raised by presidio-hardened-x402 security controls."""

from __future__ import annotations


class X402Error(Exception):
    """Base exception for all presidio-hardened-x402 errors."""


class X402PaymentError(X402Error):
    """Raised when the upstream payment signing or network call fails."""


class PIIBlockedError(X402Error):
    """Raised when PII is detected in payment metadata and ``pii_action='block'``."""

    def __init__(self, message: str, entities: list[str]) -> None:
        super().__init__(message)
        self.entities = entities  # list of detected entity type strings


class PolicyViolationError(X402Error):
    """Raised when a payment would violate the configured spending policy."""

    def __init__(self, message: str, *, amount_usd: float, limit_usd: float) -> None:
        super().__init__(message)
        self.amount_usd = amount_usd
        self.limit_usd = limit_usd


class ReplayDetectedError(X402Error):
    """Raised when a payment fingerprint matches a recent transaction."""

    def __init__(self, message: str, *, fingerprint: str) -> None:
        super().__init__(message)
        self.fingerprint = fingerprint
