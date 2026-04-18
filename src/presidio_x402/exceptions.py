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


class MPADeniedError(X402Error):
    """Raised when multi-party authorization is required but not approved.

    Attributes
    ----------
    approvals_received:
        Number of approvals collected before denial.
    threshold:
        Number of approvals required.
    """

    def __init__(self, message: str, *, approvals_received: int, threshold: int) -> None:
        super().__init__(message)
        self.approvals_received = approvals_received
        self.threshold = threshold


class MPATimeoutError(X402Error):
    """Raised when multi-party authorization approval collection timed out.

    Attributes
    ----------
    approvals_received:
        Number of approvals collected before timeout.
    threshold:
        Number of approvals required.
    """

    def __init__(self, message: str, *, approvals_received: int, threshold: int) -> None:
        super().__init__(message)
        self.approvals_received = approvals_received
        self.threshold = threshold


class MPAWebhookURLError(X402Error):
    """Raised when an MPA webhook URL fails SSRF safety validation.

    Applies at config time (scheme + IP-literal checks) and at request time
    (DNS-resolution check against blocked networks).
    """


class ScreeningError(X402Error):
    """Base class for remote screening-API failures."""


class ScreeningAuthError(ScreeningError):
    """Raised when the screening API rejects the API key (HTTP 401).

    Not retried — caller must obtain a new key or fall back to local screening.
    """


class ScreeningRateLimitError(ScreeningError):
    """Raised when the screening API daily quota is exhausted (HTTP 429).

    Attributes
    ----------
    retry_after:
        Seconds until the quota resets, parsed from the ``Retry-After`` header.
        ``None`` when the server did not supply the header.
    """

    def __init__(self, message: str, *, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ScreeningUnavailableError(ScreeningError):
    """Raised when the screening API is unreachable or returned a 5xx after retry."""
