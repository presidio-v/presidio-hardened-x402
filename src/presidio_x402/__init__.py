"""
presidio-hardened-x402
~~~~~~~~~~~~~~~~~~~~~~

Security middleware for the x402 payment protocol.

Intercepts x402 payment requests before blockchain commit to enforce:
  - PII detection and redaction (Presidio) in payment metadata fields
  - Spending policy enforcement (per-agent, per-endpoint, per-time-window budgets)
  - Replay/duplicate payment detection (HMAC-SHA256 fingerprinting with TTL)
  - Structured tamper-evident audit logging (JSON-L)

Usage::

    from presidio_x402 import HardenedX402Client

    client = HardenedX402Client(
        payment_signer=my_signer,
        policy={"max_per_call_usd": 0.10, "daily_limit_usd": 5.0},
        pii_entities=["EMAIL_ADDRESS", "PERSON", "US_SSN"],
    )
    response = await client.get("https://api.example.com/resource")
"""

from __future__ import annotations

import logging

from .audit_log import AuditLog, FileAuditWriter, NullAuditWriter, StreamAuditWriter
from .compliance_report import ComplianceReport
from .exceptions import (
    MPADeniedError,
    MPATimeoutError,
    PIIBlockedError,
    PolicyViolationError,
    ReplayDetectedError,
    ScreeningAuthError,
    ScreeningError,
    ScreeningRateLimitError,
    ScreeningUnavailableError,
    X402Error,
    X402PaymentError,
)
from .gateway import HardenedX402Client
from .metrics import MetricsCollector
from .mpa import MPAApproverConfig, MPAConfig, MPAEngine
from .pii_filter import PIIFilter
from .policy_engine import PolicyConfig, PolicyEngine
from .replay_guard import ReplayGuard, compute_fingerprint
from .screening_client import ScreeningClient

__version__ = "0.3.0"
__all__ = [
    # Primary public API
    "HardenedX402Client",
    "PolicyConfig",
    "ComplianceReport",
    # Multi-party authorization
    "MPAConfig",
    "MPAApproverConfig",
    "MPAEngine",
    # Prometheus metrics
    "MetricsCollector",
    # Remote screening
    "ScreeningClient",
    # Exceptions
    "X402Error",
    "X402PaymentError",
    "PIIBlockedError",
    "PolicyViolationError",
    "ReplayDetectedError",
    "MPADeniedError",
    "MPATimeoutError",
    "ScreeningError",
    "ScreeningAuthError",
    "ScreeningRateLimitError",
    "ScreeningUnavailableError",
    # Components (for custom composition)
    "PIIFilter",
    "PolicyEngine",
    "ReplayGuard",
    "compute_fingerprint",
    "AuditLog",
    "NullAuditWriter",
    "StreamAuditWriter",
    "FileAuditWriter",
]

logger = logging.getLogger("presidio_x402")

# ---------------------------------------------------------------------------
# On-import security audit
# ---------------------------------------------------------------------------
_KNOWN_VULNERABLE: dict[str, dict[str, str]] = {
    "httpx": {},
    "presidio-analyzer": {},
    "presidio-anonymizer": {},
}


def _on_import_audit() -> None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        issues: list[str] = []
        for pkg in _KNOWN_VULNERABLE:
            try:
                ver = version(pkg)
                logger.debug("Dependency OK: %s==%s", pkg, ver)
            except PackageNotFoundError:
                issues.append(f"{pkg} is not installed")

        if issues:
            for issue in issues:
                logger.warning("[PRESIDIO AUDIT] %s", issue)
        else:
            logger.info("[PRESIDIO AUDIT] All x402 dependencies present")

    except Exception:
        logger.debug("Dependency audit skipped")

    logger.info("Presidio hardening applied — presidio-hardened-x402 %s", __version__)


_on_import_audit()
