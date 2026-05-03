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
# Minimum-safe versions per PRESIDIO-REQ.md REQ-6. Bumped when a CVE / security
# advisory lands or when the upstream project marks a version as vulnerable.
# Keys are PyPI distribution names; values are the lowest version known not to
# carry an unfixed advisory at the time of this release.
_KNOWN_VULNERABLE: dict[str, str] = {
    "httpx": "0.27.0",
    "presidio-analyzer": "2.2.362",
    "presidio-anonymizer": "2.2.362",
    "cryptography": "46.0.6",
}


def _on_import_audit() -> None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            from packaging.version import InvalidVersion as _InvalidVersion
            from packaging.version import Version as _Version
        except ImportError:  # pragma: no cover - packaging ships with pip
            _Version = None  # noqa: N806 - aliasing imported class symbol
            # _InvalidVersion is unreachable on the fallback path: line 124's
            # `if _Version is None: continue` short-circuits before any code
            # that would reference it. Omitted here.

        issues: list[str] = []
        for pkg, min_safe in _KNOWN_VULNERABLE.items():
            try:
                ver = version(pkg)
            except PackageNotFoundError:
                issues.append(f"{pkg} is not installed")
                continue
            if _Version is None:
                logger.debug("Dependency present (version compare unavailable): %s==%s", pkg, ver)
                continue
            try:
                if _Version(ver) < _Version(min_safe):
                    issues.append(
                        f"{pkg}=={ver} is below minimum-safe version {min_safe} "
                        "(see PRESIDIO-REQ §REQ-6)"
                    )
                else:
                    logger.debug("Dependency OK: %s==%s (>= %s)", pkg, ver, min_safe)
            except _InvalidVersion:
                logger.debug("Dependency version unparseable: %s==%s", pkg, ver)

        if issues:
            for issue in issues:
                logger.warning("[PRESIDIO AUDIT] %s", issue)
        else:
            logger.info("[PRESIDIO AUDIT] All x402 dependencies present at minimum-safe versions")

    except Exception:
        logger.debug("Dependency audit skipped")

    logger.info("Presidio hardening applied — presidio-hardened-x402 %s", __version__)


_on_import_audit()
