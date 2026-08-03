# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
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

from ._types import PaymentProtocolBinding
from .action_ref import (
    compute_action_ref,
    compute_screen_ref,
    format_action_ref_timestamp,
    format_screen_scope,
)
from .arch_translucency_adapter import ArchTranslucencyAdapter, SLOTrigger
from .audit_log import AuditLog, FileAuditWriter, NullAuditWriter, StreamAuditWriter
from .bindings.x402 import X402Binding
from .capability import (
    CAPABILITY_SCHEMA_ID,
    CapabilityError,
    Caveats,
    Grant,
    VerifiedGrantChain,
    delegate_grant,
    issue_grant,
    policy_config_from_chain,
    verify_chain,
)
from .capability_enforcer import CapabilityEnforcer, StageTiming
from .compliance_report import ComplianceReport
from .core import ScreeningPipeline
from .decision_ref import (
    PAYMENT_DECISION_SCHEMA_ID,
    ControlResults,
    DecisionRefEmitter,
    DecisionRefError,
    DecisionRefVerification,
    FileDecisionRefWriter,
    NullDecisionRefWriter,
    build_decision_evidence,
    build_payment_decision_content,
    compute_decision_ref,
    f_controls,
    verify_decision_ref,
)
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
from .log_redaction import RedactingFilter, SecretRedactor, install_log_redaction
from .metrics import MetricsCollector
from .mica import OBLIGATION_MAP, EvidenceError, Obligation, build_evidence
from .mpa import MPAApproverConfig, MPAConfig, MPAEngine, build_countersignature
from .pii_filter import PROVISIONING_ENTITIES, PIIFilter
from .policy_engine import PolicyConfig, PolicyEngine
from .replay_guard import ReplayGuard, compute_fingerprint
from .screening_client import ScreeningClient
from .slo_broker import (
    CapacityProvider,
    SLOPaymentBroker,
    SLOPaymentDecision,
    UpgradeReceipt,
    X402CapacityProvider,
)
from .slo_policy import SLOPaymentPolicy
from .treasury_binding import (
    SETTLEMENT_REF_SCHEMA_ID,
    TREASURY_BUNDLE_SCHEMA_ID,
    FileSettlementWriter,
    NullSettlementWriter,
    SettlementFacts,
    TreasuryBindingError,
    export_bundle,
    verify_bundle,
)

__version__ = "0.10.0"
__all__ = [
    # Primary public API
    "HardenedX402Client",
    "PolicyConfig",
    "ComplianceReport",
    # Rail-agnostic screening core + rail bindings (v0.5.0)
    "ScreeningPipeline",
    "PaymentProtocolBinding",
    "X402Binding",
    # Capability certificates (capability-grant@1) — Pillar I
    "issue_grant",
    "delegate_grant",
    "verify_chain",
    "policy_config_from_chain",
    "VerifiedGrantChain",
    "Grant",
    "Caveats",
    "CapabilityError",
    "CAPABILITY_SCHEMA_ID",
    # Capability enforcement stage (E2 / CJ-EVAL Phase A+B) — Pillar I on the path
    "CapabilityEnforcer",
    "StageTiming",
    # MiCA/EU signed evidence (evidence-ref@1 wire format)
    "build_evidence",
    "Obligation",
    "OBLIGATION_MAP",
    "EvidenceError",
    # Decision-ref emission (payment-decision@1 in evidence-ref@1) — Pillar II
    "DecisionRefEmitter",
    "DecisionRefError",
    "DecisionRefVerification",
    "ControlResults",
    "NullDecisionRefWriter",
    "FileDecisionRefWriter",
    "build_payment_decision_content",
    "build_decision_evidence",
    "compute_decision_ref",
    "verify_decision_ref",
    "f_controls",
    "PAYMENT_DECISION_SCHEMA_ID",
    # Treasury binding (settlement-ref@1 + treasury-bundle@1) — v0.10.0
    "SettlementFacts",
    "export_bundle",
    "verify_bundle",
    "TreasuryBindingError",
    "NullSettlementWriter",
    "FileSettlementWriter",
    "SETTLEMENT_REF_SCHEMA_ID",
    "TREASURY_BUNDLE_SCHEMA_ID",
    # Multi-party authorization
    "MPAConfig",
    "MPAApproverConfig",
    "MPAEngine",
    "build_countersignature",
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
    "compute_action_ref",
    "compute_screen_ref",
    "format_action_ref_timestamp",
    "format_screen_scope",
    "AuditLog",
    "NullAuditWriter",
    "StreamAuditWriter",
    "FileAuditWriter",
    # Log-sink secret redaction
    "install_log_redaction",
    "RedactingFilter",
    "SecretRedactor",
    # Market-based SLO enforcement (v0.7.0)
    "SLOPaymentBroker",
    "SLOPaymentPolicy",
    "SLOPaymentDecision",
    "SLOTrigger",
    "ArchTranslucencyAdapter",
    "CapacityProvider",
    "X402CapacityProvider",
    "UpgradeReceipt",
    "PROVISIONING_ENTITIES",
]

logger = logging.getLogger("presidio_x402")

# Enforce sink-level secret redaction across the whole presidio_x402 logger
# namespace as soon as the package is imported (family audit rec R2, 2026-06-06).
# Runs before _on_import_audit() below so even the audit's own log lines are
# filtered. All submodule loggers already exist (imported above).
install_log_redaction()

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
    "cryptography": "48.0.1",
    # CVE-2026-44843 / GHSA-pjwx-r37v-7724 — unsafe deserialization in
    # RunnableWithMessageHistory, astream_log, astream_events(version="v1").
    # 1.3.3 (1.x line) and 0.3.85 (0.3.x line) carry the fix; pinning the
    # 1.3.3 floor here is correct for our optional [langchain] extra.
    "langchain-core": "1.3.3",
}


def _on_import_audit() -> None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            from packaging.version import InvalidVersion as _InvalidVersion
            from packaging.version import Version as _Version
        except ImportError:  # pragma: no cover - packaging is a declared dependency
            # This fallback is defense-in-depth against a broken install, not a
            # supported mode: taking it silently disables every version comparison
            # below, so the dependency-CVE warning never fires. `packaging` is a
            # declared dependency precisely so this branch stays unreachable.
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
