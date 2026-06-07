"""Sink-level secret redaction for the ``presidio_x402`` logger.

The gateway, audit log, replay guard, and MPA engine all emit structured log
events, and integrator code logs through child loggers of ``presidio_x402``.
Manual redaction at individual call sites is insufficient: a single ``logger``
call that interpolates a wallet key, bearer token, or signed ``X-PAYMENT`` token
would leak it to whatever sink the deployment has configured (stdout, files, a
SIEM forwarder).

This module installs a :class:`logging.Filter` on the ``presidio_x402`` logger at
package import time so the "secrets never reach the log sink" guarantee is
enforced for *every* record on that logger and its children — not just the calls
that remember to redact. This mirrors the family pattern established in
``presidio_angellist.hardening`` (family audit recommendation R2, 2026-06-06).

Note: this does **not** touch the tamper-evident audit trail. ``audit_log`` writes
JSON-L through its own file/stream writers, not through the ``logging`` module, so
the HMAC chain and payment records are unaffected.
"""

from __future__ import annotations

import logging
import re

# Each tuple is ``(pattern, replacement)``. Patterns keep a non-secret prefix in a
# capture group so the redacted line still says *what kind* of secret was scrubbed,
# which keeps logs useful for debugging without exposing the value.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Generic provider API keys (Stripe-style, Anthropic-style).
    (re.compile(r"(sk_(?:live|test)_)[A-Za-z0-9]+"), r"\1***REDACTED***"),
    (re.compile(r"(sk-ant-)[A-Za-z0-9\-_]+"), r"\1***REDACTED***"),
    # Auth headers / query params.
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*"), r"\1***REDACTED***"),
    (re.compile(r"(access_token=)[^&\s]+"), r"\1***REDACTED***"),
    (re.compile(r"(api_key=)[^&\s]+"), r"\1***REDACTED***"),
    (re.compile(r"(Authorization:\s*)[^\r\n]+", re.IGNORECASE), r"\1***REDACTED***"),
    # x402-specific: EVM/SVM private keys and HMAC key/signature material are
    # 32-byte hex (optionally 0x-prefixed). Wallet *addresses* are 20-byte
    # (40 hex) and are intentionally not matched here — they are pseudo-public
    # and appear in allowlists and audit records by design.
    (re.compile(r"\b(0x)?[0-9a-fA-F]{64}\b"), r"\g<1>***REDACTED***"),
]


class SecretRedactor:
    """Scrubs secret-shaped substrings from a string before it reaches a sink."""

    def redact(self, text: str) -> str:
        for pattern, replacement in _SECRET_PATTERNS:
            text = pattern.sub(replacement, text)
        return text


class RedactingFilter(logging.Filter):
    """A ``logging.Filter`` that scrubs secrets from every record at the sink.

    Installed on the ``presidio_x402`` logger at import time. The filter renders
    the record (applying any ``%``-args), redacts the resulting message, stores it
    back on ``record.msg`` and clears ``record.args`` so downstream handlers only
    ever format already-redacted text.
    """

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        super().__init__()
        self._redactor = redactor or SecretRedactor()

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - never let logging crash a payment
            return True
        record.msg = self._redactor.redact(message)
        record.args = None
        return True


_NAMESPACE = "presidio_x402"


def _namespace_loggers() -> list[logging.Logger]:
    """The ``presidio_x402`` logger plus every existing logger beneath it.

    A ``logging.Filter`` attached to a parent logger is **not** applied to records
    emitted by child loggers — filters only run on the logger the record
    originates from (and on handlers along the propagation path). The library logs
    through per-module child loggers (``presidio_x402.gateway`` etc.), so the
    filter must be attached to each of them individually. All module loggers
    already exist by the time this runs because ``__init__`` imports every
    submodule before calling :func:`install_log_redaction`.
    """
    loggers = [logging.getLogger(_NAMESPACE)]
    manager = loggers[0].manager
    prefix = _NAMESPACE + "."
    for name in list(manager.loggerDict):
        if name.startswith(prefix):
            loggers.append(logging.getLogger(name))
    return loggers


def install_log_redaction(redactor: SecretRedactor | None = None) -> RedactingFilter:
    """Attach a :class:`RedactingFilter` to every ``presidio_x402`` logger.

    Idempotent and re-runnable: a single filter instance is shared across the
    namespace, and a logger that already carries it is skipped. Safe to call again
    after creating new child loggers (it will cover any not yet filtered). Returns
    the active filter.
    """
    loggers = _namespace_loggers()
    flt: RedactingFilter | None = None
    for logger in loggers:
        for existing in logger.filters:
            if isinstance(existing, RedactingFilter):
                flt = existing
                break
        if flt is not None:
            break
    if flt is None:
        flt = RedactingFilter(redactor)
    for logger in loggers:
        if not any(isinstance(f, RedactingFilter) for f in logger.filters):
            logger.addFilter(flt)
    return flt
