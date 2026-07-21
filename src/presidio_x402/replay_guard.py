# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Replay and duplicate payment detection for x402.

Creates an HMAC-SHA256 fingerprint of the canonical payment fields and checks
whether the same payment has been submitted within the configured TTL window.

Backends:
  - In-memory (default): single-process, lost on restart — suitable for
    development and stateless agent deployments
  - Redis: cross-process, survives restarts — suitable for production deployments
    with multiple agent workers (requires ``pip install presidio-hardened-x402[redis]``)

Usage::

    guard = ReplayGuard(ttl=300)
    guard.check_and_record("fp-abc123")   # first call: OK
    guard.check_and_record("fp-abc123")   # second call: raises ReplayDetectedError
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from decimal import Decimal, InvalidOperation

from .exceptions import ConfigurationError, ReplayDetectedError

logger = logging.getLogger("presidio_x402.replay_guard")

_FINGERPRINT_KEY_ENV = "PRESIDIO_X402_FINGERPRINT_KEY"
#: Opt-in hard gate: when truthy, a missing/weak fingerprint key fails import
#: (fail-closed) instead of silently falling back to a per-process key.
_REQUIRE_FINGERPRINT_KEY_ENV = "PRESIDIO_X402_REQUIRE_FINGERPRINT_KEY"

#: Redis namespace must be a Redis-key-safe token — no ``:`` (the prefix
#: delimiter) and no glob metacharacters (``*?[]``) that the ``clear()`` KEYS
#: scan would otherwise honour.
_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _gate_or_fallback(reason: str) -> bytes:
    """Raise (fail-closed) when the operator demanded a real key, else fall back."""
    if _truthy(os.environ.get(_REQUIRE_FINGERPRINT_KEY_ENV)):
        raise ConfigurationError(
            f"{_FINGERPRINT_KEY_ENV} {reason}, but {_REQUIRE_FINGERPRINT_KEY_ENV} is set. "
            "Refusing to start with a per-process fingerprint key (fail-closed): provide a "
            "32-byte hex key shared across replicas, or unset the REQUIRE gate for dev."
        )
    return secrets.token_bytes(32)


def _load_fingerprint_key() -> bytes:
    hex_key = os.environ.get(_FINGERPRINT_KEY_ENV)
    if hex_key:
        try:
            key = bytes.fromhex(hex_key)
        except ValueError:
            logger.error(
                "%s is set but not valid hex — falling back to per-process key. "
                "Cross-process replay detection is disabled.",
                _FINGERPRINT_KEY_ENV,
            )
            return _gate_or_fallback("is set but not valid hex")
        if len(key) < 16:
            logger.error(
                "%s is shorter than 16 bytes — falling back to per-process key.",
                _FINGERPRINT_KEY_ENV,
            )
            return _gate_or_fallback("is shorter than 16 bytes")
        return key
    logger.error(
        "%s not set — replay guard uses a per-process key and will NOT detect "
        "replays across load-balanced replicas. Set this env var (32-byte hex) "
        "in all replicas to enable cross-process deduplication. This message is "
        "ERROR-level rather than WARNING because the default is silently insecure "
        "in any horizontally-scaled deployment; treat as a deployment-time defect.",
        _FINGERPRINT_KEY_ENV,
    )
    return _gate_or_fallback("is not set")


_FINGERPRINT_KEY = _load_fingerprint_key()


def _canonical_amount(amount: str) -> str:
    """Return a stable decimal string for semantically equivalent amounts."""
    try:
        value = Decimal(amount)
    except InvalidOperation as exc:
        raise ValueError(f"Invalid payment amount {amount!r}: not a decimal value") from exc
    if not value.is_finite() or value < 0:
        raise ValueError(f"Invalid payment amount {amount!r}: must be finite and non-negative")
    if value == 0:
        return "0"
    # Strip trailing zeros without Decimal.normalize(). normalize() is a *context*
    # operation bounded by the default 28-significant-digit precision, so an amount
    # longer than that was silently rounded — distinct amounts differing only past
    # the 28th digit canonicalised to the same string and therefore collided on the
    # replay fingerprint. ``amount`` arrives from the server's 402 response, so it
    # is attacker-influenced and must not be rounded. format(value, "f") is exact.
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def compute_fingerprint(
    resource_url: str,
    pay_to: str,
    amount: str,
    currency: str,
    deadline_seconds: int,
    network: str = "",
) -> str:
    """Compute a canonical HMAC-SHA256 fingerprint of the payment key fields.

    The fingerprint is a hex string. It is stable for the same logical payment
    and distinct for payments that differ in any key field.

    Parameters
    ----------
    resource_url:
        The resource URL (post-redaction is NOT used here — use the original URL
        for fingerprinting to catch duplicate payments regardless of redaction).
    pay_to:
        Recipient wallet address.
    amount:
        Payment amount as a decimal string.
    currency:
        Token symbol.
    deadline_seconds:
        Payment deadline (seconds). Payments with different deadlines are
        considered distinct to avoid false positives on retried expired payments.
    network:
        Blockchain network identifier. Included so identical payment tuples on
        different rails/chains do not collide.
    """
    # Canonicalise case-insensitive fields before serialisation. EVM addresses
    # are case-insensitive (EIP-55 checksum is optional); a server that returns
    # the same `pay_to` in mixed case across retries would otherwise produce
    # distinct fingerprints and bypass replay detection. Currency tickers and
    # network names are likewise normalised to prevent representation-level
    # bypasses, and decimal amounts are canonicalised so "1.0" and "1.00" are
    # treated as the same logical payment.
    canonical = json.dumps(
        [
            resource_url,
            pay_to.lower(),
            _canonical_amount(amount),
            currency.upper(),
            int(deadline_seconds),
            network.lower(),
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(_FINGERPRINT_KEY, canonical, hashlib.sha256).hexdigest()


class _MemoryStore:
    """In-memory TTL store for payment fingerprints."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, float] = {}  # fingerprint → expiry timestamp

    def check_and_set(self, key: str, ttl: int) -> bool:
        """Atomically record *key* if absent. Returns True if newly added."""
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            if key in self._store:
                return False
            self._store[key] = now + ttl
            return True

    def _evict(self, now: float) -> None:
        expired = [k for k, exp in self._store.items() if exp <= now]
        for k in expired:
            del self._store[k]

    def release(self, key: str) -> None:
        """Forget *key* if present (compensating rollback)."""
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


class _RedisStore:
    """Redis-backed TTL store for payment fingerprints."""

    def __init__(self, redis_url: str, *, namespace: str | None = None) -> None:
        try:
            import redis

            self._client = redis.from_url(redis_url, decode_responses=True)
        except ImportError as exc:
            raise ImportError(
                "Redis backend requires: pip install presidio-hardened-x402[redis]"
            ) from exc
        # Per-tenant isolation: distinct tenants on a shared Redis must not see or
        # evict each other's fingerprints. The namespace is folded into the key
        # prefix; ``clear()`` therefore scopes its KEYS scan to one tenant only.
        self._prefix = (
            f"presidio_x402:replay:{namespace}:" if namespace else "presidio_x402:replay:"
        )

    def check_and_set(self, key: str, ttl: int) -> bool:
        # SET NX EX is atomic on the Redis server — no TOCTOU window.
        result = self._client.set(self._prefix + key, "1", ex=ttl, nx=True)
        return result is not None

    def release(self, key: str) -> None:
        """Delete the fingerprint key (compensating rollback)."""
        self._client.delete(self._prefix + key)

    def clear(self) -> None:
        keys = self._client.keys(self._prefix + "*")
        if keys:
            self._client.delete(*keys)


class ReplayGuard:
    """Detects and blocks duplicate x402 payments.

    Parameters
    ----------
    ttl:
        Time-to-live in seconds. A payment fingerprint is remembered for this
        long after first submission. Default: 300 seconds (5 minutes).
    redis_url:
        If provided, uses a Redis backend instead of in-memory storage.
        Example: ``"redis://localhost:6379/0"``.
    namespace:
        Optional per-tenant namespace folded into the Redis key prefix, isolating
        one tenant's replay window from another's on a shared Redis. Must match
        ``[A-Za-z0-9_.-]+`` (no ``:`` delimiter, no glob metacharacters). Ignored
        by the in-memory backend, which is already per-process isolated.
    """

    def __init__(
        self,
        ttl: int = 300,
        *,
        redis_url: str | None = None,
        namespace: str | None = None,
    ) -> None:
        self.ttl = ttl
        if namespace is not None and not _NAMESPACE_RE.match(namespace):
            raise ConfigurationError(
                f"invalid replay namespace {namespace!r}: must match [A-Za-z0-9_.-]+ "
                "(no ':' delimiter or glob metacharacters, which would break key "
                "scoping and the clear() KEYS scan)"
            )
        if redis_url:
            self._store: _MemoryStore | _RedisStore = _RedisStore(redis_url, namespace=namespace)
            logger.info(
                "ReplayGuard initialized with Redis backend (namespace=%s)", namespace or "<none>"
            )
        else:
            self._store = _MemoryStore()
            logger.debug("ReplayGuard initialized with in-memory backend (TTL=%ds)", ttl)

    def check_and_record(self, fingerprint: str) -> None:
        """Check whether *fingerprint* is a replay; record it if not.

        Raises :class:`~presidio_x402.exceptions.ReplayDetectedError` if the
        fingerprint was seen within the TTL window. Otherwise, records the
        fingerprint and returns normally.
        """
        if not self._store.check_and_set(fingerprint, self.ttl):
            logger.error(
                "Replay detected: fingerprint %s...",
                fingerprint[:16],
                extra={"event": "REPLAY_DETECTED", "fingerprint": fingerprint[:16]},
            )
            raise ReplayDetectedError(
                f"Duplicate payment detected (fingerprint: {fingerprint[:16]}…)",
                fingerprint=fingerprint,
            )
        logger.debug("Replay guard: new fingerprint recorded %s...", fingerprint[:16])

    def release(self, fingerprint: str) -> None:
        """Forget a fingerprint recorded by :meth:`check_and_record`.

        Compensating rollback: when a payment passes the replay check but is
        then denied (MPA) or fails to sign, the fingerprint must be released so
        the legitimate retry of the same canonical payment is not rejected as a
        replay. This is what makes the documented MPA crypto-mode
        countersignature retry workflow work — the signature-less first attempt
        no longer poisons the retry (F-03).
        """
        self._store.release(fingerprint)
        logger.debug("Replay guard: released fingerprint %s...", fingerprint[:16])

    def reset(self) -> None:
        """Clear all recorded fingerprints (useful in tests)."""
        self._store.clear()
