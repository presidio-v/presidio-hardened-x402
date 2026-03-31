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
import logging
import secrets
import threading
import time

from .exceptions import ReplayDetectedError

logger = logging.getLogger("presidio_x402.replay_guard")

# A random per-process key for the HMAC — prevents cross-process fingerprint
# collision attacks while still allowing in-memory deduplication.
_PROCESS_KEY = secrets.token_bytes(32)


def compute_fingerprint(
    resource_url: str,
    pay_to: str,
    amount: str,
    currency: str,
    deadline_seconds: int,
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
    """
    canonical = "|".join([resource_url, pay_to, amount, currency, str(deadline_seconds)])
    return hmac.new(_PROCESS_KEY, canonical.encode(), hashlib.sha256).hexdigest()


class _MemoryStore:
    """In-memory TTL store for payment fingerprints."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, float] = {}  # fingerprint → expiry timestamp

    def exists(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            return key in self._store

    def set(self, key: str, ttl: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            self._store[key] = now + ttl

    def _evict(self, now: float) -> None:
        expired = [k for k, exp in self._store.items() if exp <= now]
        for k in expired:
            del self._store[k]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


class _RedisStore:
    """Redis-backed TTL store for payment fingerprints."""

    def __init__(self, redis_url: str) -> None:
        try:
            import redis

            self._client = redis.from_url(redis_url, decode_responses=True)
        except ImportError as exc:
            raise ImportError(
                "Redis backend requires: pip install presidio-hardened-x402[redis]"
            ) from exc
        self._prefix = "presidio_x402:replay:"

    def exists(self, key: str) -> bool:
        return bool(self._client.exists(self._prefix + key))

    def set(self, key: str, ttl: int) -> None:
        self._client.set(self._prefix + key, "1", ex=ttl)

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
    """

    def __init__(self, ttl: int = 300, *, redis_url: str | None = None) -> None:
        self.ttl = ttl
        if redis_url:
            self._store: _MemoryStore | _RedisStore = _RedisStore(redis_url)
            logger.info("ReplayGuard initialized with Redis backend")
        else:
            self._store = _MemoryStore()
            logger.debug("ReplayGuard initialized with in-memory backend (TTL=%ds)", ttl)

    def check_and_record(self, fingerprint: str) -> None:
        """Check whether *fingerprint* is a replay; record it if not.

        Raises :class:`~presidio_x402.exceptions.ReplayDetectedError` if the
        fingerprint was seen within the TTL window. Otherwise, records the
        fingerprint and returns normally.
        """
        if self._store.exists(fingerprint):
            logger.warning("Replay detected: fingerprint %s...", fingerprint[:16])
            raise ReplayDetectedError(
                f"Duplicate payment detected (fingerprint: {fingerprint[:16]}…)",
                fingerprint=fingerprint,
            )
        self._store.set(fingerprint, self.ttl)
        logger.debug("Replay guard: new fingerprint recorded %s...", fingerprint[:16])

    def reset(self) -> None:
        """Clear all recorded fingerprints (useful in tests)."""
        self._store.clear()
