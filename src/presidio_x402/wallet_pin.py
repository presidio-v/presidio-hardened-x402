# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Pay-to pinning — trust-on-first-use detection of recipient-wallet rotation.

The static per-origin allowlist (``trusted_wallets``) is the strong control: the
operator states which wallets an origin may name and anything else is rejected.
It only covers origins the operator has enumerated. For every other origin the
client signs whatever ``pay_to`` the 402 challenge carries, so a recipient that
changes between one challenge and the next — a compromised resource server, a
DNS/MITM swap that only starts after the first successful payment, or an
endpoint that simply rotates its address per request — passes through silently.

Independent measurement of the live catalogues (probe402, MCRI #001, 21–31
August 2026) found 33 of 6,835 quoted endpoints changing their payment address
between observations, one of them on nearly every probe. A static allowlist
cannot be maintained against that population; this module records the first
``pay_to`` observed per ``(origin, network)`` and reports every later
divergence.

Semantics
---------
- First observation pins ``pay_to`` and emits ``WALLET_PINNED``.
- A later challenge naming the same ``pay_to`` passes silently.
- A later challenge naming a different ``pay_to`` emits ``WALLET_ROTATED`` and,
  under ``wallet_pinning="block"``, raises :class:`WalletRotationError` before
  signing. Under ``"warn"`` the payment proceeds.
- The pin is **never** advanced automatically. A rotating endpoint therefore
  produces one ``WALLET_ROTATED`` record per challenge, which is the signal an
  operator wants in the audit trail; accepting a new address is an explicit
  operator step (:meth:`WalletPinStore.pin`).
- Origins covered by ``trusted_wallets`` are skipped: an explicit allowlist is
  the stronger statement and may legitimately name several wallets.

Trust-on-first-use is exactly that: a challenge that is already hostile on
first contact pins the hostile address. For origins whose recipient you know,
use ``trusted_wallets``; pinning is the net under everything else.

Backends mirror :class:`~presidio_x402.replay_guard.ReplayGuard`: in-memory
(per-process) by default, Redis (``redis_url``) for a shared pin table across
replicas. Pins carry no TTL unless one is given — a pin that silently expires
would let a rotation land in the gap.
"""

from __future__ import annotations

import logging
import threading

from .exceptions import ConfigurationError
from .replay_guard import _NAMESPACE_RE

logger = logging.getLogger("presidio_x402.wallet_pin")


def pin_key(origin: str, network: str) -> str:
    """Canonical pin key: origin as given by ``resource_origin`` + lower-cased network.

    Keyed on network as well as origin because a resource server can
    legitimately name a different recipient per rail (an EVM address on Base,
    a Solana address on SVM); collapsing those onto one key would report every
    rail switch as a rotation.
    """
    return f"{origin.rstrip('/')}|{network.strip().lower()}"


class _MemoryPinStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pins: dict[str, str] = {}

    def observe(self, key: str, pay_to: str, ttl: int | None) -> str | None:
        """Pin *pay_to* under *key* if unpinned; return the pinned value (or None if new)."""
        with self._lock:
            current = self._pins.get(key)
            if current is None:
                self._pins[key] = pay_to
                return None
            return current

    def set(self, key: str, pay_to: str, ttl: int | None) -> None:
        with self._lock:
            self._pins[key] = pay_to

    def get(self, key: str) -> str | None:
        with self._lock:
            return self._pins.get(key)

    def delete(self, key: str) -> None:
        with self._lock:
            self._pins.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._pins.clear()


class _RedisPinStore:
    def __init__(self, redis_url: str, *, namespace: str | None = None) -> None:
        try:
            import redis

            self._client = redis.from_url(redis_url, decode_responses=True)
        except ImportError as exc:
            raise ImportError(
                "Redis backend requires: pip install presidio-hardened-x402[redis]"
            ) from exc
        self._prefix = (
            f"presidio_x402:wallet_pin:{namespace}:" if namespace else "presidio_x402:wallet_pin:"
        )

    def observe(self, key: str, pay_to: str, ttl: int | None) -> str | None:
        # SET NX is atomic: exactly one of two concurrent first observations
        # pins, the other reads the winner back and is judged against it.
        if self._client.set(self._prefix + key, pay_to, ex=ttl, nx=True) is not None:
            return None
        return self._client.get(self._prefix + key)

    def set(self, key: str, pay_to: str, ttl: int | None) -> None:
        self._client.set(self._prefix + key, pay_to, ex=ttl)

    def get(self, key: str) -> str | None:
        return self._client.get(self._prefix + key)

    def delete(self, key: str) -> None:
        self._client.delete(self._prefix + key)

    def clear(self) -> None:
        keys = self._client.keys(self._prefix + "*")
        if keys:
            self._client.delete(*keys)


class WalletPinStore:
    """First-seen ``pay_to`` per ``(origin, network)``.

    Parameters
    ----------
    redis_url:
        If provided, pins live in Redis and are shared across processes.
        Otherwise they are per-process and lost on restart.
    namespace:
        Optional per-tenant namespace for the Redis key prefix (same rules as
        :class:`~presidio_x402.replay_guard.ReplayGuard`).
    ttl:
        Optional pin lifetime in seconds. ``None`` (default) pins never expire.
        Prefer never: an expired pin re-enters trust-on-first-use, and the
        next challenge — hostile or not — becomes the new baseline.
    """

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        namespace: str | None = None,
        ttl: int | None = None,
    ) -> None:
        if namespace is not None and not _NAMESPACE_RE.match(namespace):
            raise ConfigurationError(
                f"invalid wallet-pin namespace {namespace!r}: must match [A-Za-z0-9_.-]+"
            )
        if ttl is not None and ttl <= 0:
            raise ConfigurationError("wallet-pin ttl must be a positive number of seconds")
        self.ttl = ttl
        if redis_url:
            self._store: _MemoryPinStore | _RedisPinStore = _RedisPinStore(
                redis_url, namespace=namespace
            )
            logger.info("WalletPinStore initialized with Redis backend")
        else:
            self._store = _MemoryPinStore()
            logger.debug("WalletPinStore initialized with in-memory backend")

    def observe(self, origin: str, network: str, pay_to: str) -> str | None:
        """Record *pay_to* as the pin for ``(origin, network)`` if none exists.

        Returns ``None`` when this observation created the pin, otherwise the
        previously pinned address (lower-cased). The caller compares; the store
        never overwrites on observe.
        """
        return self._store.observe(pin_key(origin, network), pay_to.lower(), self.ttl)

    def pinned(self, origin: str, network: str) -> str | None:
        """The pinned ``pay_to`` for ``(origin, network)``, or ``None``."""
        return self._store.get(pin_key(origin, network))

    def pin(self, origin: str, network: str, pay_to: str) -> None:
        """Explicitly (re)pin — the operator accepting a rotation."""
        self._store.set(pin_key(origin, network), pay_to.lower(), self.ttl)
        logger.info("Wallet pin set for %s on %s", origin, network)

    def forget(self, origin: str, network: str) -> None:
        """Drop the pin so the next challenge re-enters trust-on-first-use."""
        self._store.delete(pin_key(origin, network))

    def reset(self) -> None:
        """Clear every pin (useful in tests)."""
        self._store.clear()
