# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Spending policy enforcement for x402 payment requests.

Blocks or throttles payments before execution based on configurable per-agent,
per-endpoint, and per-time-window budget limits.

Usage::

    engine = PolicyEngine(PolicyConfig(
        max_per_call_usd=0.05,
        daily_limit_usd=2.00,
        per_endpoint={"https://premium-api.io": 0.50},
        agent_id="agent-v1",
    ))
    engine.check_and_record(resource_url="https://api.example.com/data", amount_usd=0.02)
    # raises PolicyViolationError if any limit is exceeded
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from .exceptions import PolicyViolationError

logger = logging.getLogger("presidio_x402.policy_engine")


def _decimal_usd(value: float | int | str | Decimal, field_name: str) -> Decimal:
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"{field_name} must be a finite non-negative USD amount") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"{field_name} must be a finite non-negative USD amount")
    return amount


@dataclass
class PolicyConfig:
    """Spending policy configuration.

    All monetary values are in USD (converted from token amounts using
    the network's current rate at payment time — callers must pass
    ``amount_usd`` to :meth:`PolicyEngine.check_and_record`).
    """

    max_per_call_usd: float | None = None
    """Block any single payment whose amount exceeds this value."""

    daily_limit_usd: float | None = None
    """Block a payment that would push 24-hour aggregate spend over this value."""

    per_endpoint: dict[str, float] = field(default_factory=dict)
    """Per-endpoint-prefix daily limits: ``{url_prefix: limit_usd}``."""

    window_seconds: int = 86_400
    """Time window for aggregate limits (default: 24 hours)."""

    agent_id: str | None = None
    """Optional agent identifier, embedded in audit events."""

    @classmethod
    def from_dict(cls, data: dict) -> PolicyConfig:
        """Build a PolicyConfig from a plain dict (TOML-friendly)."""
        return cls(
            max_per_call_usd=data.get("max_per_call_usd"),
            daily_limit_usd=data.get("daily_limit_usd"),
            per_endpoint=data.get("per_endpoint", {}),
            window_seconds=data.get("window_seconds", 86_400),
            agent_id=data.get("agent_id"),
        )


def _coerce_config(config: PolicyConfig | dict | None) -> PolicyConfig:
    if config is None:
        return PolicyConfig()
    if isinstance(config, dict):
        return PolicyConfig.from_dict(config)
    return config


def _validate_config(config: PolicyConfig) -> None:
    if config.max_per_call_usd is not None:
        _decimal_usd(config.max_per_call_usd, "max_per_call_usd")
    if config.daily_limit_usd is not None:
        _decimal_usd(config.daily_limit_usd, "daily_limit_usd")
    for prefix, limit in config.per_endpoint.items():
        _decimal_usd(limit, f"per_endpoint[{prefix!r}]")


class _SpendLedger:
    """Thread-safe rolling time-window spend ledger."""

    def __init__(self, window_seconds: int) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        # List of (timestamp, amount_usd) pairs. Amounts are Decimal internally
        # so aggregate policy boundaries are not subject to binary float drift.
        self._entries: list[tuple[float, Decimal]] = []

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self._window
        self._entries = [(ts, amt) for ts, amt in self._entries if ts >= cutoff]

    def _total_decimal(self) -> Decimal:
        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)
            return sum((amt for _, amt in self._entries), Decimal("0"))

    def total(self) -> float:
        return float(self._total_decimal())

    def record(self, amount_usd: Decimal) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)
            self._entries.append((now, amount_usd))

    def release(self, amount_usd: Decimal) -> bool:
        """Reverse a single previously recorded *amount_usd* entry.

        Removes the most-recent entry matching the amount (the one just
        recorded). Returns True if an entry was removed. Used for compensating
        rollback when a recorded spend is later denied or fails to settle.
        """
        with self._lock:
            for i in range(len(self._entries) - 1, -1, -1):
                if self._entries[i][1] == amount_usd:
                    del self._entries[i]
                    return True
        return False

    def would_exceed(self, amount_usd: Decimal, limit_usd: Decimal) -> bool:
        return self._total_decimal() + amount_usd > limit_usd

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()

    def reconfigure_window(self, window_seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._window = window_seconds
            self._evict_stale(now)


def _endpoint_prefix_matches(prefix: str, url: str) -> bool:
    """True if *url* falls under per-endpoint *prefix* on a host/path boundary.

    Requires an exact (scheme, host[:port]) match and, when the configured
    prefix carries a path, alignment on a ``/`` segment boundary. This prevents
    prefix-confusion bypasses where a sibling host or path merely shares a
    leading substring with a trusted prefix (F-01, 2026-06-03).
    """
    p = urlsplit(prefix)
    u = urlsplit(url)
    if (p.scheme, p.netloc) != (u.scheme, u.netloc):
        return False
    base = p.path.rstrip("/")
    return base == "" or u.path == base or u.path.startswith(base + "/")


class PolicyEngine:
    """Enforces spending policy for x402 payments.

    Parameters
    ----------
    config:
        A :class:`PolicyConfig` or a plain dict (automatically converted).
    """

    def __init__(self, config: PolicyConfig | dict | None = None) -> None:
        config = _coerce_config(config)
        _validate_config(config)
        self.config = config
        self._global_ledger = _SpendLedger(config.window_seconds)
        self._endpoint_ledgers: dict[str, _SpendLedger] = {}
        self._ledger_lock = threading.Lock()
        # Serialises the check+record phase to prevent TOCTOU races where two
        # concurrent callers both pass would_exceed() then both record, pushing
        # aggregate spend over the configured limit.
        self._check_lock = threading.Lock()

    def update_config(self, config: PolicyConfig | dict | None) -> PolicyConfig:
        """Atomically replace the active policy configuration.

        Existing spend ledgers are preserved so a tighter limit immediately
        applies to the current rolling window. Changing ``window_seconds``
        updates the active ledgers and evicts entries that are stale under the
        new window.
        """
        new_config = _coerce_config(config)
        _validate_config(new_config)
        with self._check_lock:
            self.config = new_config
            self._global_ledger.reconfigure_window(new_config.window_seconds)
            with self._ledger_lock:
                for ledger in self._endpoint_ledgers.values():
                    ledger.reconfigure_window(new_config.window_seconds)
        logger.info("PolicyEngine config hot-reloaded")
        return new_config

    def _get_endpoint_ledger(self, prefix: str) -> _SpendLedger:
        with self._ledger_lock:
            if prefix not in self._endpoint_ledgers:
                self._endpoint_ledgers[prefix] = _SpendLedger(self.config.window_seconds)
            return self._endpoint_ledgers[prefix]

    def _matching_endpoint_prefix(self, resource_url: str) -> str | None:
        """Return the longest matching per_endpoint prefix, or None.

        Matching is boundary-aware: the prefix and the URL must share the same
        scheme and host exactly, and any prefix path must align on a ``/``
        boundary. A raw ``startswith`` (the prior implementation) let a hostile
        origin whose hostname merely *begins with* a trusted prefix — e.g.
        ``https://api.example.com.attacker.com`` against a configured
        ``https://api.example.com`` — inherit that endpoint's budget
        (CWE-697 / F-01, 2026-06-03). Candidates are tried longest-first so the
        most specific configured prefix wins.
        """
        candidates = sorted(self.config.per_endpoint.keys(), key=len, reverse=True)
        for prefix in candidates:
            if _endpoint_prefix_matches(prefix, resource_url):
                return prefix
        return None

    def check_and_record(
        self,
        *,
        resource_url: str,
        amount_usd: float,
    ) -> None:
        """Check all policy limits and record the spend if all pass.

        Raises :class:`~presidio_x402.exceptions.PolicyViolationError` if any
        limit would be exceeded. If all checks pass, the amount is recorded in
        the spend ledger.

        Parameters
        ----------
        resource_url:
            The URL being paid for (post-redaction is fine; only used for
            per-endpoint matching).
        amount_usd:
            The payment amount in USD.
        """
        amount_dec = _decimal_usd(amount_usd, "amount_usd")

        # All config reads and aggregate recording are performed under one lock.
        # This keeps runtime policy hot-reloads coherent with in-flight checks
        # and preserves the original TOCTOU protection for aggregate ledgers.
        with self._check_lock:
            # 1. Per-call limit
            if self.config.max_per_call_usd is not None:
                max_per_call_dec = _decimal_usd(self.config.max_per_call_usd, "max_per_call_usd")
            else:
                max_per_call_dec = None
            if max_per_call_dec is not None and amount_dec > max_per_call_dec:
                logger.warning(
                    "Policy violation: per-call limit %.4f USD, requested %.4f USD for %s",
                    self.config.max_per_call_usd,
                    amount_usd,
                    resource_url,
                )
                raise PolicyViolationError(
                    f"Payment of ${amount_usd:.4f} exceeds per-call limit of "
                    f"${self.config.max_per_call_usd:.4f}",
                    amount_usd=amount_usd,
                    limit_usd=self.config.max_per_call_usd,
                )

            # 2. Global aggregate limit
            if self.config.daily_limit_usd is not None:
                daily_limit_dec = _decimal_usd(self.config.daily_limit_usd, "daily_limit_usd")
            else:
                daily_limit_dec = None
            if daily_limit_dec is not None and self._global_ledger.would_exceed(
                amount_dec, daily_limit_dec
            ):
                current = self._global_ledger.total()
                logger.warning(
                    "Policy violation: global limit %.2f USD, current %.4f + %.4f",
                    self.config.daily_limit_usd,
                    current,
                    amount_usd,
                )
                raise PolicyViolationError(
                    f"Payment would push aggregate spend (${current:.4f} + ${amount_usd:.4f}) "
                    f"over global limit of ${self.config.daily_limit_usd:.2f}",
                    amount_usd=amount_usd,
                    limit_usd=self.config.daily_limit_usd,
                )

            # 3. Per-endpoint limit
            prefix = self._matching_endpoint_prefix(resource_url)
            if prefix is not None:
                ep_limit = self.config.per_endpoint[prefix]
                ep_limit_dec = _decimal_usd(ep_limit, f"per_endpoint[{prefix!r}]")
                ep_ledger = self._get_endpoint_ledger(prefix)
                if ep_ledger.would_exceed(amount_dec, ep_limit_dec):
                    current = ep_ledger.total()
                    logger.warning(
                        "Policy violation: endpoint limit %.2f USD for %s, current %.4f + %.4f",
                        ep_limit,
                        prefix,
                        current,
                        amount_usd,
                    )
                    raise PolicyViolationError(
                        f"Payment would push endpoint spend for {prefix!r} "
                        f"(${current:.4f} + ${amount_usd:.4f}) over limit of ${ep_limit:.2f}",
                        amount_usd=amount_usd,
                        limit_usd=ep_limit,
                    )

            # All checks passed — record atomically within the same lock acquisition
            self._global_ledger.record(amount_dec)
            if prefix is not None:
                self._get_endpoint_ledger(prefix).record(amount_dec)

        logger.debug("Policy check passed: %.4f USD for %s", amount_usd, resource_url)

    def refund(self, *, resource_url: str, amount_usd: float) -> None:
        """Reverse a spend recorded by :meth:`check_and_record`.

        Compensating rollback for a payment that passed policy but was then
        denied (MPA) or failed to sign, so the ledger only reflects payments
        that actually committed (F-03). Mirrors the global + per-endpoint
        recording done at check time, under the same serialisation lock. A
        no-op if the entry has already aged out of the window.
        """
        amount_dec = _decimal_usd(amount_usd, "amount_usd")
        with self._check_lock:
            self._global_ledger.release(amount_dec)
            prefix = self._matching_endpoint_prefix(resource_url)
            if prefix is not None:
                self._get_endpoint_ledger(prefix).release(amount_dec)

    def reset(self) -> None:
        """Reset all spend ledgers (useful in tests)."""
        with self._check_lock:
            self._global_ledger.reset()
            with self._ledger_lock:
                for ledger in self._endpoint_ledgers.values():
                    ledger.reset()
