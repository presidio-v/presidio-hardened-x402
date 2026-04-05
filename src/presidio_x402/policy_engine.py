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
from urllib.parse import urlparse

from .exceptions import PolicyViolationError

logger = logging.getLogger("presidio_x402.policy_engine")


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


class _SpendLedger:
    """Thread-safe rolling time-window spend ledger."""

    def __init__(self, window_seconds: int) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        # List of (timestamp, amount_usd) pairs
        self._entries: list[tuple[float, float]] = []

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self._window
        self._entries = [(ts, amt) for ts, amt in self._entries if ts >= cutoff]

    def total(self) -> float:
        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)
            return sum(amt for _, amt in self._entries)

    def record(self, amount_usd: float) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)
            self._entries.append((now, amount_usd))

    def would_exceed(self, amount_usd: float, limit_usd: float) -> bool:
        return self.total() + amount_usd > limit_usd

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()


class PolicyEngine:
    """Enforces spending policy for x402 payments.

    Parameters
    ----------
    config:
        A :class:`PolicyConfig` or a plain dict (automatically converted).
    """

    def __init__(self, config: PolicyConfig | dict | None = None) -> None:
        if config is None:
            config = PolicyConfig()
        elif isinstance(config, dict):
            config = PolicyConfig.from_dict(config)
        self.config = config
        self._global_ledger = _SpendLedger(config.window_seconds)
        self._endpoint_ledgers: dict[str, _SpendLedger] = {}
        self._ledger_lock = threading.Lock()

    def _get_endpoint_ledger(self, prefix: str) -> _SpendLedger:
        with self._ledger_lock:
            if prefix not in self._endpoint_ledgers:
                self._endpoint_ledgers[prefix] = _SpendLedger(self.config.window_seconds)
            return self._endpoint_ledgers[prefix]

    def _matching_endpoint_prefix(self, resource_url: str) -> str | None:
        """Return the longest matching per_endpoint prefix, or None."""
        parsed = urlparse(resource_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        # Try full URL, then base URL, then any configured prefix
        candidates = sorted(self.config.per_endpoint.keys(), key=len, reverse=True)
        for prefix in candidates:
            if resource_url.startswith(prefix) or base.startswith(prefix):
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
        # 1. Per-call limit
        if self.config.max_per_call_usd is not None and amount_usd > self.config.max_per_call_usd:
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
        if self.config.daily_limit_usd is not None and self._global_ledger.would_exceed(
            amount_usd, self.config.daily_limit_usd
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
            ep_ledger = self._get_endpoint_ledger(prefix)
            if ep_ledger.would_exceed(amount_usd, ep_limit):
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

        # All checks passed — record the spend
        self._global_ledger.record(amount_usd)
        if prefix is not None:
            self._get_endpoint_ledger(prefix).record(amount_usd)

        logger.debug("Policy check passed: %.4f USD for %s", amount_usd, resource_url)

    def reset(self) -> None:
        """Reset all spend ledgers (useful in tests)."""
        self._global_ledger.reset()
        with self._ledger_lock:
            for ledger in self._endpoint_ledgers.values():
                ledger.reset()
