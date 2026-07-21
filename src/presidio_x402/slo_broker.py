# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Market-based SLO enforcement — the SLO payment broker (v0.7.0).

When infrastructure degrades, the agent autonomously pays for a capacity upgrade via
x402 micropayments instead of relying on pre-provisioned autoscaling. The broker is an
economic actor that *bids for the infrastructure quality it needs, only when it needs it*.

It wraps a :class:`~presidio_x402.gateway.HardenedX402Client`, so capacity payments inherit
the full pre-execution pipeline (PII redaction, spending policy, replay guard, audit) — and
adds three SLO-specific controls layered on top:

* **Authorization, not metric.** It acts only on a *verified* :class:`~presidio_x402.
  arch_translucency_adapter.SLOTrigger` (a signature-checked arch-translucency degradation
  event). Forged/untrusted signals never reach the broker — that gate lives in the adapter.
* **Anti-drain.** :class:`~presidio_x402.slo_policy.SLOPaymentPolicy` enforces a cooldown,
  a per-event cap, a daily SLO cap (its own ledger), and step-up pricing for *consecutive*
  degradations, so a flapping or adversarial backend can't bleed the budget.
* **Anti-lock-in.** Capacity is bought through a pluggable :class:`CapacityProvider`, so the
  agent is not economically welded to a single provider.

Every decision emits an audit event (``SLO_PAYMENT_TRIGGERED`` / ``SLO_PAYMENT_BLOCKED``).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .audit_log import AuditLog, NullAuditWriter
from .exceptions import PolicyViolationError, X402Error
from .policy_engine import _decimal_usd, _SpendLedger
from .slo_policy import SLOPaymentPolicy, validate_slo_policy

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._types import AuditWriter
    from .arch_translucency_adapter import SLOTrigger
    from .gateway import HardenedX402Client

logger = logging.getLogger("presidio_x402.slo_broker")


class SLOBrokerError(X402Error):
    """Raised on broker misconfiguration (fail-closed at construction)."""


@dataclass(frozen=True)
class UpgradeReceipt:
    """Result of a capacity-provider purchase attempt."""

    provider: str
    endpoint: str
    amount_usd: float
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class SLOPaymentDecision:
    """Outcome of handling one trigger."""

    action: str  # "paid" | "blocked" | "skipped"
    reason: str
    amount_usd: float
    receipt: UpgradeReceipt | None = None


class CapacityProvider(Protocol):
    """A provider the agent can pay to upgrade capacity. Implementations must not
    spend more than ``max_usd`` and should surface the actual charge in the receipt."""

    name: str

    async def purchase_upgrade(self, trigger: SLOTrigger, *, max_usd: float) -> UpgradeReceipt:
        raise NotImplementedError


class X402CapacityProvider:
    """Default provider: pays an x402 capacity-upgrade endpoint via the wrapped client.

    The endpoint is expected to answer with HTTP 402 and a payment offer; the
    :class:`~presidio_x402.gateway.HardenedX402Client` settles it (subject to its own
    policy/PII/replay controls), so this provider mainly binds an endpoint to the agent.
    """

    def __init__(self, name: str, endpoint: str, client: HardenedX402Client) -> None:
        self.name = name
        self._endpoint = endpoint
        self._client = client

    async def purchase_upgrade(self, trigger: SLOTrigger, *, max_usd: float) -> UpgradeReceipt:
        payload = {
            "slo": trigger.slo,
            "observed": trigger.value,
            "threshold": trigger.threshold,
            "max_usd": max_usd,
        }
        resp = await self._client.post(self._endpoint, json=payload)
        ok = resp.status_code < 400
        # The agent authorized at most max_usd; the gateway enforces the real cap.
        return UpgradeReceipt(
            provider=self.name,
            endpoint=self._endpoint,
            amount_usd=max_usd if ok else 0.0,
            ok=ok,
            detail=f"HTTP {resp.status_code}",
        )


class SLOPaymentBroker:
    """Decides and executes SLO-triggered capacity payments.

    Parameters
    ----------
    client:
        The wrapped :class:`~presidio_x402.gateway.HardenedX402Client` (shared spending
        ledger / audit pipeline).
    slo_policy:
        :class:`~presidio_x402.slo_policy.SLOPaymentPolicy` (validated at construction).
    provider:
        A :class:`CapacityProvider` to buy upgrades from.
    base_event_usd:
        Base price for one capacity upgrade, before escalation/caps.
    audit_writer:
        Optional sink for the broker's ``SLO_PAYMENT_*`` audit events.
    clock:
        Monotonic clock for cooldown (injectable for tests). Defaults to
        :func:`time.monotonic`.
    """

    def __init__(
        self,
        client: HardenedX402Client,
        *,
        slo_policy: SLOPaymentPolicy,
        provider: CapacityProvider,
        base_event_usd: float,
        audit_writer: AuditWriter | None = None,
        agent_id: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        validate_slo_policy(slo_policy)
        _decimal_usd(base_event_usd, "base_event_usd")
        self._client = client
        self._policy = slo_policy
        self._provider = provider
        self._base_usd = base_event_usd
        self._audit = AuditLog(audit_writer or NullAuditWriter(), agent_id=agent_id)
        self._clock = clock
        self._slo_ledger = _SpendLedger(slo_policy.window_seconds)
        self._last_payment_ts: float | None = None
        self._consecutive = 0
        self._lock = asyncio.Lock()

    async def handle_trigger(self, trigger: SLOTrigger) -> SLOPaymentDecision:
        """Decide and (if authorized) execute a capacity payment for one verified
        trigger. Serialized so concurrent triggers cannot both pass the cooldown."""
        async with self._lock:
            if not trigger.degraded:
                # Recovery: reset the consecutive-escalation counter.
                self._consecutive = 0
                return SLOPaymentDecision("skipped", "not degraded", 0.0)

            now = self._clock()
            if (
                self._last_payment_ts is not None
                and (now - self._last_payment_ts) < self._policy.cooldown_seconds
            ):
                return self._blocked(trigger, "cooldown active", 0.0)

            amount = self._base_usd * self._policy.escalation_multiplier(self._consecutive)
            if self._policy.max_per_slo_event_usd is not None:
                amount = min(amount, self._policy.max_per_slo_event_usd)
            amount_dec = _decimal_usd(amount, "slo_amount")

            if self._policy.max_daily_slo_usd is not None:
                cap = _decimal_usd(self._policy.max_daily_slo_usd, "max_daily_slo_usd")
                if self._slo_ledger.would_exceed(amount_dec, cap):
                    return self._blocked(trigger, "daily SLO cap reached", amount)

            try:
                receipt = await self._provider.purchase_upgrade(trigger, max_usd=amount)
            except PolicyViolationError as exc:
                return self._blocked(trigger, f"client policy blocked: {exc}", amount)
            except Exception as exc:  # provider/network failure → no payment recorded
                logger.exception("capacity provider failed")
                return self._blocked(trigger, f"provider error: {exc}", amount)

            if not receipt.ok:
                return self._blocked(trigger, f"provider declined: {receipt.detail}", amount)

            charged = receipt.amount_usd
            self._slo_ledger.record(_decimal_usd(charged, "charged_usd"))
            self._last_payment_ts = now
            self._consecutive += 1
            self._emit("SLO_PAYMENT_TRIGGERED", trigger, charged, "allowed")
            logger.info(
                "SLO payment: %s degraded (%d>%d) → $%.4f via %s",
                trigger.slo,
                trigger.value,
                trigger.threshold,
                charged,
                receipt.provider,
            )
            return SLOPaymentDecision("paid", "ok", charged, receipt)

    def _blocked(self, trigger: SLOTrigger, reason: str, amount: float) -> SLOPaymentDecision:
        self._emit("SLO_PAYMENT_BLOCKED", trigger, amount, "blocked", error=reason)
        logger.warning("SLO payment blocked (%s) for %s", reason, trigger.slo)
        return SLOPaymentDecision("blocked", reason, amount)

    def _emit(
        self, event_type: str, trigger: SLOTrigger, amount: float, outcome: str, *, error: str = ""
    ) -> None:
        self._audit.emit(
            event_type,
            resource_url=f"slo://{trigger.signer}/{trigger.slo}",
            amount_usd=amount,
            outcome=outcome,
            error_message=error or None,
        )

    @property
    def consecutive_degradations(self) -> int:
        return self._consecutive
