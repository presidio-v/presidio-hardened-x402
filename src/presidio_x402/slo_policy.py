"""SLO-payment spending policy (v0.7.0).

:class:`SLOPaymentPolicy` extends :class:`~presidio_x402.policy_engine.PolicyConfig`
with limits specific to *market-based SLO enforcement* — the agent paying for
capacity upgrades when infrastructure degrades. Because it **is** a ``PolicyConfig``,
it drops into a :class:`~presidio_x402.policy_engine.PolicyEngine` unchanged, so SLO
capacity payments are also counted against the ordinary per-call / daily / per-endpoint
budgets (one shared ledger). The SLO-specific caps below are a second, independent layer
the :class:`~presidio_x402.slo_broker.SLOPaymentBroker` enforces *before* it pays — the
primary mitigation for the "SLO-triggered spending drain" threat.
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy_engine import PolicyConfig, _decimal_usd


@dataclass
class SLOPaymentPolicy(PolicyConfig):
    """Spending policy for SLO-triggered capacity payments."""

    latency_threshold_ms: float = 200.0
    """Self-measurement threshold: p99 latency above which the broker's own
    ``get()`` path treats a request as degraded. Signed triggers from
    arch-translucency carry their own threshold and are authoritative on the
    event path; this governs the broker-measured path."""

    max_per_slo_event_usd: float | None = None
    """Hard cap on a single capacity-upgrade payment."""

    cooldown_seconds: int = 300
    """Minimum gap between consecutive SLO payments — the anti-drain control."""

    max_daily_slo_usd: float | None = None
    """Cap on SLO spend within ``window_seconds`` (separate from the general
    ``daily_limit_usd``, which also still applies via the shared ledger)."""

    tier_escalation_rules: tuple[float, ...] = ()
    """Step-up multipliers for *consecutive* degradation events, applied to the
    base event price. ``()`` → flat pricing (multiplier 1.0). Example
    ``(1.0, 2.0, 4.0)`` charges 1×, 2×, then 4× for the 1st/2nd/3rd+ consecutive
    degradation, so a flapping backend gets economically expensive fast."""

    @classmethod
    def from_dict(cls, data: dict) -> SLOPaymentPolicy:
        base = PolicyConfig.from_dict(data)
        return cls(
            max_per_call_usd=base.max_per_call_usd,
            daily_limit_usd=base.daily_limit_usd,
            per_endpoint=base.per_endpoint,
            window_seconds=base.window_seconds,
            agent_id=base.agent_id,
            latency_threshold_ms=data.get("latency_threshold_ms", 200.0),
            max_per_slo_event_usd=data.get("max_per_slo_event_usd"),
            cooldown_seconds=data.get("cooldown_seconds", 300),
            max_daily_slo_usd=data.get("max_daily_slo_usd"),
            tier_escalation_rules=tuple(data.get("tier_escalation_rules", ())),
        )

    def escalation_multiplier(self, consecutive_index: int) -> float:
        """Multiplier for the ``consecutive_index``-th consecutive degradation
        (0-based), clamped to the last rule. Empty rules → ``1.0``."""
        if not self.tier_escalation_rules:
            return 1.0
        i = max(0, min(consecutive_index, len(self.tier_escalation_rules) - 1))
        return self.tier_escalation_rules[i]


def validate_slo_policy(policy: SLOPaymentPolicy) -> None:
    """Fail-closed config validation (raises ``ValueError`` on any bad limit)."""
    if policy.latency_threshold_ms <= 0:
        raise ValueError("latency_threshold_ms must be > 0")
    if policy.cooldown_seconds < 0:
        raise ValueError("cooldown_seconds must be >= 0")
    if policy.max_per_slo_event_usd is not None:
        _decimal_usd(policy.max_per_slo_event_usd, "max_per_slo_event_usd")
    if policy.max_daily_slo_usd is not None:
        _decimal_usd(policy.max_daily_slo_usd, "max_daily_slo_usd")
    for i, multiplier in enumerate(policy.tier_escalation_rules):
        if multiplier <= 0:
            raise ValueError(f"tier_escalation_rules[{i}] must be > 0")
