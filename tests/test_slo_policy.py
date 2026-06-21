"""Tests for SLOPaymentPolicy (v0.7.0)."""

from __future__ import annotations

import pytest

from presidio_x402.policy_engine import PolicyConfig, PolicyEngine
from presidio_x402.slo_policy import SLOPaymentPolicy, validate_slo_policy


def test_is_a_policyconfig_and_drops_into_engine():
    # Being a PolicyConfig subclass, it must configure a PolicyEngine unchanged so
    # SLO spend shares the ordinary ledger.
    pol = SLOPaymentPolicy(max_per_call_usd=0.50, daily_limit_usd=5.0)
    assert isinstance(pol, PolicyConfig)
    engine = PolicyEngine(pol)
    engine.check_and_record(resource_url="https://compute.io/up", amount_usd=0.10)


def test_from_dict_round_trips_base_and_slo_fields():
    pol = SLOPaymentPolicy.from_dict(
        {
            "max_per_call_usd": 0.5,
            "daily_limit_usd": 10.0,
            "latency_threshold_ms": 150,
            "max_per_slo_event_usd": 0.25,
            "cooldown_seconds": 60,
            "max_daily_slo_usd": 2.0,
            "tier_escalation_rules": [1.0, 2.0, 4.0],
        }
    )
    assert pol.max_per_call_usd == 0.5
    assert pol.latency_threshold_ms == 150
    assert pol.tier_escalation_rules == (1.0, 2.0, 4.0)


def test_escalation_multiplier_clamps_to_last_rule():
    pol = SLOPaymentPolicy(tier_escalation_rules=(1.0, 2.0, 4.0))
    assert [pol.escalation_multiplier(i) for i in range(5)] == [1.0, 2.0, 4.0, 4.0, 4.0]


def test_escalation_default_is_flat():
    assert SLOPaymentPolicy().escalation_multiplier(7) == 1.0


def test_validate_rejects_bad_limits():
    with pytest.raises(ValueError):
        validate_slo_policy(SLOPaymentPolicy(latency_threshold_ms=0))
    with pytest.raises(ValueError):
        validate_slo_policy(SLOPaymentPolicy(cooldown_seconds=-1))
    with pytest.raises(ValueError):
        validate_slo_policy(SLOPaymentPolicy(max_per_slo_event_usd=-0.1))
    with pytest.raises(ValueError):
        validate_slo_policy(SLOPaymentPolicy(tier_escalation_rules=(1.0, 0.0)))


def test_validate_accepts_sane_policy():
    validate_slo_policy(
        SLOPaymentPolicy(
            latency_threshold_ms=200,
            cooldown_seconds=300,
            max_per_slo_event_usd=0.5,
            max_daily_slo_usd=10.0,
            tier_escalation_rules=(1.0, 1.5),
        )
    )
