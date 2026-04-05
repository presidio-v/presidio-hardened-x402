"""Tests for PolicyEngine — spending policy enforcement."""

from __future__ import annotations

import time

import pytest

from presidio_x402.exceptions import PolicyViolationError
from presidio_x402.policy_engine import PolicyConfig, PolicyEngine


class TestPolicyEnginePerCallLimit:
    def setup_method(self):
        self.engine = PolicyEngine(PolicyConfig(max_per_call_usd=0.10))

    def test_allows_payment_below_limit(self):
        self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.05)

    def test_allows_payment_at_limit(self):
        self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.10)

    def test_blocks_payment_above_limit(self):
        with pytest.raises(PolicyViolationError) as exc_info:
            self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.15)
        assert exc_info.value.amount_usd == pytest.approx(0.15)
        assert exc_info.value.limit_usd == pytest.approx(0.10)

    def test_exception_message_is_informative(self):
        with pytest.raises(PolicyViolationError, match="per-call limit"):
            self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=1.00)


class TestPolicyEngineDailyLimit:
    def setup_method(self):
        self.engine = PolicyEngine(PolicyConfig(daily_limit_usd=0.30))

    def test_allows_first_payment_within_daily(self):
        self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.10)

    def test_blocks_when_daily_would_be_exceeded(self):
        self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.20)
        self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.05)
        with pytest.raises(PolicyViolationError, match="aggregate spend"):
            self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.10)

    def test_aggregate_accumulates_across_calls(self):
        for _ in range(3):
            self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.09)
        with pytest.raises(PolicyViolationError):
            self.engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.09)


class TestPolicyEnginePerEndpointLimit:
    def setup_method(self):
        self.engine = PolicyEngine(PolicyConfig(per_endpoint={"https://premium-api.io": 0.20}))

    def test_allows_payment_within_endpoint_limit(self):
        self.engine.check_and_record(
            resource_url="https://premium-api.io/v1/data", amount_usd=0.10
        )

    def test_blocks_payment_exceeding_endpoint_limit(self):
        self.engine.check_and_record(
            resource_url="https://premium-api.io/v1/data", amount_usd=0.15
        )
        with pytest.raises(PolicyViolationError, match="endpoint spend"):
            self.engine.check_and_record(
                resource_url="https://premium-api.io/v1/other", amount_usd=0.10
            )

    def test_does_not_limit_unmatched_endpoint(self):
        # A different endpoint is not subject to the per_endpoint limit
        self.engine.check_and_record(resource_url="https://other-api.io/data", amount_usd=0.50)

    def test_endpoint_prefix_matching_base_url(self):
        engine = PolicyEngine(PolicyConfig(per_endpoint={"https://premium-api.io": 0.05}))
        engine.check_and_record(resource_url="https://premium-api.io/any/path", amount_usd=0.04)
        with pytest.raises(PolicyViolationError):
            engine.check_and_record(resource_url="https://premium-api.io/another", amount_usd=0.04)


class TestPolicyEngineFromDict:
    def test_from_dict_creates_correct_config(self):
        engine = PolicyEngine({"max_per_call_usd": 0.05, "daily_limit_usd": 1.0})
        with pytest.raises(PolicyViolationError):
            engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.10)

    def test_empty_dict_creates_permissive_config(self):
        engine = PolicyEngine({})
        # Should not raise
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=999.0)


class TestPolicyEngineNoPolicyConfigPermissive:
    def test_none_config_allows_everything(self):
        engine = PolicyEngine(None)
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=1000.0)


class TestPolicyEngineReset:
    def test_reset_clears_ledger(self):
        engine = PolicyEngine(PolicyConfig(daily_limit_usd=0.10))
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)
        engine.reset()
        # After reset, should allow another payment
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)


class TestPolicyEngineWindowExpiry:
    def test_old_entries_expire_from_window(self):
        engine = PolicyEngine(PolicyConfig(daily_limit_usd=0.10, window_seconds=1))
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)
        time.sleep(1.1)
        # Old entry expired; new payment should be allowed
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)
