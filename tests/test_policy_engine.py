"""Tests for PolicyEngine — spending policy enforcement."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

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

    def test_decimal_boundary_does_not_trip_float_drift(self):
        engine = PolicyEngine(PolicyConfig(daily_limit_usd=0.30))
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.10)
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.20)
        with pytest.raises(PolicyViolationError):
            engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.01)


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


class TestPolicyEnginePrefixConfusion:
    """F-01 (2026-06-03): a sibling host/path sharing a leading substring with a
    configured per-endpoint prefix must NOT inherit that prefix's budget."""

    def test_lookalike_host_does_not_inherit_endpoint_budget(self):
        # api.example.com has a generous $5.00 endpoint limit. A hostile origin
        # whose hostname merely begins with it must not borrow that budget.
        engine = PolicyEngine(
            PolicyConfig(
                daily_limit_usd=100.0,
                per_endpoint={"https://api.example.com": 5.00},
            )
        )
        assert (
            engine._matching_endpoint_prefix("https://api.example.com.attacker.com/drain") is None
        )
        assert engine._matching_endpoint_prefix("https://api.example.com/data") == (
            "https://api.example.com"
        )

    def test_path_prefix_requires_segment_boundary(self):
        engine = PolicyEngine(PolicyConfig(per_endpoint={"https://api.example.com/v1": 0.50}))
        # Exact and child paths match; a sibling that merely shares the substring does not.
        assert engine._matching_endpoint_prefix("https://api.example.com/v1") == (
            "https://api.example.com/v1"
        )
        assert engine._matching_endpoint_prefix("https://api.example.com/v1/data") == (
            "https://api.example.com/v1"
        )
        assert engine._matching_endpoint_prefix("https://api.example.com/v1beta") is None

    def test_scheme_and_port_must_match_exactly(self):
        engine = PolicyEngine(PolicyConfig(per_endpoint={"https://api.example.com": 0.50}))
        assert engine._matching_endpoint_prefix("http://api.example.com/data") is None
        assert engine._matching_endpoint_prefix("https://api.example.com:8443/data") is None


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

    def test_reset_clears_endpoint_ledgers(self):
        engine = PolicyEngine(
            PolicyConfig(
                per_endpoint={"https://api.example.com": 0.10},
            )
        )
        engine.check_and_record(resource_url="https://api.example.com/data", amount_usd=0.08)
        # Endpoint ledger now has 0.08 recorded; another 0.08 would exceed 0.10
        engine.reset()
        # After reset, endpoint ledger is cleared — same payment is allowed again
        engine.check_and_record(resource_url="https://api.example.com/data", amount_usd=0.08)


class TestPolicyEngineWindowExpiry:
    def test_old_entries_expire_from_window(self):
        engine = PolicyEngine(PolicyConfig(daily_limit_usd=0.10, window_seconds=1))
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)
        time.sleep(1.1)
        # Old entry expired; new payment should be allowed
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)


class TestPolicyEngineRefund:
    """F-03 compensating rollback: refund reverses a recorded spend on both the
    global and per-endpoint ledgers."""

    def test_refund_frees_global_budget(self):
        engine = PolicyEngine(PolicyConfig(daily_limit_usd=0.10))
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)
        # A second 0.08 would exceed the 0.10 daily limit...
        with pytest.raises(PolicyViolationError):
            engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)
        # ...but after refunding the first, it fits again.
        engine.refund(resource_url="https://api.example.com", amount_usd=0.08)
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.08)

    def test_refund_frees_per_endpoint_budget(self):
        engine = PolicyEngine(PolicyConfig(per_endpoint={"https://api.example.com": 0.10}))
        engine.check_and_record(resource_url="https://api.example.com/data", amount_usd=0.08)
        engine.refund(resource_url="https://api.example.com/data", amount_usd=0.08)
        # Endpoint ledger reversed → same payment is allowed again.
        engine.check_and_record(resource_url="https://api.example.com/data", amount_usd=0.08)

    def test_refund_without_matching_entry_is_noop(self):
        engine = PolicyEngine(PolicyConfig(daily_limit_usd=0.10))
        engine.refund(resource_url="https://api.example.com", amount_usd=0.05)  # must not raise


class TestPolicyEngineHotReload:
    def test_update_config_applies_new_per_call_limit(self):
        engine = PolicyEngine(PolicyConfig(max_per_call_usd=1.00))
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.50)

        active = engine.update_config(PolicyConfig(max_per_call_usd=0.10))

        assert active.max_per_call_usd == pytest.approx(0.10)
        with pytest.raises(PolicyViolationError, match="per-call limit"):
            engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.50)

    def test_update_config_preserves_aggregate_spend_window(self):
        engine = PolicyEngine(PolicyConfig(daily_limit_usd=1.00))
        engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.75)

        engine.update_config({"daily_limit_usd": 0.80})

        with pytest.raises(PolicyViolationError, match="aggregate spend"):
            engine.check_and_record(resource_url="https://api.example.com", amount_usd=0.10)

    def test_update_config_is_safe_during_concurrent_checks(self):
        engine = PolicyEngine(PolicyConfig(max_per_call_usd=1.00))

        def check_many() -> None:
            for _ in range(50):
                engine.check_and_record(
                    resource_url="https://api.example.com/resource", amount_usd=0.01
                )

        def update_many() -> None:
            for i in range(50):
                engine.update_config({"max_per_call_usd": 1.00 + (i % 2)})

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(check_many) for _ in range(4)]
            futures.extend(pool.submit(update_many) for _ in range(4))
            for future in futures:
                future.result()

        engine.check_and_record(resource_url="https://api.example.com/resource", amount_usd=0.50)
