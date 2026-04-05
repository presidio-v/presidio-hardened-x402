"""Tests for ReplayGuard — duplicate payment detection."""

from __future__ import annotations

import time

import pytest

from presidio_x402.exceptions import ReplayDetectedError
from presidio_x402.replay_guard import ReplayGuard, compute_fingerprint


class TestComputeFingerprint:
    def test_same_inputs_produce_same_fingerprint(self):
        fp1 = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDC", 300)
        fp2 = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDC", 300)
        assert fp1 == fp2

    def test_different_url_produces_different_fingerprint(self):
        fp1 = compute_fingerprint("https://api.example.com/a", "0xabc", "0.01", "USDC", 300)
        fp2 = compute_fingerprint("https://api.example.com/b", "0xabc", "0.01", "USDC", 300)
        assert fp1 != fp2

    def test_different_amount_produces_different_fingerprint(self):
        fp1 = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDC", 300)
        fp2 = compute_fingerprint("https://api.example.com", "0xabc", "0.02", "USDC", 300)
        assert fp1 != fp2

    def test_different_currency_produces_different_fingerprint(self):
        fp1 = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDC", 300)
        fp2 = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDT", 300)
        assert fp1 != fp2

    def test_different_deadline_produces_different_fingerprint(self):
        fp1 = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDC", 300)
        fp2 = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDC", 600)
        assert fp1 != fp2

    def test_fingerprint_is_hex_string(self):
        fp = compute_fingerprint("https://api.example.com", "0xabc", "0.01", "USDC", 300)
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex is 64 chars
        int(fp, 16)  # should not raise


class TestReplayGuardMemory:
    def setup_method(self):
        self.guard = ReplayGuard(ttl=5)

    def test_first_call_allowed(self):
        self.guard.check_and_record("fp-unique-1")

    def test_second_call_with_same_fingerprint_blocked(self):
        self.guard.check_and_record("fp-unique-2")
        with pytest.raises(ReplayDetectedError) as exc_info:
            self.guard.check_and_record("fp-unique-2")
        assert exc_info.value.fingerprint == "fp-unique-2"

    def test_different_fingerprints_both_allowed(self):
        self.guard.check_and_record("fp-a")
        self.guard.check_and_record("fp-b")  # different fingerprint — should not raise

    def test_replay_error_message_contains_fingerprint_prefix(self):
        self.guard.check_and_record("abcdef1234567890")
        with pytest.raises(ReplayDetectedError, match="abcdef12"):
            self.guard.check_and_record("abcdef1234567890")

    def test_ttl_expiry_allows_resubmission(self):
        guard = ReplayGuard(ttl=1)
        guard.check_and_record("fp-expiry-test")
        time.sleep(1.1)
        guard.check_and_record("fp-expiry-test")  # should not raise after TTL

    def test_reset_clears_all_fingerprints(self):
        self.guard.check_and_record("fp-reset-test")
        self.guard.reset()
        self.guard.check_and_record("fp-reset-test")  # should not raise after reset


class TestReplayGuardRedisUnavailable:
    def test_redis_import_error_raises_helpful_message(self):
        """Redis backend raises ImportError with helpful message if redis is not installed."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "redis":
                raise ImportError("mocked: redis not installed")
            return real_import(name, *args, **kwargs)

        import unittest.mock

        with (
            unittest.mock.patch("builtins.__import__", side_effect=mock_import),
            pytest.raises(ImportError, match="Redis backend requires"),
        ):
            ReplayGuard(ttl=60, redis_url="redis://localhost:6379/0")
