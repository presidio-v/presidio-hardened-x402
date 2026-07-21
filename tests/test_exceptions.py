"""Tests for exception types."""

from __future__ import annotations

from presidio_x402.exceptions import MPATimeoutError


class TestMPATimeoutError:
    def test_carries_approval_counts_and_message(self):
        err = MPATimeoutError("approval collection timed out", approvals_received=1, threshold=3)
        assert err.approvals_received == 1
        assert err.threshold == 3
        assert "timed out" in str(err)
