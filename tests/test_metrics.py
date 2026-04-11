"""Tests for the Prometheus MetricsCollector."""

from __future__ import annotations

import pytest


class TestMetricsCollectorImport:
    def test_import_does_not_raise(self):
        from presidio_x402.metrics import MetricsCollector  # noqa: F401

    def test_collector_instantiates(self):
        from presidio_x402.metrics import MetricsCollector

        collector = MetricsCollector()
        assert collector is not None


class TestMetricsCollectorWithPrometheus:
    """Tests that run when prometheus-client is available."""

    @pytest.fixture
    def collector(self):
        # Use a unique namespace per test to avoid counter registration conflicts
        import uuid

        from presidio_x402.metrics import _PROM_AVAILABLE, MetricsCollector

        if not _PROM_AVAILABLE:
            pytest.skip("prometheus-client not installed")
        return MetricsCollector(namespace=f"x402_test_{uuid.uuid4().hex[:8]}")

    def test_record_payment_allowed(self, collector):
        collector.record_payment_allowed(amount_usd=0.05)

    def test_record_payment_blocked(self, collector):
        collector.record_payment_blocked(reason="pii", amount_usd=0.01)
        collector.record_payment_blocked(reason="policy", amount_usd=0.50)
        collector.record_payment_blocked(reason="replay")  # no amount

    def test_record_pii_detection(self, collector):
        collector.record_pii_detection(["EMAIL_ADDRESS", "PERSON"], action="redact")
        collector.record_pii_detection(["US_SSN"], action="block")

    def test_record_policy_violation(self, collector):
        collector.record_policy_violation("per_call")
        collector.record_policy_violation("daily_limit")
        collector.record_policy_violation("per_endpoint")

    def test_record_replay_detection(self, collector):
        collector.record_replay_detection()

    def test_record_mpa_event(self, collector):
        collector.record_mpa_event("approved")
        collector.record_mpa_event("denied")
        collector.record_mpa_event("timeout")

    def test_counters_are_registered(self, collector):
        assert hasattr(collector, "payments_total")
        assert hasattr(collector, "payment_amount_usd")
        assert hasattr(collector, "pii_detections_total")
        assert hasattr(collector, "policy_violations_total")
        assert hasattr(collector, "replay_detections_total")
        assert hasattr(collector, "mpa_events_total")


class TestMetricsCollectorNoop:
    """Tests for graceful no-op behaviour when prometheus-client is absent."""

    @pytest.fixture
    def noop_collector(self, monkeypatch):
        """Monkeypatch _PROM_AVAILABLE to False to simulate missing prometheus-client."""
        import presidio_x402.metrics as metrics_mod

        monkeypatch.setattr(metrics_mod, "_PROM_AVAILABLE", False)
        from presidio_x402.metrics import MetricsCollector

        return MetricsCollector()

    def test_noop_collector_available_is_false(self, noop_collector):
        assert noop_collector._available is False

    def test_noop_record_payment_allowed_does_not_raise(self, noop_collector):
        noop_collector.record_payment_allowed(0.10)

    def test_noop_record_payment_blocked_does_not_raise(self, noop_collector):
        noop_collector.record_payment_blocked("pii", 0.01)

    def test_noop_record_pii_detection_does_not_raise(self, noop_collector):
        noop_collector.record_pii_detection(["EMAIL_ADDRESS"], "redact")

    def test_noop_record_policy_violation_does_not_raise(self, noop_collector):
        noop_collector.record_policy_violation("per_call")

    def test_noop_record_replay_detection_does_not_raise(self, noop_collector):
        noop_collector.record_replay_detection()

    def test_noop_record_mpa_event_does_not_raise(self, noop_collector):
        noop_collector.record_mpa_event("approved")

    def test_noop_has_no_prometheus_attributes(self, noop_collector):
        assert not hasattr(noop_collector, "payments_total")
