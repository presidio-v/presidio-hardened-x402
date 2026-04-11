"""Prometheus metrics exporter for presidio-hardened-x402.

Exposes counters and histograms for every security control activation.
Requires the ``prometheus`` optional extra::

    pip install "presidio-hardened-x402[prometheus]"

If ``prometheus-client`` is not installed, all :class:`MetricsCollector`
record methods are silent no-ops — the library continues to work normally.

Usage::

    from presidio_x402 import HardenedX402Client
    from presidio_x402.metrics import MetricsCollector

    collector = MetricsCollector()
    client = HardenedX402Client(
        payment_signer=signer,
        metrics_collector=collector,
    )

Expose a ``/metrics`` endpoint (e.g., with FastAPI)::

    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from starlette.responses import Response

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
"""

from __future__ import annotations

import logging

logger = logging.getLogger("presidio_x402.metrics")

try:
    from prometheus_client import Counter, Histogram

    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False
    logger.debug(
        "prometheus-client not installed — metrics will be no-ops; "
        "install with: pip install 'presidio-hardened-x402[prometheus]'"
    )


class MetricsCollector:
    """Prometheus metrics collector for presidio-hardened-x402.

    When ``prometheus-client`` is available, creates and manages Prometheus
    counters and histograms for all security control events. When it is not
    installed, all methods silently do nothing.

    Parameters
    ----------
    namespace:
        Prometheus metric name prefix (default: ``"x402"``).
    """

    def __init__(self, namespace: str = "x402") -> None:
        self._available = _PROM_AVAILABLE
        if not self._available:
            return

        self.payments_total: Counter = Counter(
            f"{namespace}_payments_total",
            "Total x402 payment attempts",
            ["outcome", "reason"],
        )
        self.payment_amount_usd: Histogram = Histogram(
            f"{namespace}_payment_amount_usd",
            "Distribution of x402 payment amounts in USD",
            buckets=[0.001, 0.005, 0.01, 0.05, 0.10, 0.50, 1.0, 5.0, 10.0, 50.0],
        )
        self.pii_detections_total: Counter = Counter(
            f"{namespace}_pii_detections_total",
            "PII detections in x402 payment metadata",
            ["entity_type", "action"],
        )
        self.policy_violations_total: Counter = Counter(
            f"{namespace}_policy_violations_total",
            "Spending policy violations",
            ["violation_type"],
        )
        self.replay_detections_total: Counter = Counter(
            f"{namespace}_replay_detections_total",
            "Replay/duplicate payment detections",
        )
        self.mpa_events_total: Counter = Counter(
            f"{namespace}_mpa_events_total",
            "Multi-party authorization events",
            ["outcome"],
        )

    def record_payment_allowed(self, amount_usd: float) -> None:
        """Record a successfully executed payment."""
        if not self._available:
            return
        self.payments_total.labels(outcome="allowed", reason="none").inc()
        self.payment_amount_usd.observe(amount_usd)

    def record_payment_blocked(self, reason: str, amount_usd: float | None = None) -> None:
        """Record a blocked payment.

        Parameters
        ----------
        reason:
            Block reason: ``"pii"``, ``"policy"``, ``"replay"``, ``"mpa"``, ``"error"``.
        amount_usd:
            Payment amount (if known at block time).
        """
        if not self._available:
            return
        self.payments_total.labels(outcome="blocked", reason=reason).inc()
        if amount_usd is not None:
            self.payment_amount_usd.observe(amount_usd)

    def record_pii_detection(self, entity_types: list[str], action: str) -> None:
        """Record PII detected in payment metadata.

        Parameters
        ----------
        entity_types:
            List of Presidio entity type strings (e.g., ``["EMAIL_ADDRESS", "PERSON"]``).
        action:
            PII action taken: ``"redact"``, ``"block"``, or ``"warn"``.
        """
        if not self._available:
            return
        for entity_type in entity_types:
            self.pii_detections_total.labels(entity_type=entity_type, action=action).inc()

    def record_policy_violation(self, violation_type: str) -> None:
        """Record a policy violation.

        Parameters
        ----------
        violation_type:
            Type of violation: ``"per_call"``, ``"daily_limit"``, ``"per_endpoint"``.
        """
        if not self._available:
            return
        self.policy_violations_total.labels(violation_type=violation_type).inc()

    def record_replay_detection(self) -> None:
        """Record a replay/duplicate payment detection."""
        if not self._available:
            return
        self.replay_detections_total.inc()

    def record_mpa_event(self, outcome: str) -> None:
        """Record an MPA authorization event.

        Parameters
        ----------
        outcome:
            ``"approved"``, ``"denied"``, or ``"timeout"``.
        """
        if not self._available:
            return
        self.mpa_events_total.labels(outcome=outcome).inc()
