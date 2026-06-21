"""OpenTelemetry spans for security-control activations."""

from __future__ import annotations

import pytest

from presidio_x402 import telemetry
from presidio_x402._types import PaymentDetails
from presidio_x402.audit_log import AuditLog, NullAuditWriter
from presidio_x402.core import ScreeningPipeline
from presidio_x402.mica import load_trust_store, sign_evidence, verify_ref
from presidio_x402.mpa import MPAApproverConfig, MPAConfig, MPAEngine, build_countersignature
from presidio_x402.pii_filter import PIIFilter
from presidio_x402.policy_engine import PolicyEngine
from presidio_x402.replay_guard import ReplayGuard

pytest.importorskip("opentelemetry.sdk.trace")


@pytest.fixture(scope="module")
def _span_exporter():
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    try:
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
    except ImportError:
        from opentelemetry.sdk.trace.export import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


@pytest.fixture
def span_exporter(_span_exporter):
    _span_exporter.clear()
    yield _span_exporter
    _span_exporter.clear()


def _details(**overrides) -> PaymentDetails:
    defaults = {
        "resource_url": "https://api.example.com/resource",
        "pay_to": "0xabcdef1234567890abcdef1234567890abcdef12",
        "amount": "1.00",
        "currency": "USDC",
        "network": "base-mainnet",
        "deadline_seconds": 300,
        "description": "research",
        "reason": "",
        "extra": {},
    }
    defaults.update(overrides)
    return PaymentDetails(**defaults)


def _pipeline(*, mpa_engine: MPAEngine | None = None) -> ScreeningPipeline:
    return ScreeningPipeline(
        pii_filter=PIIFilter(),
        policy=PolicyEngine({"max_per_call_usd": 5.00}),
        replay=ReplayGuard(),
        audit=AuditLog(NullAuditWriter()),
        mpa_engine=mpa_engine,
    )


def test_security_control_span_noops_when_trace_api_disabled(monkeypatch):
    calls: list[tuple[str, object]] = []

    class Span:
        def set_attribute(self, key: str, value: object) -> None:
            calls.append((key, value))

    monkeypatch.setattr(telemetry, "_trace_api", lambda: None)

    assert telemetry._trace_api() is None
    assert telemetry._tracer() is None

    telemetry.set_span_attribute(Span(), "ignored", {"nested": "dict"})
    assert calls == []

    with telemetry.security_control_span("policy", invalid={"nested": "dict"}) as span:
        span.set_attribute("manual", "ok")

    assert calls == []


@pytest.mark.asyncio
async def test_security_pipeline_emits_control_spans(span_exporter):
    secret = b"alice-secret"
    details = _details()
    mpa = MPAEngine(
        MPAConfig(
            threshold=1,
            approvers=[MPAApproverConfig("alice", mode="crypto", shared_secret=secret)],
        )
    )
    sig = build_countersignature(secret, details, 1.0)

    await _pipeline(mpa_engine=mpa).apply(details, mpa_signatures={"alice": sig})

    names = {span.name for span in span_exporter.get_finished_spans()}
    assert "presidio_x402.security.pii_filter" in names
    assert "presidio_x402.security.policy" in names
    assert "presidio_x402.security.replay" in names
    assert "presidio_x402.security.mpa" in names


def test_evidence_verify_emits_span(span_exporter):
    ref = {
        "content_hash": "abc123def456",
        "signer": "presidio-hardened-x402",
        "signature": sign_evidence(
            "abc123def456",
            "presidio-hardened-x402",
            algorithm="hmac-sha256",
            key="shared-key",
        ),
    }

    assert verify_ref(ref, load_trust_store({"presidio-hardened-x402": "shared-key"})) is True

    spans = span_exporter.get_finished_spans()
    evidence = [span for span in spans if span.name == "presidio_x402.security.evidence_verify"]
    assert evidence
    assert evidence[-1].attributes["presidio_x402.outcome"] == "verified"
