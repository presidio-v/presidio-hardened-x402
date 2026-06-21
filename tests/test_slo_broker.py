"""Tests for SLOPaymentBroker — the evidence-gated SLO payment decision engine (v0.7.0)."""

from __future__ import annotations

import pytest

from presidio_x402.arch_translucency_adapter import SLOTrigger
from presidio_x402.exceptions import PolicyViolationError
from presidio_x402.slo_broker import SLOPaymentBroker, UpgradeReceipt
from presidio_x402.slo_policy import SLOPaymentPolicy

ARCH = "presidio-hardened-arch-translucency"


def _trigger(value: int = 420, threshold: int = 200) -> SLOTrigger:
    return SLOTrigger(
        slo="p99_latency_ms",
        value=value,
        threshold=threshold,
        window="5m",
        signer=ARCH,
        content_hash="ab" * 16,
        observed_at="2026-06-21T10:00:00+00:00",
    )


class _Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class _FakeProvider:
    name = "fake"

    def __init__(
        self, ok: bool = True, charge: float | None = None, raises: Exception | None = None
    ):
        self.ok = ok
        self.charge = charge
        self.raises = raises
        self.calls: list[float] = []

    async def purchase_upgrade(self, trigger, *, max_usd: float) -> UpgradeReceipt:
        self.calls.append(max_usd)
        if self.raises is not None:
            raise self.raises
        amount = self.charge if self.charge is not None else max_usd
        return UpgradeReceipt("fake", "https://compute.io/up", amount, self.ok, "detail")


class _CapWriter:
    def __init__(self) -> None:
        self.events: list = []

    def write(self, event) -> None:
        self.events.append(event)

    def flush(self) -> None:
        pass


def _broker(policy=None, provider=None, base=0.10, clock=None, audit=None):
    return SLOPaymentBroker(
        client=object(),  # only the default provider touches the client; we inject our own
        slo_policy=policy or SLOPaymentPolicy(),
        provider=provider or _FakeProvider(),
        base_event_usd=base,
        audit_writer=audit,
        clock=clock or _Clock(),
    )


@pytest.mark.asyncio
async def test_pays_on_degraded_trigger():
    prov, cap = _FakeProvider(), _CapWriter()
    broker = _broker(provider=prov, audit=cap)
    decision = await broker.handle_trigger(_trigger())
    assert decision.action == "paid"
    assert decision.amount_usd == pytest.approx(0.10)
    assert prov.calls == [pytest.approx(0.10)]
    assert any(e.event_type == "SLO_PAYMENT_TRIGGERED" for e in cap.events)


@pytest.mark.asyncio
async def test_skips_non_degraded_trigger():
    prov = _FakeProvider()
    broker = _broker(provider=prov)
    decision = await broker.handle_trigger(_trigger(value=100, threshold=200))
    assert decision.action == "skipped"
    assert prov.calls == []


@pytest.mark.asyncio
async def test_cooldown_blocks_then_allows():
    clock = _Clock()
    pol = SLOPaymentPolicy(cooldown_seconds=300)
    prov, cap = _FakeProvider(), _CapWriter()
    broker = _broker(policy=pol, provider=prov, clock=clock, audit=cap)

    assert (await broker.handle_trigger(_trigger())).action == "paid"
    second = await broker.handle_trigger(_trigger())
    assert second.action == "blocked" and "cooldown" in second.reason
    assert any(e.event_type == "SLO_PAYMENT_BLOCKED" for e in cap.events)

    clock.advance(301)
    assert (await broker.handle_trigger(_trigger())).action == "paid"
    assert len(prov.calls) == 2  # the blocked attempt never reached the provider


@pytest.mark.asyncio
async def test_tier_escalation_steps_up_price():
    clock = _Clock()
    pol = SLOPaymentPolicy(cooldown_seconds=300, tier_escalation_rules=(1.0, 2.0, 4.0))
    prov = _FakeProvider()
    broker = _broker(policy=pol, provider=prov, base=0.10, clock=clock)
    for _ in range(3):
        await broker.handle_trigger(_trigger())
        clock.advance(301)
    assert prov.calls == [pytest.approx(0.10), pytest.approx(0.20), pytest.approx(0.40)]


@pytest.mark.asyncio
async def test_per_event_cap_clamps_escalated_amount():
    clock = _Clock()
    pol = SLOPaymentPolicy(
        cooldown_seconds=300, tier_escalation_rules=(1.0, 10.0), max_per_slo_event_usd=0.15
    )
    prov = _FakeProvider()
    broker = _broker(policy=pol, provider=prov, base=0.10, clock=clock)
    await broker.handle_trigger(_trigger())  # 0.10
    clock.advance(301)
    await broker.handle_trigger(_trigger())  # escalated 1.00 → capped 0.15
    assert prov.calls == [pytest.approx(0.10), pytest.approx(0.15)]


@pytest.mark.asyncio
async def test_daily_slo_cap_blocks_when_exceeded():
    pol = SLOPaymentPolicy(cooldown_seconds=0, max_daily_slo_usd=0.25)
    prov = _FakeProvider()
    broker = _broker(policy=pol, provider=prov, base=0.10)
    assert (await broker.handle_trigger(_trigger())).action == "paid"  # 0.10
    assert (await broker.handle_trigger(_trigger())).action == "paid"  # 0.20
    third = await broker.handle_trigger(_trigger())  # 0.30 > 0.25
    assert third.action == "blocked" and "daily SLO cap" in third.reason


@pytest.mark.asyncio
async def test_provider_decline_is_not_recorded():
    pol = SLOPaymentPolicy(cooldown_seconds=0, max_daily_slo_usd=0.25)
    prov = _FakeProvider(ok=False)
    broker = _broker(policy=pol, provider=prov, base=0.10)
    decision = await broker.handle_trigger(_trigger())
    assert decision.action == "blocked" and "declined" in decision.reason
    # A declined attempt must not consume the daily SLO budget.
    prov.ok = True
    assert (await broker.handle_trigger(_trigger())).action == "paid"


@pytest.mark.asyncio
async def test_client_policy_violation_blocks():
    prov = _FakeProvider(raises=PolicyViolationError("over limit", amount_usd=1.0, limit_usd=0.5))
    broker = _broker(provider=prov)
    decision = await broker.handle_trigger(_trigger())
    assert decision.action == "blocked" and "client policy" in decision.reason


@pytest.mark.asyncio
async def test_recovery_resets_escalation():
    clock = _Clock()
    pol = SLOPaymentPolicy(cooldown_seconds=300, tier_escalation_rules=(1.0, 2.0, 4.0))
    prov = _FakeProvider()
    broker = _broker(policy=pol, provider=prov, base=0.10, clock=clock)
    await broker.handle_trigger(_trigger())  # 0.10, consecutive→1
    clock.advance(301)
    await broker.handle_trigger(_trigger(value=100))  # recovery → reset consecutive
    assert broker.consecutive_degradations == 0
    clock.advance(301)
    await broker.handle_trigger(_trigger())  # back to base 0.10, not escalated
    assert prov.calls == [pytest.approx(0.10), pytest.approx(0.10)]
