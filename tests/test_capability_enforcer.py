"""Tests for the CapabilityEnforcer pipeline stage (E2 scaffold).

Covers: allow and block paths (over-budget, out-of-prefix, expired), both
construction modes (configured chain / per-call trust-store verify), block-time
DENY evidence emission and its offline verifiability + grant-hash parent linkage,
per-stage timing population, constructor validation, and — critically — that the
stage is **default-off** and byte-identical when unconfigured.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402._types import PaymentDetails
from presidio_x402.audit_log import AuditLog, NullAuditWriter
from presidio_x402.capability import CapabilityError, issue_grant, verify_chain
from presidio_x402.capability_enforcer import CapabilityEnforcer, StageTiming
from presidio_x402.core import ScreeningPipeline
from presidio_x402.decision_ref import DecisionRefEmitter, verify_decision_ref
from presidio_x402.pii_filter import PIIFilter
from presidio_x402.policy_engine import PolicyEngine
from presidio_x402.replay_guard import ReplayGuard

_PREFIX = "https://api.example.com/v1"
_URL = "https://api.example.com/v1/inference/run"
_WINDOW_FROM = datetime(2026, 1, 1, tzinfo=timezone.utc)
_WINDOW_UNTIL = datetime(2027, 1, 1, tzinfo=timezone.utc)
_INSIDE = datetime(2026, 6, 1, tzinfo=timezone.utc)
_AFTER = datetime(2027, 6, 1, tzinfo=timezone.utc)


def _kp() -> tuple[str, str]:
    sk = ed25519.Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def _pub_of(priv_hex: str) -> str:
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        .public_key()
        .public_bytes_raw()
        .hex()
    )


def _root_grant():
    op_priv, op_pub = _kp()
    a_priv, a_pub = _kp()
    grant = issue_grant(
        subject="agent-0",
        issuer="op",
        issuer_private_key=op_priv,
        subject_public_key=a_pub,
        caveats={
            "max_per_call_usd": "0.50",
            "endpoint_prefixes": [_PREFIX],
            "valid_from": _WINDOW_FROM.isoformat().replace("+00:00", "Z"),
            "valid_until": _WINDOW_UNTIL.isoformat().replace("+00:00", "Z"),
        },
        issued_at=_WINDOW_FROM,
    )
    trust = {"op": {"alg": "ed25519", "public_key": op_pub}}
    return grant, trust


def _details(url: str = _URL, amount: str = "0.10") -> PaymentDetails:
    return PaymentDetails(
        resource_url=url,
        pay_to="0x" + "ab" * 20,
        amount=amount,
        currency="USDC",
        network="base-sepolia",
        deadline_seconds=300,
    )


class _ListWriter:
    def __init__(self):
        self.records = []

    def write(self, envelope):
        self.records.append(dict(envelope))


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_constructor_requires_exactly_one_source():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    with pytest.raises(ValueError):
        CapabilityEnforcer()  # neither
    with pytest.raises(ValueError):
        CapabilityEnforcer(chain=chain, trust_store=trust)  # both


# ---------------------------------------------------------------------------
# Direct enforce(): allow + each block class
# ---------------------------------------------------------------------------


def test_enforce_allow_returns_chain_and_times():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    enf = CapabilityEnforcer(chain=chain)
    timing = StageTiming()
    out = enf.enforce(_details(amount="0.10"), Decimal("0.10"), at=_INSIDE, timing=timing)
    assert out is chain
    assert timing.capability_verify_ns is not None and timing.capability_verify_ns >= 0
    assert timing.evidence_write_ns is None  # nothing written on allow


def test_enforce_blocks_over_budget():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    enf = CapabilityEnforcer(chain=chain)
    with pytest.raises(CapabilityError):
        enf.enforce(_details(amount="0.75"), Decimal("0.75"), at=_INSIDE)


def test_enforce_blocks_out_of_prefix():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    enf = CapabilityEnforcer(chain=chain)
    with pytest.raises(CapabilityError):
        enf.enforce(
            _details(url="https://api.example.com/v2/x", amount="0.10"),
            Decimal("0.10"),
            at=_INSIDE,
        )


def test_enforce_blocks_expired():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    enf = CapabilityEnforcer(chain=chain)
    with pytest.raises(CapabilityError):
        enf.enforce(_details(amount="0.10"), Decimal("0.10"), at=_AFTER)


# ---------------------------------------------------------------------------
# Trust-store mode (verify a presented chain per call)
# ---------------------------------------------------------------------------


def test_trust_store_mode_allows_valid_presented_chain():
    grant, trust = _root_grant()
    enf = CapabilityEnforcer(trust_store=trust)
    out = enf.enforce(
        _details(amount="0.10"), Decimal("0.10"), presented_chain=[grant], at=_INSIDE
    )
    assert out.subject == "agent-0"


def test_trust_store_mode_rejects_missing_presented_chain():
    _grant, trust = _root_grant()
    enf = CapabilityEnforcer(trust_store=trust)
    with pytest.raises(CapabilityError):
        enf.enforce(_details(), Decimal("0.10"), at=_INSIDE)


def test_configured_mode_rejects_presented_chain():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    enf = CapabilityEnforcer(chain=chain)
    with pytest.raises(CapabilityError):
        enf.enforce(_details(), Decimal("0.10"), presented_chain=[grant], at=_INSIDE)


# ---------------------------------------------------------------------------
# Block-time evidence: signed DENY record, parent-linked, verifiable
# ---------------------------------------------------------------------------


def test_block_emits_verifiable_parent_linked_deny_record():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    signer_priv, _ = _kp()
    writer = _ListWriter()
    emitter = DecisionRefEmitter(signing_key=signer_priv, signer="policy-signer", writer=writer)
    enf = CapabilityEnforcer(chain=chain, emitter=emitter, agent_id="agent-0")

    timing = StageTiming()
    with pytest.raises(CapabilityError):
        enf.enforce(_details(amount="0.75"), Decimal("0.75"), at=_INSIDE, timing=timing)

    assert len(writer.records) == 1
    env = writer.records[0]
    assert env["payment_decision"]["verdict"] == "DENY"
    # Parent-linked to the chain's terminal grant hash.
    grant_hash = chain.grants[-1].grant_hash
    parents = env["payment_decision"]["provenance"]["parents"]
    assert f"capability-grant:{grant_hash}" in parents
    # Offline-verifiable, and the parent linkage checks out.
    trust_pub = {"policy-signer": {"alg": "ed25519", "public_key": _pub_of(signer_priv)}}
    result = verify_decision_ref(
        env, trust_pub, require_parents=[f"capability-grant:{grant_hash}"]
    )
    assert result.ok, result.reason
    assert timing.evidence_write_ns is not None and timing.evidence_write_ns >= 0


def test_block_without_emitter_still_raises_no_record():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    enf = CapabilityEnforcer(chain=chain, emitter=None)
    with pytest.raises(CapabilityError):
        enf.enforce(_details(amount="0.75"), Decimal("0.75"), at=_INSIDE)


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------


def _pipeline(enforcer=None, emitter=None):
    return ScreeningPipeline(
        pii_filter=PIIFilter(mode="regex"),
        policy=PolicyEngine(None),
        replay=ReplayGuard(ttl=3600),
        audit=AuditLog(NullAuditWriter()),
        pii_action="redact",
        decision_ref_emitter=emitter,
        capability_enforcer=enforcer,
    )


@pytest.mark.asyncio
async def test_pipeline_allows_and_records_stage_timing():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)
    enf = CapabilityEnforcer(chain=chain)
    pipeline = _pipeline(enforcer=enf)
    timing = StageTiming()
    # exercise inside the window: patch enforce's clock via a chain re-verify is
    # not needed — check_payment uses `at=None` => now; the wide 2026..2027 window
    # admits the real current date used by the suite.
    details, fp = await pipeline.apply(_details(amount="0.10"), stage_timings=timing)
    assert details.pay_to == "0x" + "ab" * 20
    assert timing.redaction_ns is not None
    assert timing.capability_verify_ns is not None


@pytest.mark.asyncio
async def test_pipeline_blocks_over_budget_and_emits_audit():
    grant, trust = _root_grant()
    chain = verify_chain([grant], trust, at=_INSIDE)

    class _Audit:
        def __init__(self):
            self.events = []

        def write(self, e):
            self.events.append(e)

    audit = _Audit()
    enf = CapabilityEnforcer(chain=chain)
    pipeline = ScreeningPipeline(
        pii_filter=PIIFilter(mode="regex"),
        policy=PolicyEngine(None),
        replay=ReplayGuard(ttl=3600),
        audit=AuditLog(audit),
        pii_action="redact",
        capability_enforcer=enf,
    )
    with pytest.raises(CapabilityError):
        await pipeline.apply(_details(amount="0.75"))
    assert any(getattr(e, "event_type", None) == "CAPABILITY_BLOCKED" for e in audit.events)
    assert any(getattr(e, "outcome", None) == "blocked" for e in audit.events)


# ---------------------------------------------------------------------------
# Default-off: unconfigured pipeline is byte-identical (no capability code runs)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_off_no_enforcer_unchanged():
    pipeline = _pipeline(enforcer=None)
    # No stage_timings, no enforcer => the classic path.
    details, fp = await pipeline.apply(_details(amount="0.10"))
    assert isinstance(fp, str) and fp
    assert details.amount == "0.10"


@pytest.mark.asyncio
async def test_default_off_stage_timings_none_when_unused():
    pipeline = _pipeline(enforcer=None)
    timing = StageTiming()
    await pipeline.apply(_details(amount="0.10"), stage_timings=timing)
    # redaction is timed when a sink is passed, but no capability stage ran.
    assert timing.capability_verify_ns is None
    assert timing.evidence_write_ns is None
