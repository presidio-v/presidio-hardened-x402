"""Gate-certificate parents on payment-decision@1 records (issue #160).

Certificates are issued by ikigov-assess itself (``build_certificate`` + ``sign``,
the ``[gate]`` extra) with the family Ed25519 test key, so the verifier under test
is the real one. The behaviour mirrors presidio-hardened-x402-mcp (#89):

- identity: the family ``gate-certificate@1`` vector hashes to its pinned
  ADR-0006 identity, the same bare hash x402-mcp writes;
- refuse to build: tampered, expired, untrusted issuer, a decision other than
  OPEN, unreadable / oversized / non-JSON files, the extra not installed, a gate
  without a decision-ref emitter;
- accept: a config-sourced policy (no capability chain) now gets the gate as
  its parent, the missing classification -> gate -> payment edge; with a chain
  the gate follows the capability-grant parent;
- expiry while running: the record is still emitted, without the gate;
- no gate configured: records are unchanged.
"""

from __future__ import annotations

import builtins
import copy
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from presidio_x402._types import PaymentDetails
from presidio_x402.audit_log import AuditLog, NullAuditWriter
from presidio_x402.core import ScreeningPipeline
from presidio_x402.decision_ref import (
    DecisionRefEmitter,
    NullDecisionRefWriter,
    capability_parents,
    verify_decision_ref,
)
from presidio_x402.gate import (
    MAX_FILE_BYTES,
    GateCertificateError,
    GateParents,
    load_gate_parents,
)
from presidio_x402.gateway import HardenedX402Client
from presidio_x402.pii_filter import PIIFilter
from presidio_x402.policy_engine import PolicyEngine
from presidio_x402.replay_guard import ReplayGuard

from .test_decision_ref import _keypair, _real_chain

ikigov_cert = pytest.importorskip("presidio_ikigov_assess.certificate")

VECTOR_PATH = Path(__file__).parent / "fixtures" / "gate-certificate-valid.json"
# Pinned in x402-mcp's tests as well: both packages must name this gate identically.
VECTOR_IDENTITY = "dbb7c6a36f0aea55bbe5dead3daf8f4f3d59116966e79bd4b78ecfe2a83ebd4a"
VECTOR_AT = datetime(2026, 7, 3, tzinfo=UTC)

ISSUER = "presidio-hardened-ikigov-assess"
SEED = "01" * 32  # family test key (private seed)
PUBLIC_KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
OTHER_SEED = "02" * 32
G0_ITEMS = frozenset({"S1", "S2", "S3"})


def _utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _issue(
    *,
    affirmed: frozenset[str] = G0_ITEMS,
    issued: datetime | None = None,
    valid_days: int = 30,
    seed: str = SEED,
    use_case: str = "payment-gate",
) -> dict:
    issued = issued or datetime.now(UTC) - timedelta(days=1)
    doc = ikigov_cert.build_certificate(
        use_case=use_case,
        gate="G0",
        risk_class="medium",
        affirmed=affirmed,
        skipped=G0_ITEMS - affirmed,
        issuer=ISSUER,
        assessed_at=_utc(issued),
        not_after=_utc(issued + timedelta(days=valid_days)),
    )
    return ikigov_cert.sign(doc, alg="ed25519", key_hex_or_secret=seed, signer=ISSUER)


def _write(tmp_path: Path, name: str, payload: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _identity(path: Path) -> str:
    return ikigov_cert.certificate_content_hash(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def trust(tmp_path: Path) -> Path:
    return _write(tmp_path, "trust.json", {ISSUER: {"alg": "ed25519", "public_key": PUBLIC_KEY}})


@pytest.fixture
def emitter():
    priv, pub = _keypair()
    signer = "presidio-hardened-x402-policy"
    emitter = DecisionRefEmitter(signing_key=priv, signer=signer, writer=NullDecisionRefWriter())
    return emitter, {signer: {"alg": "ed25519", "public_key": pub}}


def _pipeline(**overrides) -> ScreeningPipeline:
    defaults = {
        "pii_filter": PIIFilter(),
        "policy": PolicyEngine(None),
        "replay": ReplayGuard(ttl=300),
        "audit": AuditLog(NullAuditWriter()),
        "agent_id": "agent-x",
    }
    defaults.update(overrides)
    return ScreeningPipeline(**defaults)


def _details(**overrides) -> PaymentDetails:
    base = {
        "resource_url": "https://api.merchant.example/v1/data",
        "pay_to": "0xabcdef1234567890abcdef1234567890abcdef12",
        "amount": "0.01",
        "currency": "USDC",
        "network": "base-sepolia",
        "deadline_seconds": 300,
        "description": "",
        "reason": "",
    }
    base.update(overrides)
    return PaymentDetails(**base)


async def _record(pipeline: ScreeningPipeline, **details) -> dict:
    captured: list[dict] = []
    await pipeline.apply(_details(**details), on_decision_ref=captured.append)
    assert len(captured) == 1
    return captured[0]


class TestLoad:
    @pytest.fixture
    def vector_trust(self, tmp_path):
        # The vector's embedded evidence-refs are signed as presidio-hardened-ai
        # with the same family key.
        key = {"alg": "ed25519", "public_key": PUBLIC_KEY}
        return _write(tmp_path, "vt.json", {ISSUER: key, "presidio-hardened-ai": key})

    def test_family_vector_identity_matches_x402_mcp(self, vector_trust):
        gate = load_gate_parents([VECTOR_PATH], vector_trust, now=VECTOR_AT)
        assert gate.identities == (VECTOR_IDENTITY,)
        assert gate.not_after == datetime(2027, 7, 2, tzinfo=UTC)

    def test_vector_refused_once_expired(self, vector_trust):
        with pytest.raises(GateCertificateError, match="expired"):
            load_gate_parents([VECTOR_PATH], vector_trust, now=datetime(2028, 1, 1, tzinfo=UTC))

    def test_duplicates_named_once_and_earliest_bound_governs(self, tmp_path, trust):
        cert = _write(tmp_path, "c.json", _issue())
        other = _write(tmp_path, "d.json", _issue(use_case="other-gate", valid_days=10))
        gate = load_gate_parents([cert, other, cert], trust)
        assert gate.identities == (_identity(cert), _identity(other))
        doc = json.loads(other.read_text(encoding="utf-8"))
        assert gate.not_after == ikigov_cert.parse_timestamp(doc["not_after"])

    def test_current_drops_parents_after_not_after(self):
        bound = datetime(2026, 1, 1, tzinfo=UTC)
        gate = GateParents(("a" * 64,), bound)
        assert gate.current(bound) == ["a" * 64]
        assert gate.current(bound + timedelta(seconds=1)) == []
        assert GateParents(("a" * 64,), None).current(bound) == ["a" * 64]

    def test_no_certificate_refused(self, trust):
        with pytest.raises(GateCertificateError, match="no gate certificate"):
            load_gate_parents([], trust)

    def test_tampered_refused(self, tmp_path, trust):
        doc = copy.deepcopy(_issue())
        doc["risk_class"] = "low"
        with pytest.raises(GateCertificateError):
            load_gate_parents([_write(tmp_path, "t.json", doc)], trust)

    def test_untrusted_issuer_refused(self, tmp_path, trust):
        cert = _write(tmp_path, "u.json", _issue(seed=OTHER_SEED))
        with pytest.raises(GateCertificateError):
            load_gate_parents([cert], trust)

    def test_expired_refused(self, tmp_path, trust):
        old = datetime.now(UTC) - timedelta(days=60)
        cert = _write(tmp_path, "e.json", _issue(issued=old, valid_days=30))
        with pytest.raises(GateCertificateError):
            load_gate_parents([cert], trust)

    def test_not_open_refused(self, tmp_path, trust):
        cert = _write(tmp_path, "p.json", _issue(affirmed=frozenset({"S1"})))
        with pytest.raises(GateCertificateError, match="only an open gate"):
            load_gate_parents([cert], trust)

    def test_non_json_refused(self, tmp_path, trust):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(GateCertificateError, match="not valid JSON"):
            load_gate_parents([path], trust)

    def test_oversized_refused(self, tmp_path, trust):
        path = tmp_path / "big.json"
        path.write_bytes(b" " * (MAX_FILE_BYTES + 1))
        with pytest.raises(GateCertificateError, match="exceeds"):
            load_gate_parents([path], trust)

    def test_missing_file_refused(self, tmp_path, trust):
        with pytest.raises(GateCertificateError, match="cannot read"):
            load_gate_parents([tmp_path / "absent.json"], trust)

    def test_missing_extra_names_the_extra(self, tmp_path, trust, monkeypatch):
        cert = _write(tmp_path, "c.json", _issue())  # issue before imports are blocked
        real_import = builtins.__import__

        def no_ikigov(name, *args, **kwargs):
            if name.startswith("presidio_ikigov_assess"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_ikigov)
        with pytest.raises(GateCertificateError, match=r"presidio-hardened-x402\[gate\]"):
            load_gate_parents([cert], trust)


class TestRecordsCarryTheGate:
    def test_gate_without_emitter_refused(self):
        with pytest.raises(ValueError, match="requires a decision_ref_emitter"):
            _pipeline(gate_parents=GateParents(("a" * 64,), None))

    @pytest.mark.asyncio
    async def test_config_policy_record_names_the_gate(self, tmp_path, trust, emitter):
        cert = _write(tmp_path, "cert.json", _issue())
        gate = load_gate_parents([cert], trust)
        em, em_trust = emitter
        env = await _record(_pipeline(decision_ref_emitter=em, gate_parents=gate))

        identity = _identity(cert)
        content = env["payment_decision"]
        assert content["parents"] == [identity]
        assert content["provenance"]["parents"] == [identity]
        check = verify_decision_ref(env, em_trust, require_parents=[identity])
        assert check.ok, check.reason

    @pytest.mark.asyncio
    async def test_gate_follows_the_capability_parent(self, tmp_path, trust, emitter):
        cert = _write(tmp_path, "cert.json", _issue())
        gate = load_gate_parents([cert], trust)
        chain = _real_chain()
        em, em_trust = emitter
        env = await _record(
            _pipeline(decision_ref_emitter=em, capability_chain=chain, gate_parents=gate)
        )

        grant = capability_parents(chain)[0]
        identity = _identity(cert)
        assert env["payment_decision"]["provenance"]["parents"] == [grant, identity]
        assert env["payment_decision"]["parents"] == [grant.split(":", 1)[1], identity]
        assert verify_decision_ref(env, em_trust, require_parents=[grant, identity]).ok

    @pytest.mark.asyncio
    async def test_expired_while_running_emits_without_gate(self, emitter, caplog):
        em, em_trust = emitter
        lapsed = GateParents(("a" * 64,), datetime.now(UTC) - timedelta(seconds=1))
        pipeline = _pipeline(decision_ref_emitter=em, gate_parents=lapsed)

        with caplog.at_level(logging.WARNING, logger="presidio_x402.core"):
            first = await _record(pipeline)
            second = await _record(pipeline, amount="0.02")

        for env in (first, second):
            assert "parents" not in env["payment_decision"]
            assert verify_decision_ref(env, em_trust).ok
        warnings = [r for r in caplog.records if "gate certificate expired" in r.getMessage()]
        assert len(warnings) == 1

    @pytest.mark.asyncio
    async def test_no_gate_leaves_records_unchanged(self, emitter):
        em, _ = emitter
        env = await _record(_pipeline(decision_ref_emitter=em))
        assert "parents" not in env["payment_decision"]
        assert env["payment_decision"]["provenance"]["parents"] == []

    def test_client_passes_the_gate_to_its_pipeline(self, emitter):
        em, _ = emitter
        gate = GateParents(("b" * 64,), None)

        class _Signer:
            async def sign(self, details):  # pragma: no cover - never called
                raise AssertionError

        client = HardenedX402Client(_Signer(), decision_ref_emitter=em, gate_parents=gate)
        assert client._pipeline._gate_parents is gate
