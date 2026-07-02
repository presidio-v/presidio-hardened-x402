"""Conformance test for the x402 payment-decision-ref fixture.

Mirrors babyblueviper1's `check_decision_ref.py` (autogen#7353 / crewAI#4877) against
our `decision_ref` shape, and adds the payment-semantic recompute (`verdict = f(controls)`).
Zero-dependency, offline — the same grading @babyblueviper1 runs on landed vectors.

Fixture: tests/conformance/decision-ref/presidio-x402-decision-ref-v1.fixture.json
Contributed upstream to giskard09/argentum-core examples/conformance/presidio/.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

FIXTURE = (
    Path(__file__).parent
    / "conformance"
    / "decision-ref"
    / "presidio-x402-decision-ref-v1.fixture.json"
)


def jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def f(controls: dict) -> str:
    """Pure precedence-combinator over the five recorded control verdicts."""
    if controls["pii"]["verdict"] == "PII_BLOCKED":
        return "DENY"
    if controls["trusted_wallet"]["verdict"] == "UNTRUSTED":
        return "DENY"
    if controls["policy"]["verdict"] == "VIOLATION":
        return "DENY"
    if controls["replay"]["verdict"] == "DUPLICATE":
        return "DENY"
    if controls["mpa"]["verdict"] == "DENIED":
        return "DENY"
    if controls["mpa"]["verdict"] in ("PENDING", "TIMEOUT"):
        return "REFER"
    return "ALLOW"


_FIXTURE = json.loads(FIXTURE.read_text(encoding="utf-8"))
_VECTORS = _FIXTURE["vectors"]
_IDS = [v["id"] for v in _VECTORS]


def _admission_ok(v: dict) -> bool:
    # signer must not resolve to the actor's runtime (self-approval).
    return v["signer"]["resolves_to"] != "actor-runtime"


def _verdict_recomputes(v: dict) -> bool:
    return f(v["artifact"]["controls"]) == v["artifact"]["verdict"]


@pytest.mark.parametrize("v", _VECTORS, ids=_IDS)
def test_decision_ref_recomputes_from_preimage(v):
    """decision_ref = sha256(JCS(its own published preimage fields))."""
    pre = v["decision_ref_preimage"]
    assert set(v["decision_ref_preimage_fields"]) == set(pre.keys())
    assert sha256_hex(jcs(pre)) == v["decision_ref"]
    assert bytes.fromhex(v["preimage_canonical_bytes_hex"]).decode("utf-8") == v["jcs_payload"]
    assert v["jcs_payload"] == jcs(pre)


@pytest.mark.parametrize("v", _VECTORS, ids=_IDS)
def test_artifact_hash_recomputes(v):
    """artifact_hash = sha256(JCS(payment-decision@1 content))."""
    assert sha256_hex(jcs(v["artifact"])) == v["artifact_hash"]
    assert v["decision_ref_preimage"]["artifact_hash"] == v["artifact_hash"]


@pytest.mark.parametrize("v", _VECTORS, ids=_IDS)
def test_tamper_sensitive_on_verdict(v):
    """Changing the verdict must change decision_ref."""
    tampered = dict(v["decision_ref_preimage"])
    alt = "DENY" if tampered["verdict"] != "DENY" else "ALLOW"
    tampered["verdict"] = alt
    assert sha256_hex(jcs(tampered)) != v["decision_ref"]


@pytest.mark.parametrize("v", _VECTORS, ids=_IDS)
def test_accept_reject_matches_expect(v):
    """The two fail-closed negatives must fail; the baseline must pass both."""
    accepted = _admission_ok(v) and _verdict_recomputes(v)
    assert accepted == (v["expect"] == "accept"), (
        f"{v['id']}: admission_ok={_admission_ok(v)} verdict_recomputes={_verdict_recomputes(v)}"
    )


def test_fixture_leads_with_negatives():
    """A content type proves its worth by what it rejects — both named negatives present."""
    fmodes = {v.get("failure_mode") for v in _VECTORS}
    assert "signer_equals_runtime" in fmodes
    assert "verdict_not_recomputable" in fmodes
    assert any(v["expect"] == "accept" for v in _VECTORS)
