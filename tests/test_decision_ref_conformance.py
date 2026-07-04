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


# --- second block: pshkv's digest / forward-compat axis (x402#2332, autogen#7353) ---
_DFC = _FIXTURE.get("digest_forward_compat_vectors", [])
_DFC_IDS = [v["id"] for v in _DFC]


def _conformant_preimage(v: dict) -> bool:
    """A preimage is verifiable only if its field list is present and set-equal to its keys."""
    fields = v.get("decision_ref_preimage_fields")
    return bool(fields) and set(fields) == set(v["decision_ref_preimage"].keys())


@pytest.mark.parametrize("v", _DFC, ids=_DFC_IDS)
def test_digest_forward_compat(v):
    """Digest axis: id sensitive to its preimage, and fails closed on the unknown."""
    a = v["assert"]
    pre = v["decision_ref_preimage"]
    if a == "decision_ref_differs":
        # same artifact, one changed preimage field -> a different, still-recomputable id
        assert pre["artifact_hash"] == _FIXTURE["vectors"][0]["artifact_hash"]
        assert sha256_hex(jcs(pre)) == v["decision_ref"] != v["baseline_decision_ref"]
    elif a == "decision_ref_equals":
        # JCS is order-insensitive: scrambled keys canonicalise to the same bytes and id
        assert jcs(v["decision_ref_preimage_unsorted"]) == jcs(pre) == v["jcs_payload"]
        assert sha256_hex(jcs(pre)) == v["decision_ref"] == v["baseline_decision_ref"]
    elif a in ("non_conformant", "fail_closed"):
        assert v["expect"] == "reject"
        assert not _conformant_preimage(v)
    else:
        pytest.fail(f"{v['id']}: unknown assert '{a}'")


def test_digest_block_covers_pshkv_matrix():
    """All five pshkv cases present: two bindings, canonicalisation, and both fail-closed."""
    asserts = [v["assert"] for v in _DFC]
    assert asserts.count("decision_ref_differs") == 2  # policy_version + verdict binding
    assert "decision_ref_equals" in asserts  # reorder -> same digest
    assert "non_conformant" in asserts  # missing preimage field list
    assert "fail_closed" in asserts  # unknown field, not in declared list
