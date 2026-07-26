"""Python side of the treasury-binding cross-language conformance vectors.

These vectors are the *normative* contract between this repository's Python
canonicaliser and the sibling Rust one — the binding's correctness rests on the
bytes agreeing, not on any shared code. This file proves the Python half:
``mica.canonical_bytes`` + ``sha256_hex`` + ``sign_evidence`` reproduce every
pinned vector byte-for-byte, and every rejection case is refused with a *typed*
error rather than an interpreter accident.

The Rust half is a companion test in the ledger repository over these same
files. Until it lands, Gate 1 ("green on both sides") is met only halfway — the
gap is tracked, not papered over: nothing here asserts anything about Rust.

Hard axes covered, one test each: non-ASCII escaping (emoji, combining marks,
DEL, C0 controls), key ordering on non-ASCII keys, lone surrogates, non-string
object keys, integers past i64::MAX, floats, and the depth boundary at 128/129.
Plus the two family negatives, which a signature-only verifier would admit.

Regenerate the vectors with ``tests/conformance/treasury-binding/build_vectors.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from presidio_x402.decision_ref import (
    REASON_SIGNER_EQUALS_RUNTIME,
    REASON_VERDICT_NOT_RECOMPUTABLE,
    verify_decision_ref,
)
from presidio_x402.mica import (
    EvidenceError,
    canonical_bytes,
    load_trust_store,
    sha256_hex,
    sign_evidence,
)
from presidio_x402.treasury_binding import (
    SettlementFacts,
    TreasuryBindingError,
    build_settlement_ref_content,
    check_canonical_depth,
    verify_settlement_ref,
)

ROOT = Path(__file__).parent / "treasury-binding"
VECTORS = ROOT / "vectors"


def _load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text(encoding="utf-8"))


CANONICAL = _load("canonical-bytes.json")
SETTLEMENT = _load("settlement-ref.json")
NEGATIVES = _load("decision-ref-negatives.json")


def _materialise(case: dict) -> object:
    """Build a case's payload from whichever representation it uses.

    Three kinds, because not every input is expressible as JSON text: ``inline``
    is a literal, ``raw-json`` carries the exact source text (a lone surrogate is
    legal JSON but has no in-memory equivalent on every runtime), and
    ``construct`` is a recipe (a 129-deep literal is unreadable, and a
    non-string-keyed object cannot be written as JSON at all).
    """
    kind = case["kind"]
    if kind == "inline":
        return case["payload"]
    if kind == "raw-json":
        return json.loads(case["payload_json"])
    spec = case["construct"]
    if spec["op"] == "nested-object":
        node: object = spec["leaf"]
        for _ in range(spec["depth"]):
            node = {spec["key"]: node}
        return node
    if spec["op"] == "int-keyed-object":
        return dict.fromkeys(spec["keys"], spec["value"])
    raise AssertionError(f"unknown construct op {spec['op']!r}")


# ---------------------------------------------------------------------------
# Provenance — drift detection
# ---------------------------------------------------------------------------


def test_vectors_match_provenance_hashes():
    """Every vector file's SHA-256 matches PROVENANCE.json.

    A mismatch means a vector was hand-edited rather than regenerated, which
    would silently move the contract the sibling implementation is pinned to.
    """
    prov = json.loads((ROOT / "PROVENANCE.json").read_text(encoding="utf-8"))
    assert prov["source_repo"] == "presidio-hardened-x402"
    assert prov["files"], "provenance must list the vector files"
    for rel, expected in prov["files"].items():
        actual = hashlib.sha256((VECTORS / rel).read_bytes()).hexdigest()
        assert actual == expected, f"vector drift: {rel}"


def test_depth_definition_is_pinned_in_the_vector_file():
    """The boundary cases are meaningless without the definition they assume."""
    assert "depth 0" in CANONICAL["depth_definition"]
    assert "128 is accepted" in CANONICAL["depth_definition"]
    assert "129 is rejected" in CANONICAL["depth_definition"]


# ---------------------------------------------------------------------------
# Layer 0 — canonical bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CANONICAL["accept"], ids=[c["name"] for c in CANONICAL["accept"]])
def test_canonical_accept_cases_are_byte_identical(case: dict):
    payload = _materialise(case)
    produced = canonical_bytes(payload)
    assert produced.hex() == case["canonical_hex"], case["name"]
    assert hashlib.sha256(produced).hexdigest() == case["sha256"], case["name"]
    if "canonical_utf8" in case:
        assert produced.decode("utf-8") == case["canonical_utf8"]


@pytest.mark.parametrize("case", CANONICAL["reject"], ids=[c["name"] for c in CANONICAL["reject"]])
def test_canonical_reject_cases_fail_closed_with_a_typed_error(case: dict):
    payload = _materialise(case)
    if case["reject_reason"] == "too-deep":
        # The canonicaliser itself has no depth cap on this side; the bound lives
        # on the export path, which is the only path a sibling ever consumes.
        with pytest.raises(TreasuryBindingError):
            check_canonical_depth(payload)
        return
    with pytest.raises(EvidenceError):
        canonical_bytes(payload)


def test_depth_boundary_accepts_128_and_rejects_129():
    """Both sides of the boundary, asserted against the pinned definition."""
    accept = next(c for c in CANONICAL["accept"] if c["name"] == "nested-depth-128")
    reject = next(c for c in CANONICAL["reject"] if c["name"] == "nested-depth-129")
    check_canonical_depth(_materialise(accept))  # must not raise
    with pytest.raises(TreasuryBindingError):
        check_canonical_depth(_materialise(reject))


def test_lone_surrogate_raises_evidence_error_not_unicode_error():
    """Error-type parity: the family error, never a bare UnicodeEncodeError.

    A caller catching ``EvidenceError`` at the boundary would otherwise see a
    ``UnicodeEncodeError`` escape and turn a fail-closed refusal into a crash.
    """
    payload = json.loads('{"k":"\\ud800"}')
    with pytest.raises(EvidenceError) as excinfo:
        canonical_bytes(payload)
    assert not isinstance(excinfo.value, UnicodeEncodeError)
    assert "surrogate" in str(excinfo.value)


def test_non_ascii_key_order_equals_code_point_order():
    """UTF-8 byte order IS code-point order — pinned, not assumed."""
    case = next(c for c in CANONICAL["accept"] if c["name"] == "non-ascii-keys")
    keys = list(case["payload"].keys())
    encoded = canonical_bytes(case["payload"]).decode("utf-8")
    positions = [encoded.index(f'"{k}"') for k in sorted(keys)]
    assert positions == sorted(positions)
    assert sorted(keys) == sorted(keys, key=lambda k: k.encode("utf-8"))


def test_nfc_and_nfd_spellings_do_not_collapse():
    """Two spellings of one grapheme are distinct records, not one."""
    case = next(c for c in CANONICAL["accept"] if c["name"] == "non-ascii-escaping")
    payload = case["payload"]
    assert payload["combining"] != payload["precomposed"]
    assert canonical_bytes(payload["combining"]) != canonical_bytes(payload["precomposed"])


# ---------------------------------------------------------------------------
# settlement-ref@1 golden
# ---------------------------------------------------------------------------


def test_settlement_ref_golden_reproduces_byte_for_byte():
    golden = SETTLEMENT["golden"]
    content = golden["content"]
    facts = SettlementFacts.from_mapping(content["settlement"])
    rebuilt = build_settlement_ref_content(
        decision_ref=content["decision_ref"], facts=facts, issued_at=content["issued_at"]
    )
    assert rebuilt == content
    encoded = canonical_bytes(rebuilt)
    assert encoded.hex() == golden["canonical_hex"]
    assert encoded.decode("utf-8") == golden["canonical_utf8"]
    assert sha256_hex(rebuilt) == golden["content_hash"]
    assert facts.settlement_key == golden["settlement_key"]


def test_settlement_ref_signature_is_reproducible_and_signer_bound():
    golden = SETTLEMENT["golden"]
    signer = golden["envelope"]["evidence"][0]["signer"]
    signature = sign_evidence(
        golden["content_hash"],
        signer,
        algorithm="ed25519",
        key="01" * 32,
    )
    assert signature == golden["signature_hex"]
    # The signed message binds the signer id, so re-labelling the record breaks it.
    other = sign_evidence(
        golden["content_hash"], "someone-else", algorithm="ed25519", key="01" * 32
    )
    assert other != golden["signature_hex"]


def test_settlement_ref_envelope_verifies_against_the_pinned_trust_store():
    trust = load_trust_store(SETTLEMENT["trust_store"])
    envelope = SETTLEMENT["golden"]["envelope"]
    ok, reason, ref = verify_settlement_ref(envelope, trust)
    assert ok, reason
    assert ref == SETTLEMENT["golden"]["content_hash"]


def test_settlement_ref_tampered_field_fails_closed():
    """Mutating a committed fact breaks the content hash, not just the meaning."""
    trust = load_trust_store(SETTLEMENT["trust_store"])
    envelope = json.loads(json.dumps(SETTLEMENT["golden"]["envelope"]))
    envelope["settlement"]["settlement"]["log_index"] += 1
    ok, reason, _ = verify_settlement_ref(envelope, trust)
    assert not ok and reason == "settlement_hash_mismatch"


@pytest.mark.parametrize(
    "case", SETTLEMENT["reject"], ids=[c["name"] for c in SETTLEMENT["reject"]]
)
def test_settlement_facts_reject_cases(case: dict):
    with pytest.raises(EvidenceError):
        SettlementFacts.from_mapping(case["settlement"])


@pytest.mark.parametrize(
    "case", SETTLEMENT["normalisation"], ids=[c["name"] for c in SETTLEMENT["normalisation"]]
)
def test_settlement_facts_normalisation(case: dict):
    facts = SettlementFacts(
        chain=case["chain"], tx_hash=case["input"], block_number=1, log_index=0
    )
    assert facts.tx_hash == case["canonical"]


# ---------------------------------------------------------------------------
# The two family negatives — a signature-only verifier admits both
# ---------------------------------------------------------------------------

_NEG_IDS = [v["id"] for v in NEGATIVES["vectors"]]


@pytest.mark.parametrize("vector", NEGATIVES["vectors"], ids=_NEG_IDS)
def test_decision_negatives_grade_as_expected(vector: dict):
    trust = dict(NEGATIVES["trust_store"])
    trust.update(vector.get("trust_store_override", {}))
    result = verify_decision_ref(vector["envelope"], trust)
    assert result.ok == (vector["expect"] == "accept"), (vector["id"], result.reason)
    if vector["expect"] == "reject":
        expected = {
            "signer_equals_runtime": REASON_SIGNER_EQUALS_RUNTIME,
            "verdict_not_recomputable": REASON_VERDICT_NOT_RECOMPUTABLE,
        }[vector["failure_mode"]]
        assert result.reason == expected


def test_negatives_are_cryptographically_valid_so_only_semantics_reject_them():
    """The point of the pair: both signatures verify. Signature checking alone
    is not admission control."""
    for vector in NEGATIVES["vectors"]:
        if vector["expect"] != "reject":
            continue
        ref = vector["envelope"]["evidence"][0]
        signer = ref["signer"]
        assert sign_evidence(ref["content_hash"], signer, key="01" * 32) == ref["signature"]


def test_vector_set_leads_with_the_negatives():
    modes = {v.get("failure_mode") for v in NEGATIVES["vectors"]}
    assert {"signer_equals_runtime", "verdict_not_recomputable"} <= modes
    assert any(v["expect"] == "accept" for v in NEGATIVES["vectors"])
