"""Conformance of mica.py against the vendored presidio-evidence golden vectors.

This is v0.6.0 Evidence Phase-A, vectors-first. Rather than hardcode the family
golden constants (as ``test_mica.py`` historically did), these tests drive off the
**vendored vector files** under ``tests/evidence-vectors/`` — a byte-for-byte copy
of the normative ``presidio-evidence`` contract (``schemas/`` + ``vectors/`` are the
contract per ADR-0001, not the implementation). When ``presidio-evidence``
regenerates its vectors, re-vendoring changes these files and the provenance test
flags the drift before any version bump.

Patent posture: this vendors the *contract* (public-safe defensive-publication
material per the evidence ADR-0001 Q4). It imports nothing from the private
``presidio-evidence`` package; ``mica.py`` is x402's own conforming implementation.
The ``import presidio_evidence`` consolidation (Phase-B) is deferred to a
post-non-provisional point release — see ``plan/v060-v070-scope.md``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from presidio_x402.mica import (
    EvidenceError,
    canonical_bytes,
    load_trust_store,
    parse_document,
    sha256_hex,
    sign_evidence,
    verify_ed25519,
    verify_hmac,
    verify_ref,
)

VECTORS = Path(__file__).parent / "evidence-vectors"


def _load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Provenance — drift detection inside x402's own tree
# ---------------------------------------------------------------------------


def test_vendored_vectors_match_provenance_hashes():
    """Every vendored file's SHA-256 matches PROVENANCE.json. A mismatch means
    the vectors were edited in place or partially re-vendored — investigate
    before trusting any conformance result below."""
    prov = _load("PROVENANCE.json")
    assert prov["source_repo"] == "presidio-evidence"
    for rel, expected in prov["files"].items():
        actual = hashlib.sha256((VECTORS / rel).read_bytes()).hexdigest()
        assert actual == expected, f"vendored vector drift: {rel}"


# ---------------------------------------------------------------------------
# Layer 0 — canonical JSON + content hashing
# ---------------------------------------------------------------------------


def test_canonical_json_cases_byte_identical():
    data = _load("canonical-json/vectors.json")
    for case in data["cases"]:
        produced = canonical_bytes(case["payload"]).decode("utf-8")
        assert produced == case["canonical"], case["name"]
        assert sha256_hex(case["payload"]) == case["sha256_hex"], case["name"]


def test_canonical_json_rejects_floats():
    data = _load("canonical-json/vectors.json")
    assert data["rejected"], "vector file must carry rejected (float) cases"
    for case in data["rejected"]:
        with pytest.raises(EvidenceError):
            canonical_bytes(case["payload"])


# ---------------------------------------------------------------------------
# Layer 1 — signing + verification (Ed25519 + HMAC), with tamper cases
# ---------------------------------------------------------------------------


def test_ed25519_golden_sign_and_verify():
    pytest.importorskip("cryptography")
    g = _load("signing/ed25519-golden.json")
    sig = sign_evidence(
        g["content_hash"], g["signer"], algorithm="ed25519", key=g["private_key_hex"]
    )
    assert sig == g["signature_hex"]
    # Direct verifier
    assert verify_ed25519(g["content_hash"], g["signer"], g["signature_hex"], g["public_key_hex"])
    # Through a trust store + verify_ref
    trust = load_trust_store({g["signer"]: {"alg": "ed25519", "public_key": g["public_key_hex"]}})
    ref = {
        "content_hash": g["content_hash"],
        "signer": g["signer"],
        "signature": g["signature_hex"],
    }
    assert verify_ref(ref, trust) is True


def test_ed25519_tamper_cases_fail_closed():
    pytest.importorskip("cryptography")
    g = _load("signing/ed25519-golden.json")
    for t in g["tamper_cases"]:
        got = verify_ed25519(
            t["content_hash"], t["signer"], t["signature_hex"], t["public_key_hex"]
        )
        assert got is t["verifies"], t["reason"]


def test_hmac_golden_sign_and_verify():
    g = _load("signing/hmac-sha256-golden.json")
    sig = sign_evidence(g["content_hash"], g["signer"], algorithm="hmac-sha256", key=g["key"])
    assert sig == g["signature_hex"]
    assert verify_hmac(g["content_hash"], g["signer"], g["signature_hex"], g["key"])
    trust = load_trust_store({g["signer"]: {"alg": "hmac-sha256", "key": g["key"]}})
    ref = {
        "content_hash": g["content_hash"],
        "signer": g["signer"],
        "signature": g["signature_hex"],
    }
    assert verify_ref(ref, trust) is True


def test_hmac_tamper_cases_fail_closed():
    g = _load("signing/hmac-sha256-golden.json")
    for t in g["tamper_cases"]:
        got = verify_hmac(t["content_hash"], t["signer"], t["signature_hex"], t["key"])
        assert got is t["verifies"], t["reason"]


def test_verify_ref_unknown_signer_and_alg_mismatch_fail_closed():
    g = _load("signing/hmac-sha256-golden.json")
    ref = {
        "content_hash": g["content_hash"],
        "signer": g["signer"],
        "signature": g["signature_hex"],
    }
    # Unknown signer → False
    assert verify_ref(ref, load_trust_store({"someone-else": "shared-key"})) is False
    # Right signer, but trust store declares the wrong algorithm → False (no fail-open)
    pytest.importorskip("cryptography")
    wrong_alg = load_trust_store({g["signer"]: {"alg": "ed25519", "public_key": "00" * 32}})
    assert verify_ref(ref, wrong_alg) is False


def test_verify_ref_malformed_raw_trust_entry_returns_false():
    g = _load("signing/hmac-sha256-golden.json")
    ref = {
        "content_hash": g["content_hash"],
        "signer": g["signer"],
        "signature": g["signature_hex"],
    }
    trust = {g["signer"]: {"alg": "hmac-sha256", "key": []}}
    assert verify_ref(ref, trust) is False


# ---------------------------------------------------------------------------
# Trust store — structural conformance
# ---------------------------------------------------------------------------


def test_trust_store_valid_loads_with_rotation():
    pytest.importorskip("cryptography")
    norm = load_trust_store(_load("trust-store/valid.json"))
    assert set(norm) == {
        "presidio-hardened-ai",
        "rotating-signer",
        "legacy-hmac-bare",
        "hmac-object",
    }
    assert len(norm["rotating-signer"]["keys"]) == 2  # rotation key list preserved
    assert norm["legacy-hmac-bare"] == {"alg": "hmac-sha256", "keys": ["shared-key"]}


@pytest.mark.parametrize(
    "rel",
    [p.name for p in sorted((VECTORS / "trust-store").glob("invalid-*.json"))],
)
def test_trust_store_invalid_rejected(rel: str):
    with pytest.raises(EvidenceError):
        load_trust_store(_load(f"trust-store/{rel}"))


# ---------------------------------------------------------------------------
# Evidence-ref envelope — structural parse (fail-closed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel",
    [
        p.name
        for p in sorted((VECTORS / "evidence-ref").glob("valid-*.json"))
        if ".notes." not in p.name
    ],
)
def test_evidence_ref_valid_parses(rel: str):
    refs = parse_document(_load(f"evidence-ref/{rel}"))
    assert isinstance(refs, list)


@pytest.mark.parametrize(
    "rel",
    [p.name for p in sorted((VECTORS / "evidence-ref").glob("invalid-*.json"))],
)
def test_evidence_ref_invalid_rejected(rel: str):
    with pytest.raises(EvidenceError):
        parse_document(_load(f"evidence-ref/{rel}"))
