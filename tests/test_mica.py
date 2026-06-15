"""Tests for the MiCA/EU evidence module (session-3 T3).

Covers: the cross-repo evidence-ref@1 wire format (golden vector byte-identical
to presidio-hardened-ai / ikigov-assess), honest-claims selection logic
(obligations only emitted when the audit window supports them and deployment
flags assert what the middleware cannot observe), and fail-closed behaviour.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from presidio_x402._types import AuditEvent
from presidio_x402.compliance_report import ComplianceReport
from presidio_x402.mica import (
    OBLIGATION_MAP,
    EvidenceError,
    applicable_obligations,
    build_evidence,
    canonical_bytes,
    sha256_hex,
    sign_evidence,
)

# ---------------------------------------------------------------------------
# Cross-repo golden vector — pins the wire format. Byte-identical to the
# vectors committed in presidio-hardened-ai tests/test_ed25519.py and
# ikigov-assess tests/test_evidence.py. Do not change within evidence-ref@1.
# ---------------------------------------------------------------------------

GOLD_PRIV = "01" * 32
GOLD_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
GOLD_CH = "abc123def456"
GOLD_SIGNER = "presidio-hardened-ai"
GOLD_SIG = (
    "a0dc8599958734457f194ebce15c60ec097754b59897ab5dc758f73abadafe36"
    "97874049d9f7736de4e3a9cc28b2fb4d76b15d8bce7fa0b26c8434bebbba590a"
)
GOLD_HMAC_KEY = "shared-key"
GOLD_HMAC_SIG = "2e7af6d2882dd53847dcf3032e1fe36e58c5a879c224ea97b505b3e3b626b87a"


def test_golden_vector_ed25519_byte_identical():
    assert sign_evidence(GOLD_CH, GOLD_SIGNER, algorithm="ed25519", key=GOLD_PRIV) == GOLD_SIG


def test_golden_vector_hmac_byte_identical():
    sig = sign_evidence(GOLD_CH, GOLD_SIGNER, algorithm="hmac-sha256", key=GOLD_HMAC_KEY)
    assert sig == GOLD_HMAC_SIG


def test_canonical_profile_matches_family():
    payload = {"b": "2", "a": "1", "u": "ß"}
    assert canonical_bytes(payload) == '{"a":"1","b":"2","u":"ß"}'.encode()


def test_signing_fails_closed():
    with pytest.raises(EvidenceError):
        sign_evidence(GOLD_CH, GOLD_SIGNER, key="")  # no key
    with pytest.raises(EvidenceError):
        sign_evidence(GOLD_CH, GOLD_SIGNER, algorithm="rsa-pss", key=GOLD_PRIV)
    with pytest.raises(EvidenceError):
        sign_evidence(GOLD_CH, GOLD_SIGNER, algorithm="ed25519", key="zz" * 32)


# ---------------------------------------------------------------------------
# Audit-window fixtures
# ---------------------------------------------------------------------------


def _event(event_type: str, ts: str = "2026-06-12T10:00:00+00:00") -> AuditEvent:
    return AuditEvent(
        timestamp=datetime.fromisoformat(ts).astimezone(timezone.utc),
        event_type=event_type,
        resource_url="https://api.example.com/v1/data",
        amount_usd=0.01,
        network="base-sepolia",
        agent_id="test-agent",
        outcome="blocked" if event_type.endswith("BLOCKED") else "allowed",
    )


def _report(*event_types: str) -> ComplianceReport:
    return ComplianceReport.from_events([_event(t) for t in event_types])


FULL_WINDOW = (
    "PAYMENT_ALLOWED",
    "PII_REDACTED",
    "REPLAY_BLOCKED",
    "POLICY_BLOCKED",
)


# ---------------------------------------------------------------------------
# Honest-claims selection
# ---------------------------------------------------------------------------


def test_default_selection_on_full_window():
    ids = {o.item_id for o in applicable_obligations(_report(*FULL_WINDOW))}
    assert ids == {
        "MICA-68-9-RECORDS",
        "MICA-68-8-INTEGRITY",
        "DORA-17-2-SECURITY-EVENTS",
        "GDPR-5-1C-MINIMISATION",
        "TFR-14-4-LAYER-SEPARATION",
    }


def test_no_redaction_no_gdpr_and_no_tfr_claims():
    ids = {o.item_id for o in applicable_obligations(_report("PAYMENT_ALLOWED"))}
    assert "GDPR-5-1C-MINIMISATION" not in ids
    assert "TFR-14-4-LAYER-SEPARATION" not in ids
    assert "DORA-17-2-SECURITY-EVENTS" not in ids  # no security events either
    assert "MICA-68-9-RECORDS" in ids  # records exist regardless


def test_ppaet_item_needs_flags_and_replay_data():
    report = _report(*FULL_WINDOW)
    # Data present but flags absent → not emitted.
    assert "MICA-92-1-PPAET-INPUT" not in {o.item_id for o in applicable_obligations(report)}
    # Flags present and replay data present → emitted.
    flagged = applicable_obligations(
        report, deployment_flags=frozenset({"ppaet", "admitted_to_trading"})
    )
    assert "MICA-92-1-PPAET-INPUT" in {o.item_id for o in flagged}
    # Flags present but NO replay data → still not emitted (honest-claims).
    no_replay = applicable_obligations(
        _report("PAYMENT_ALLOWED", "PII_REDACTED"),
        deployment_flags=frozenset({"ppaet", "admitted_to_trading"}),
    )
    assert "MICA-92-1-PPAET-INPUT" not in {o.item_id for o in no_replay}


def test_explicit_include_without_flags_fails_closed():
    with pytest.raises(EvidenceError):
        applicable_obligations(_report(*FULL_WINDOW), include=["MICA-92-1-PPAET-INPUT"])


def test_no_amlr_mappings_until_verified():
    # AMLR (EU) 2024/1624 article content was UNVERIFIED at authoring time —
    # the map must not cite it (docs/mica-obligations.md guardrail).
    assert not any("2024/1624" in o.regulation for o in OBLIGATION_MAP)


def test_obligation_map_hygiene():
    ids = [o.item_id for o in OBLIGATION_MAP]
    assert len(set(ids)) == len(ids)
    for ob in OBLIGATION_MAP:
        assert ob.verification in ("VERIFIED-PRIMARY", "VERIFIED-SECONDARY")
        assert ob.attests and ob.article and ob.regulation
        # The TFR entry must stay a negative/clarifying attestation.
        if ob.item_id.startswith("TFR-"):
            assert "no claim that redaction supports TFR compliance" in ob.attests


# ---------------------------------------------------------------------------
# Envelope building — evidence-ref@1 contract
# ---------------------------------------------------------------------------

CONTRACT_FIELDS = {
    "item_id",
    "source",
    "source_version",
    "ledger_ref",
    "content_hash",
    "signer",
    "signature",
    "claimed_at",
}


def test_envelope_matches_evidence_ref_contract():
    env = build_evidence(_report(*FULL_WINDOW), signing_key=GOLD_PRIV)
    assert env["schema"] == "presidio-hardened/evidence-ref@1"
    assert env["evidence"], "envelope must contain refs"
    for ref in env["evidence"]:
        assert set(ref) == CONTRACT_FIELDS
        for value in ref.values():
            assert isinstance(value, str) and value and len(value) <= 512
        assert ref["content_hash"] == sha256_hex(env["attested_content"])


def test_envelope_signature_verifies_with_family_verifier():
    """The emitted signature must verify under the exact consumer-side check
    used by ikigov-assess (Ed25519 over canonical {content_hash, signer})."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ed25519

    env = build_evidence(_report(*FULL_WINDOW), signing_key=GOLD_PRIV)
    ref = env["evidence"][0]
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(GOLD_PRIV))
    pk = sk.public_key()
    message = canonical_bytes({"content_hash": ref["content_hash"], "signer": ref["signer"]})
    pk.verify(bytes.fromhex(ref["signature"]), message)  # raises on failure


def test_attested_content_is_pii_free_summary():
    env = build_evidence(_report(*FULL_WINDOW), signing_key=GOLD_PRIV)
    content = env["attested_content"]
    assert set(content) == {"event_counts", "n_events", "chain_ok", "window_first", "window_last"}
    assert content["n_events"] == len(FULL_WINDOW)
    # No URLs, agent ids, or amounts — counts and window bounds only.
    assert "resource_url" not in str(content)


def test_envelope_carries_human_reviewable_obligations_and_disclaimer():
    env = build_evidence(_report(*FULL_WINDOW), signing_key=GOLD_PRIV)
    assert len(env["obligations"]) == len(env["evidence"])
    assert "makes no compliance claim" in env["disclaimer"]
    for ob in env["obligations"]:
        assert ob["verification"] in ("VERIFIED-PRIMARY", "VERIFIED-SECONDARY")


def test_build_evidence_fails_closed_on_broken_chain():
    report = _report(*FULL_WINDOW)
    report.chain_ok = False
    with pytest.raises(EvidenceError):
        build_evidence(report, signing_key=GOLD_PRIV)


def test_build_evidence_fails_closed_on_empty_support():
    with pytest.raises(EvidenceError):
        build_evidence(ComplianceReport.from_events([]), signing_key=GOLD_PRIV)


def test_hmac_mode_works_without_crypto_extra():
    env = build_evidence(_report(*FULL_WINDOW), signing_key="shared-key", algorithm="hmac-sha256")
    assert env["signing_algorithm"] == "hmac-sha256"
    assert all(len(ref["signature"]) == 64 for ref in env["evidence"])  # HMAC-SHA256 hex
