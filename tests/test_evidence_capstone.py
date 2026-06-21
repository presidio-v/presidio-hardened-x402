"""v0.6.0 Evidence Phase-A — end-to-end capstone.

Where ``test_evidence_conformance.py`` pins wire-bytes to the vendored vectors,
this proves the two Phase-A halves *compose* in a realistic flow:

    audit window → ComplianceReport → mica.build_evidence (sign)
        → JSON wire (ship to a sink) → parse_document → trust store → verify_ref

It also asserts the exact gate v0.7.0's SLO broker will use — a signed degradation
trigger from ``presidio-hardened-arch-translucency`` is verified fail-closed before
any payment — and that the audit *records* themselves fan out through the remote
sink path. No network: transports and signers are local.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from presidio_x402._types import AuditEvent
from presidio_x402.audit_sinks import MultiAuditWriter, S3AuditWriter
from presidio_x402.compliance_report import ComplianceReport
from presidio_x402.mica import (
    DEFAULT_SIGNER,
    EvidenceError,
    build_evidence,
    load_trust_store,
    parse_document,
    sha256_hex,
    sign_evidence,
    verify_ref,
)

# Family golden Ed25519 keypair (priv 01*32 → this pub); x402 signs as DEFAULT_SIGNER.
GOLD_PRIV = "01" * 32
GOLD_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
ARCH_SIGNER = "presidio-hardened-arch-translucency"
ARCH_PRIV = "02" * 32

FULL_WINDOW = ("PAYMENT_ALLOWED", "PII_REDACTED", "REPLAY_BLOCKED", "POLICY_BLOCKED")


# --- helpers ---------------------------------------------------------------


def _event(event_type: str, i: int = 0) -> AuditEvent:
    return AuditEvent(
        timestamp=datetime(2026, 6, 21, 10, i % 60, tzinfo=timezone.utc),
        event_type=event_type,
        resource_url=f"https://api.example.com/v1/data/{i}",
        amount_usd=0.01,
        network="base-sepolia",
        agent_id="agent-x",
        outcome="blocked" if event_type.endswith("BLOCKED") else "allowed",
    )


def _window() -> tuple[ComplianceReport, list[AuditEvent]]:
    events = [_event(t, i) for i, t in enumerate(FULL_WINDOW)]
    return ComplianceReport.from_events(events), events


def _ed25519_pub(priv_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return (
        sk.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def _slo_trigger_ref(*, signer: str, key: str, value: int = 420, **override) -> dict:
    """A signed SLO degradation trigger as arch-translucency would emit it."""
    content = {"slo": "p99_latency_ms", "value": value, "threshold": 200, "window": "5m"}
    content_hash = sha256_hex(content)
    signature = sign_evidence(content_hash, signer, algorithm="ed25519", key=key)
    ref = {
        "item_id": "SLO-DEGRADED",
        "source": signer,
        "source_version": "0.16.0",
        "ledger_ref": "arch-translucency:slo/1",
        "content_hash": content_hash,
        "signer": signer,
        "signature": signature,
        "claimed_at": "2026-06-21T10:00:00+00:00",
    }
    ref.update(override)
    return ref


class _FakeS3:
    def __init__(self):
        self.puts: list[dict] = []

    def put_object(self, *, Bucket, Key, Body):  # noqa: N803 - boto3 PascalCase kwargs
        self.puts.append({"Bucket": Bucket, "Key": Key, "Body": Body})


class _ListWriter:
    def __init__(self):
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)

    def flush(self) -> None:
        pass


# --- producer → verify round-trip ------------------------------------------


def test_end_to_end_ed25519_roundtrip():
    pytest.importorskip("cryptography")
    report, _ = _window()
    env = build_evidence(report, signing_key=GOLD_PRIV, algorithm="ed25519")
    trust = load_trust_store({DEFAULT_SIGNER: {"alg": "ed25519", "public_key": GOLD_PUB}})
    refs = parse_document(env)
    assert refs, "envelope must carry refs"
    assert all(verify_ref(r, trust) is True for r in refs)


def test_end_to_end_hmac_roundtrip():
    report, _ = _window()
    env = build_evidence(report, signing_key="shared-key", algorithm="hmac-sha256")
    trust = load_trust_store({DEFAULT_SIGNER: {"alg": "hmac-sha256", "key": "shared-key"}})
    assert all(verify_ref(r, trust) is True for r in parse_document(env))


# --- both halves travel: audit records via sink + evidence via JSON wire ----


def test_audit_records_fan_out_through_remote_sink():
    _, events = _window()
    listing, s3 = _ListWriter(), _FakeS3()
    multi = MultiAuditWriter(listing, S3AuditWriter(bucket="b", client=s3, batch_size=1))
    for e in events:
        multi.write(e)
    assert len(listing.events) == len(events)  # local capture
    assert len(s3.puts) == len(events)  # central retention (one object/event at batch_size=1)


def test_signed_evidence_survives_json_wire_and_reverifies():
    pytest.importorskip("cryptography")
    report, _ = _window()
    env = build_evidence(report, signing_key=GOLD_PRIV, algorithm="ed25519")
    # Serialize → transport (e.g. S3/SIEM) → read back, exactly as a sink would.
    shipped = json.dumps(env, default=str)
    received = json.loads(shipped)
    trust = load_trust_store({DEFAULT_SIGNER: {"alg": "ed25519", "public_key": GOLD_PUB}})
    assert all(verify_ref(r, trust) is True for r in parse_document(received))


# --- fail-closed end-to-end -------------------------------------------------


@pytest.mark.parametrize("field", ["content_hash", "signature", "signer"])
def test_tampered_ref_fails_closed(field):
    pytest.importorskip("cryptography")
    report, _ = _window()
    env = build_evidence(report, signing_key=GOLD_PRIV, algorithm="ed25519")
    trust = load_trust_store({DEFAULT_SIGNER: {"alg": "ed25519", "public_key": GOLD_PUB}})
    ref = dict(env["evidence"][0])
    if field == "signer":
        ref[field] = "evil-signer"
    else:
        original = ref[field]
        flipped = ("0" if original[0] != "0" else "1") + original[1:]
        ref[field] = flipped
    assert verify_ref(ref, trust) is False


def test_wrong_trust_store_fails_closed():
    pytest.importorskip("cryptography")
    report, _ = _window()
    env = build_evidence(report, signing_key=GOLD_PRIV, algorithm="ed25519")
    wrong = load_trust_store({DEFAULT_SIGNER: {"alg": "ed25519", "public_key": "00" * 32}})
    assert all(verify_ref(r, wrong) is False for r in parse_document(env))


def test_build_evidence_fails_closed_on_broken_chain():
    report, _ = _window()
    report.chain_ok = False
    with pytest.raises(EvidenceError):
        build_evidence(report, signing_key=GOLD_PRIV)


# --- the v0.7.0 SLO-broker gate ---------------------------------------------


def test_v07_broker_gate_verifies_signed_slo_trigger():
    """The exact check the v0.7.0 SLOPaymentBroker will run before paying:
    accept a degradation trigger only if it is a signed evidence-ref from a
    trusted arch-translucency signer; reject forged or untrusted triggers."""
    pytest.importorskip("cryptography")
    broker_trust = load_trust_store(
        {ARCH_SIGNER: {"alg": "ed25519", "public_key": _ed25519_pub(ARCH_PRIV)}}
    )
    genuine = _slo_trigger_ref(signer=ARCH_SIGNER, key=ARCH_PRIV)
    assert verify_ref(genuine, broker_trust) is True  # payment would be authorized

    # Forged: attacker re-signs the same content with a key the broker doesn't trust.
    forged = _slo_trigger_ref(signer=ARCH_SIGNER, key=GOLD_PRIV)
    assert verify_ref(forged, broker_trust) is False  # no payment

    # Untrusted signer entirely absent from the broker's trust store.
    assert verify_ref(genuine, load_trust_store({"someone-else": "k"})) is False


def test_multi_signer_trust_store_verifies_self_and_arch():
    pytest.importorskip("cryptography")
    report, _ = _window()
    x402_ref = parse_document(build_evidence(report, signing_key=GOLD_PRIV))[0]
    arch_ref = _slo_trigger_ref(signer=ARCH_SIGNER, key=ARCH_PRIV)
    trust = load_trust_store(
        {
            DEFAULT_SIGNER: {"alg": "ed25519", "public_key": GOLD_PUB},
            ARCH_SIGNER: {"alg": "ed25519", "public_key": _ed25519_pub(ARCH_PRIV)},
        }
    )
    assert verify_ref(x402_ref, trust) is True
    assert verify_ref(arch_ref, trust) is True
