"""Tests for the arch-translucency adapter — the fail-closed verification gate
that turns a signed degradation envelope into a trusted SLOTrigger (v0.7.0)."""

from __future__ import annotations

import pytest

from presidio_x402.arch_translucency_adapter import (
    DEFAULT_ARCH_SIGNER,
    ArchTranslucencyAdapter,
    SLOTriggerError,
)
from presidio_x402.mica import sha256_hex, sign_evidence

ARCH_PRIV = "03" * 32
OTHER_PRIV = "04" * 32


def _ed25519_pub(priv_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return (
        sk.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def _envelope(content: dict, *, signer: str, key: str, **ref_override) -> dict:
    ch = sha256_hex(content)
    sig = sign_evidence(ch, signer, algorithm="ed25519", key=key)
    ref = {
        "item_id": "SLO-DEGRADED",
        "source": signer,
        "source_version": "0.16.0",
        "ledger_ref": "arch-translucency:slo/1",
        "content_hash": ch,
        "signer": signer,
        "signature": sig,
        "claimed_at": "2026-06-21T10:00:00+00:00",
    }
    ref.update(ref_override)
    return {
        "schema": "presidio-hardened/evidence-ref@1",
        "evidence": [ref],
        "attested_content": content,
    }


def _content(value: int = 420, threshold: int = 200) -> dict:
    return {"slo": "p99_latency_ms", "value": value, "threshold": threshold, "window": "5m"}


def _adapter(**kw) -> ArchTranslucencyAdapter:
    pytest.importorskip("cryptography")
    trust = {DEFAULT_ARCH_SIGNER: {"alg": "ed25519", "public_key": _ed25519_pub(ARCH_PRIV)}}
    return ArchTranslucencyAdapter(trust, **kw)


def test_valid_signed_envelope_yields_degraded_trigger():
    adapter = _adapter()
    env = _envelope(_content(420, 200), signer=DEFAULT_ARCH_SIGNER, key=ARCH_PRIV)
    triggers = adapter.build_triggers(env)
    assert len(triggers) == 1
    t = triggers[0]
    assert t.slo == "p99_latency_ms" and t.value == 420 and t.threshold == 200
    assert t.degraded is True
    assert t.signer == DEFAULT_ARCH_SIGNER
    assert adapter.rejected == 0


def test_non_degraded_envelope_is_verified_but_not_degraded():
    adapter = _adapter()
    env = _envelope(_content(120, 200), signer=DEFAULT_ARCH_SIGNER, key=ARCH_PRIV)
    t = adapter.build_trigger_strict(env)
    assert t.degraded is False  # verified, but no breach → broker will skip


def test_tampered_content_fails_closed():
    adapter = _adapter()
    env = _envelope(_content(420, 200), signer=DEFAULT_ARCH_SIGNER, key=ARCH_PRIV)
    # Mutate the content after signing → content_hash no longer matches.
    env["attested_content"]["value"] = 9999
    assert adapter.build_triggers(env) == []
    assert adapter.rejected == 1


def test_untrusted_signer_fails_closed():
    adapter = _adapter()
    # Signed by a key the trust store doesn't know.
    env = _envelope(_content(), signer=DEFAULT_ARCH_SIGNER, key=OTHER_PRIV)
    assert adapter.build_triggers(env) == []


def test_expected_signers_allowlist_excludes_other_signer():
    pytest.importorskip("cryptography")
    # Trust store knows two signers, but adapter only expects the arch one.
    trust = {
        DEFAULT_ARCH_SIGNER: {"alg": "ed25519", "public_key": _ed25519_pub(ARCH_PRIV)},
        "rogue": {"alg": "ed25519", "public_key": _ed25519_pub(OTHER_PRIV)},
    }
    adapter = ArchTranslucencyAdapter(trust, expected_signers=[DEFAULT_ARCH_SIGNER])
    env = _envelope(_content(), signer="rogue", key=OTHER_PRIV)
    assert adapter.build_triggers(env) == []


def test_missing_attested_content_fails_closed():
    adapter = _adapter()
    env = _envelope(_content(), signer=DEFAULT_ARCH_SIGNER, key=ARCH_PRIV)
    del env["attested_content"]
    assert adapter.build_triggers(env) == []


def test_strict_raises_when_no_verified_trigger():
    adapter = _adapter()
    env = _envelope(_content(), signer=DEFAULT_ARCH_SIGNER, key=OTHER_PRIV)
    with pytest.raises(SLOTriggerError):
        adapter.build_trigger_strict(env)


def test_field_map_override():
    pytest.importorskip("cryptography")
    trust = {DEFAULT_ARCH_SIGNER: {"alg": "ed25519", "public_key": _ed25519_pub(ARCH_PRIV)}}
    adapter = ArchTranslucencyAdapter(
        trust, field_map={"value": "observed_ms", "threshold": "budget_ms"}
    )
    content = {"slo": "p99", "observed_ms": 500, "budget_ms": 200, "window": "1m"}
    env = _envelope(content, signer=DEFAULT_ARCH_SIGNER, key=ARCH_PRIV)
    t = adapter.build_trigger_strict(env)
    assert t.value == 500 and t.threshold == 200 and t.degraded is True
