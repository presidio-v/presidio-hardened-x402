"""v0.6.0 hardening: hard startup-gates for the *_KEY env vars + replay namespace.

The gates convert a silently-insecure default (per-process fingerprint/chain key)
into a fail-closed ``ConfigurationError`` when the operator sets the matching
``PRESIDIO_X402_REQUIRE_*_KEY`` opt-in. Tested via the extracted loader functions
so no module reload is needed.
"""

from __future__ import annotations

import pytest

from presidio_x402 import audit_log, replay_guard
from presidio_x402.exceptions import ConfigurationError, ReplayDetectedError

VALID_HEX = "ab" * 32  # 32 bytes


# --- fingerprint key gate (replay_guard) -----------------------------------


def test_fingerprint_gate_raises_when_required_and_missing(monkeypatch):
    monkeypatch.delenv("PRESIDIO_X402_FINGERPRINT_KEY", raising=False)
    monkeypatch.setenv("PRESIDIO_X402_REQUIRE_FINGERPRINT_KEY", "1")
    with pytest.raises(ConfigurationError):
        replay_guard._load_fingerprint_key()


def test_fingerprint_gate_raises_on_bad_hex_when_required(monkeypatch):
    monkeypatch.setenv("PRESIDIO_X402_FINGERPRINT_KEY", "nothex")
    monkeypatch.setenv("PRESIDIO_X402_REQUIRE_FINGERPRINT_KEY", "true")
    with pytest.raises(ConfigurationError):
        replay_guard._load_fingerprint_key()


def test_fingerprint_valid_key_loads_with_gate_on(monkeypatch):
    monkeypatch.setenv("PRESIDIO_X402_FINGERPRINT_KEY", VALID_HEX)
    monkeypatch.setenv("PRESIDIO_X402_REQUIRE_FINGERPRINT_KEY", "1")
    assert replay_guard._load_fingerprint_key() == bytes.fromhex(VALID_HEX)


def test_fingerprint_missing_without_gate_falls_back(monkeypatch):
    monkeypatch.delenv("PRESIDIO_X402_FINGERPRINT_KEY", raising=False)
    monkeypatch.delenv("PRESIDIO_X402_REQUIRE_FINGERPRINT_KEY", raising=False)
    key = replay_guard._load_fingerprint_key()
    assert isinstance(key, bytes) and len(key) == 32  # per-process fallback, no raise


# --- chain key gate (audit_log) --------------------------------------------


def test_chain_gate_raises_when_required_and_missing(monkeypatch):
    monkeypatch.delenv("PRESIDIO_X402_CHAIN_KEY", raising=False)
    monkeypatch.setenv("PRESIDIO_X402_REQUIRE_CHAIN_KEY", "yes")
    with pytest.raises(ConfigurationError):
        audit_log._load_chain_key()


def test_chain_valid_key_loads_with_gate_on(monkeypatch):
    monkeypatch.setenv("PRESIDIO_X402_CHAIN_KEY", VALID_HEX)
    monkeypatch.setenv("PRESIDIO_X402_REQUIRE_CHAIN_KEY", "1")
    assert audit_log._load_chain_key() == bytes.fromhex(VALID_HEX)


def test_chain_missing_without_gate_falls_back(monkeypatch):
    monkeypatch.delenv("PRESIDIO_X402_CHAIN_KEY", raising=False)
    monkeypatch.delenv("PRESIDIO_X402_REQUIRE_CHAIN_KEY", raising=False)
    key = audit_log._load_chain_key()
    assert isinstance(key, bytes) and len(key) == 32


# --- multi-tenant replay namespace -----------------------------------------


def test_replay_namespace_rejects_unsafe_chars():
    for bad in ("a:b", "glob*", "ns?", "[set]", "has space"):
        with pytest.raises(ConfigurationError):
            replay_guard.ReplayGuard(namespace=bad)


def test_replay_namespace_accepts_safe_token():
    # In-memory backend constructs fine; namespace is validated regardless.
    guard = replay_guard.ReplayGuard(namespace="tenant_42.eu-1")
    guard.check_and_record("fp-a")  # functions normally
    with pytest.raises(ReplayDetectedError):
        guard.check_and_record("fp-a")  # replay


def test_redis_store_prefix_folds_namespace():
    # redis.from_url does not connect eagerly, so this needs no live server.
    store = replay_guard._RedisStore("redis://localhost:6379/0", namespace="tenantA")
    assert store._prefix == "presidio_x402:replay:tenantA:"
    plain = replay_guard._RedisStore("redis://localhost:6379/0")
    assert plain._prefix == "presidio_x402:replay:"
