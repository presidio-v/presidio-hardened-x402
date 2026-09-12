# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Tests for pay-to pinning — trust-on-first-use recipient-rotation detection.

Motivated by MCRI #001 (probe402, 21–31 August 2026): 33 of 6,835 quoted
endpoints changed their payment address between observations, one on nearly
every probe. A static allowlist cannot be maintained against that; pinning
records the first address per (origin, network) and reports every divergence.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from presidio_x402 import HardenedX402Client, WalletPinStore
from presidio_x402._types import AuditEvent, PaymentDetails, PaymentResponse
from presidio_x402.audit_log import AuditLog, NullAuditWriter
from presidio_x402.core import ScreeningPipeline
from presidio_x402.exceptions import ConfigurationError, WalletRotationError, X402PaymentError
from presidio_x402.pii_filter import PIIFilter
from presidio_x402.policy_engine import PolicyEngine
from presidio_x402.replay_guard import ReplayGuard
from presidio_x402.wallet_pin import pin_key

ORIGIN = "https://api.example.com"
WALLET_A = "0x" + "ab" * 20
WALLET_B = "0x2222222222222222222222222222222222222222"
WALLET_A_CHECKSUMMED = "0x" + "aB" * 20


class _RecordingAuditWriter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)

    def flush(self) -> None:
        pass


def _header(
    pay_to: str, resource: str, network: str = "base-sepolia", amount: str = "0.01"
) -> str:
    return json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": network,
                    "maxAmountRequired": amount,
                    "resource": resource,
                    "description": "API data access",
                    "payTo": pay_to,
                    "requiredDeadlineSeconds": 300,
                }
            ]
        }
    )


def _events(audit: _RecordingAuditWriter, event_type: str) -> list[AuditEvent]:
    return [e for e in audit.events if e.event_type == event_type]


async def _signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="mock-signed-token", details=details)  # noqa: S106


def _mock_402(url: str, pay_to: str, **kw) -> None:
    respx.get(url).side_effect = [
        httpx.Response(402, headers={"X-PAYMENT": _header(pay_to, url, **kw)}),
        httpx.Response(200, text="ok"),
    ]


# ---------------------------------------------------------------------------
# WalletPinStore
# ---------------------------------------------------------------------------


class TestWalletPinStore:
    def test_first_observation_pins_and_returns_none(self):
        store = WalletPinStore()
        assert store.observe(ORIGIN, "base", WALLET_A) is None
        assert store.pinned(ORIGIN, "base") == WALLET_A

    def test_later_observation_returns_pin_and_never_overwrites(self):
        store = WalletPinStore()
        store.observe(ORIGIN, "base", WALLET_A)
        assert store.observe(ORIGIN, "base", WALLET_B) == WALLET_A
        assert store.pinned(ORIGIN, "base") == WALLET_A, "observe() must not advance the pin"

    def test_addresses_are_case_insensitive(self):
        store = WalletPinStore()
        store.observe(ORIGIN, "base", WALLET_A.upper())
        assert store.observe(ORIGIN, "base", WALLET_A.lower()) == WALLET_A.lower()

    def test_pin_keyed_on_network_as_well_as_origin(self):
        store = WalletPinStore()
        store.observe(ORIGIN, "base", WALLET_A)
        assert store.observe(ORIGIN, "solana", WALLET_B) is None, "per-rail recipients are legit"
        assert pin_key(ORIGIN + "/", " Base ") == pin_key(ORIGIN, "base")

    def test_explicit_pin_and_forget(self):
        store = WalletPinStore()
        store.observe(ORIGIN, "base", WALLET_A)
        store.pin(ORIGIN, "base", WALLET_B)
        assert store.observe(ORIGIN, "base", WALLET_B) == WALLET_B
        store.forget(ORIGIN, "base")
        assert store.pinned(ORIGIN, "base") is None
        assert store.observe(ORIGIN, "base", WALLET_A) is None

    def test_reset_clears_everything(self):
        store = WalletPinStore()
        store.observe(ORIGIN, "base", WALLET_A)
        store.reset()
        assert store.pinned(ORIGIN, "base") is None

    def test_invalid_namespace_and_ttl_rejected(self):
        with pytest.raises(ConfigurationError, match="namespace"):
            WalletPinStore(namespace="bad:ns")
        with pytest.raises(ConfigurationError, match="ttl"):
            WalletPinStore(ttl=0)

    def test_redis_backend_set_nx_semantics(self, monkeypatch):
        fakeredis = pytest.importorskip("fakeredis")
        import redis

        server = fakeredis.FakeServer()
        monkeypatch.setattr(
            redis, "from_url", lambda url, **kw: fakeredis.FakeRedis(server=server, **kw)
        )
        store = WalletPinStore(redis_url="redis://localhost:6379/0", namespace="tenant-a")
        assert store.observe(ORIGIN, "base", WALLET_A) is None
        assert store.observe(ORIGIN, "base", WALLET_B) == WALLET_A
        # A second process sharing the Redis sees the same pin.
        other = WalletPinStore(redis_url="redis://localhost:6379/0", namespace="tenant-a")
        assert other.pinned(ORIGIN, "base") == WALLET_A
        # A different tenant does not.
        stranger = WalletPinStore(redis_url="redis://localhost:6379/0", namespace="tenant-b")
        assert stranger.pinned(ORIGIN, "base") is None
        store.pin(ORIGIN, "base", WALLET_B)
        assert other.pinned(ORIGIN, "base") == WALLET_B
        store.reset()
        assert other.pinned(ORIGIN, "base") is None


# ---------------------------------------------------------------------------
# Pipeline wiring
# ---------------------------------------------------------------------------


def test_pipeline_rejects_pinning_without_store():
    with pytest.raises(ValueError, match="wallet_pin_store"):
        ScreeningPipeline(
            pii_filter=PIIFilter(),
            policy=PolicyEngine(),
            replay=ReplayGuard(),
            audit=AuditLog(NullAuditWriter()),
            wallet_pinning="block",
        )


def test_pipeline_rejects_unknown_pinning_mode():
    with pytest.raises(ValueError, match="wallet_pinning"):
        ScreeningPipeline(
            pii_filter=PIIFilter(),
            policy=PolicyEngine(),
            replay=ReplayGuard(),
            audit=AuditLog(NullAuditWriter()),
            wallet_pin_store=WalletPinStore(),
            wallet_pinning="loud",  # type: ignore[arg-type]
        )


def test_client_rejects_unknown_pinning_mode():
    with pytest.raises(ValueError, match="wallet_pinning"):
        HardenedX402Client(payment_signer=_signer, wallet_pinning="loud")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# HardenedX402Client end-to-end
# ---------------------------------------------------------------------------


class TestClientPinning:
    @pytest.mark.asyncio
    async def test_default_off_emits_no_pin_events(self):
        audit = _RecordingAuditWriter()
        with respx.mock:
            _mock_402(f"{ORIGIN}/v1/a", WALLET_A)
            _mock_402(f"{ORIGIN}/v1/b", WALLET_B)
            client = HardenedX402Client(payment_signer=_signer, audit_writer=audit)
            try:
                await client.get(f"{ORIGIN}/v1/a")
                await client.get(f"{ORIGIN}/v1/b")
            finally:
                await client.aclose()
        assert client.wallet_pins is None
        assert not _events(audit, "WALLET_PINNED")
        assert not _events(audit, "WALLET_ROTATED")

    @pytest.mark.asyncio
    async def test_first_sight_pins_and_same_address_passes_silently(self):
        audit = _RecordingAuditWriter()
        with respx.mock:
            _mock_402(f"{ORIGIN}/v1/a", WALLET_A)
            _mock_402(f"{ORIGIN}/v1/b", WALLET_A_CHECKSUMMED)
            client = HardenedX402Client(
                payment_signer=_signer, audit_writer=audit, wallet_pinning="block"
            )
            try:
                await client.get(f"{ORIGIN}/v1/a")
                await client.get(f"{ORIGIN}/v1/b")
            finally:
                await client.aclose()
        pinned = _events(audit, "WALLET_PINNED")
        assert len(pinned) == 1 and pinned[0].outcome == "allowed"
        assert not _events(audit, "WALLET_ROTATED")
        assert client.wallet_pins.pinned(ORIGIN, "base-sepolia") == WALLET_A

    @pytest.mark.asyncio
    async def test_block_mode_refuses_rotation_before_signing(self):
        audit = _RecordingAuditWriter()
        signed: list[PaymentDetails] = []

        async def capture(details: PaymentDetails) -> PaymentResponse:
            signed.append(details)
            return PaymentResponse(token="t", details=details)  # noqa: S106

        with respx.mock:
            _mock_402(f"{ORIGIN}/v1/a", WALLET_A)
            respx.get(f"{ORIGIN}/v1/b").mock(
                return_value=httpx.Response(
                    402, headers={"X-PAYMENT": _header(WALLET_B, f"{ORIGIN}/v1/b")}
                )
            )
            client = HardenedX402Client(
                payment_signer=capture,
                audit_writer=audit,
                wallet_pinning="block",
                policy={"daily_limit_usd": 1.0},
            )
            try:
                await client.get(f"{ORIGIN}/v1/a")
                with pytest.raises(WalletRotationError, match="rotated from pinned") as exc:
                    await client.get(f"{ORIGIN}/v1/b")
            finally:
                await client.aclose()

        assert exc.value.pinned == WALLET_A and exc.value.observed == WALLET_B
        assert isinstance(exc.value, X402PaymentError), "existing handlers keep catching it"
        assert [d.pay_to for d in signed] == [WALLET_A]
        rotated = _events(audit, "WALLET_ROTATED")
        assert len(rotated) == 1 and rotated[0].outcome == "blocked"
        assert WALLET_A in rotated[0].error_message and WALLET_B in rotated[0].error_message
        # Blocked before the policy ledger recorded anything — nothing to roll back.
        assert client._policy._global_ledger.total() == pytest.approx(0.01)
        # The pin itself is untouched by the rotation.
        assert client.wallet_pins.pinned(ORIGIN, "base-sepolia") == WALLET_A

    @pytest.mark.asyncio
    async def test_warn_mode_records_rotation_and_proceeds(self):
        audit = _RecordingAuditWriter()
        signed: list[PaymentDetails] = []

        async def capture(details: PaymentDetails) -> PaymentResponse:
            signed.append(details)
            return PaymentResponse(token="t", details=details)  # noqa: S106

        with respx.mock:
            _mock_402(f"{ORIGIN}/v1/a", WALLET_A)
            _mock_402(f"{ORIGIN}/v1/b", WALLET_B)
            _mock_402(f"{ORIGIN}/v1/c", WALLET_B)
            client = HardenedX402Client(
                payment_signer=capture, audit_writer=audit, wallet_pinning="warn"
            )
            try:
                for path in ("a", "b", "c"):
                    resp = await client.get(f"{ORIGIN}/v1/{path}")
                    assert resp.status_code == 200
            finally:
                await client.aclose()

        assert [d.pay_to for d in signed] == [WALLET_A, WALLET_B, WALLET_B]
        rotated = _events(audit, "WALLET_ROTATED")
        # One record per divergent challenge: the pin does not follow the rotation.
        assert len(rotated) == 2 and all(e.outcome == "allowed" for e in rotated)
        assert client.wallet_pins.pinned(ORIGIN, "base-sepolia") == WALLET_A

    @pytest.mark.asyncio
    async def test_operator_accepts_rotation_via_pin(self):
        audit = _RecordingAuditWriter()
        with respx.mock:
            _mock_402(f"{ORIGIN}/v1/a", WALLET_A)
            _mock_402(f"{ORIGIN}/v1/b", WALLET_B)
            client = HardenedX402Client(
                payment_signer=_signer, audit_writer=audit, wallet_pinning="block"
            )
            try:
                await client.get(f"{ORIGIN}/v1/a")
                client.wallet_pins.pin(ORIGIN, "base-sepolia", WALLET_B)
                resp = await client.get(f"{ORIGIN}/v1/b")
            finally:
                await client.aclose()
        assert resp.status_code == 200
        assert not _events(audit, "WALLET_ROTATED")

    @pytest.mark.asyncio
    async def test_explicit_allowlist_origin_is_not_pinned(self):
        """An allowlist may legitimately name several wallets; pinning defers to it."""
        audit = _RecordingAuditWriter()
        with respx.mock:
            _mock_402(f"{ORIGIN}/v1/a", WALLET_A)
            _mock_402(f"{ORIGIN}/v1/b", WALLET_B)
            client = HardenedX402Client(
                payment_signer=_signer,
                audit_writer=audit,
                wallet_pinning="block",
                trusted_wallets={ORIGIN: {WALLET_A, WALLET_B}},
            )
            try:
                await client.get(f"{ORIGIN}/v1/a")
                await client.get(f"{ORIGIN}/v1/b")
            finally:
                await client.aclose()
        assert not _events(audit, "WALLET_PINNED")
        assert not _events(audit, "WALLET_ROTATED")
        assert client.wallet_pins.pinned(ORIGIN, "base-sepolia") is None

    @pytest.mark.asyncio
    async def test_allowlist_still_blocks_and_pinning_covers_other_origins(self):
        audit = _RecordingAuditWriter()
        other = "https://other.example.net"
        with respx.mock:
            respx.get(f"{ORIGIN}/v1/a").mock(
                return_value=httpx.Response(
                    402, headers={"X-PAYMENT": _header(WALLET_B, f"{ORIGIN}/v1/a")}
                )
            )
            _mock_402(f"{other}/v1/a", WALLET_A)
            respx.get(f"{other}/v1/b").mock(
                return_value=httpx.Response(
                    402, headers={"X-PAYMENT": _header(WALLET_B, f"{other}/v1/b")}
                )
            )
            client = HardenedX402Client(
                payment_signer=_signer,
                audit_writer=audit,
                wallet_pinning="block",
                trusted_wallets={ORIGIN: {WALLET_A}},
            )
            try:
                with pytest.raises(X402PaymentError, match="not in trusted allowlist"):
                    await client.get(f"{ORIGIN}/v1/a")
                await client.get(f"{other}/v1/a")
                with pytest.raises(WalletRotationError):
                    await client.get(f"{other}/v1/b")
            finally:
                await client.aclose()
        assert len(_events(audit, "WALLET_BLOCKED")) == 1
        assert len(_events(audit, "WALLET_ROTATED")) == 1

    @pytest.mark.asyncio
    async def test_different_network_is_a_separate_pin(self):
        audit = _RecordingAuditWriter()
        with respx.mock:
            _mock_402(f"{ORIGIN}/v1/a", WALLET_A, network="base-sepolia")
            _mock_402(f"{ORIGIN}/v1/b", WALLET_B, network="base-mainnet")
            client = HardenedX402Client(
                payment_signer=_signer, audit_writer=audit, wallet_pinning="block"
            )
            try:
                await client.get(f"{ORIGIN}/v1/a")
                await client.get(f"{ORIGIN}/v1/b")
            finally:
                await client.aclose()
        assert len(_events(audit, "WALLET_PINNED")) == 2
        assert not _events(audit, "WALLET_ROTATED")

    @pytest.mark.asyncio
    async def test_pin_keys_off_original_origin_when_redaction_rewrites_host(self):
        """An IP-literal host is redacted in the audit URL but must still key the pin."""
        audit = _RecordingAuditWriter()
        ip_origin = "https://10.20.30.40:8443"
        with respx.mock:
            _mock_402(f"{ip_origin}/v1/a", WALLET_A)
            respx.get(f"{ip_origin}/v1/b").mock(
                return_value=httpx.Response(
                    402, headers={"X-PAYMENT": _header(WALLET_B, f"{ip_origin}/v1/b")}
                )
            )
            client = HardenedX402Client(
                payment_signer=_signer, audit_writer=audit, wallet_pinning="block"
            )
            try:
                await client.get(f"{ip_origin}/v1/a")
                with pytest.raises(WalletRotationError):
                    await client.get(f"{ip_origin}/v1/b")
            finally:
                await client.aclose()
        assert client.wallet_pins.pinned(ip_origin, "base-sepolia") == WALLET_A
        rotated = _events(audit, "WALLET_ROTATED")
        assert rotated and "10.20.30.40" not in rotated[0].resource_url
