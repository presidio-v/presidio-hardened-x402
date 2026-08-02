"""Tests for the multi-party authorization (MPA) engine."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import socket
import time

import httpx
import pytest
import respx

import presidio_x402.mpa as mpa_mod
from presidio_x402._types import PaymentDetails
from presidio_x402.exceptions import MPADeniedError, MPAWebhookURLError


class TestResolveAndCheckHost:
    """F-05 (2026-06-03): DNS-rebinding resolution runs off the event loop and
    still flags hosts that resolve into a blocked range."""

    @pytest.mark.asyncio
    async def test_loopback_resolution_is_blocked(self):
        # localhost resolves to a loopback address (blocked range) — deterministic
        # and offline. Exercises the async loop.getaddrinfo path.
        with pytest.raises(MPAWebhookURLError, match="blocked address"):
            await mpa_mod._resolve_and_check_host("localhost")

    @pytest.mark.asyncio
    async def test_dns_protection_uses_checked_ip_for_request(self, monkeypatch):
        calls: dict[str, object] = {}

        async def _fake_resolve(host: str, port: int = 443) -> tuple[str, ...]:
            calls["resolved"] = (host, port)
            return ("203.0.113.10",)

        async def _fake_post(
            url: str,
            *,
            resolved_ips: tuple[str, ...],
            content: bytes,
            headers: dict[str, str],
        ) -> httpx.Response:
            calls["posted"] = (url, resolved_ips, json.loads(content), headers)
            return httpx.Response(
                200,
                json={"approved": True, "approver_id": "alice"},
                request=httpx.Request("POST", url),
            )

        monkeypatch.setattr(mpa_mod, "_resolve_and_check_host", _fake_resolve)
        monkeypatch.setattr(mpa_mod, "_post_pinned_https", _fake_post)
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice",
                        mode="webhook",
                        webhook_url="https://approvals.example.com/alice",
                    )
                ],
            )
        )
        await engine.request_approval(_make_details(), amount_usd=1.0)

        assert calls["resolved"] == ("approvals.example.com", 443)
        posted = calls["posted"]
        assert isinstance(posted, tuple)
        assert posted[1] == ("203.0.113.10",)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_details(**overrides) -> PaymentDetails:
    defaults: dict = {
        "resource_url": "https://api.example.com/resource",
        "pay_to": "0xABCDEF1234567890",
        "amount": "1.00",
        "currency": "USDC",
        "network": "base-mainnet",
        "deadline_seconds": 300,
        "description": "Test resource",
        "reason": "",
    }
    defaults.update(overrides)
    return PaymentDetails(**defaults)


def _make_crypto_sig(
    secret: bytes, details: PaymentDetails, amount_usd: float, *, timestamp: int | None = None
) -> str:
    # Now produces the "<unix_ts>:<hmac_hex>" freshness-bound format (F-8).
    return mpa_mod.build_countersignature(secret, details, amount_usd, timestamp=timestamp)


ALICE_SECRET = b"alice-shared-secret"
BOB_SECRET = b"bob-shared-secret"
CHARLIE_SECRET = b"charlie-shared-secret"


# ---------------------------------------------------------------------------
# MPAConfig validation
# ---------------------------------------------------------------------------


class TestMPAConfigValidation:
    def test_valid_config(self):
        cfg = mpa_mod.MPAConfig(
            dns_rebinding_protection=False,
            threshold=2,
            approvers=[
                mpa_mod.MPAApproverConfig(
                    "alice", mode="webhook", webhook_url="https://a.internal"
                ),
                mpa_mod.MPAApproverConfig("bob", mode="webhook", webhook_url="https://b.internal"),
                mpa_mod.MPAApproverConfig(
                    "charlie", mode="webhook", webhook_url="https://c.internal"
                ),
            ],
        )
        assert cfg.threshold == 2
        assert len(cfg.approvers) == 3

    def test_threshold_zero_raises(self):
        with pytest.raises(ValueError, match="threshold must be >= 1"):
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=0,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice", mode="webhook", webhook_url="https://a.internal"
                    ),
                ],
            )

    def test_threshold_exceeds_approvers_raises(self):
        with pytest.raises(ValueError, match="cannot exceed number of approvers"):
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=3,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice", mode="webhook", webhook_url="https://a.internal"
                    ),
                    mpa_mod.MPAApproverConfig(
                        "bob", mode="webhook", webhook_url="https://b.internal"
                    ),
                ],
            )

    def test_empty_approvers_raises(self):
        # threshold 1 > 0 approvers → should raise
        with pytest.raises(ValueError, match="cannot exceed number of approvers"):
            mpa_mod.MPAConfig(dns_rebinding_protection=False, threshold=1, approvers=[])


# ---------------------------------------------------------------------------
# Amount below threshold: MPA skipped
# ---------------------------------------------------------------------------


class TestMPAAmountThreshold:
    def setup_method(self):
        self.engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                min_amount_usd=5.00,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice", mode="webhook", webhook_url="https://a.internal"
                    )
                ],
            )
        )

    @pytest.mark.asyncio
    async def test_below_threshold_is_exempt(self):
        """Payments below min_amount_usd should pass without contacting approvers."""
        details = _make_details(amount="1.00")
        # Would raise MPADeniedError if MPA ran (no approvers configured to respond)
        await self.engine.request_approval(details, amount_usd=1.00)

    @pytest.mark.asyncio
    async def test_exactly_at_threshold_triggers_mpa(self):
        """Payments exactly at min_amount_usd trigger MPA."""
        details = _make_details(amount="5.00")
        # No mock set up — webhook call will fail, approval not collected
        # So MPADeniedError is expected (no approvals)
        with pytest.raises(MPADeniedError):
            await self.engine.request_approval(details, amount_usd=5.00)


# ---------------------------------------------------------------------------
# Crypto mode
# ---------------------------------------------------------------------------


class TestMPACryptoMode:
    def setup_method(self):
        self.details = _make_details(amount="2.00")
        self.amount_usd = 2.00

    @pytest.mark.asyncio
    async def test_single_valid_signature_meets_threshold(self):
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET)
                ],
            )
        )
        sig = _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd)
        # Should not raise
        await engine.request_approval(
            self.details, self.amount_usd, provided_signatures={"alice": sig}
        )

    @pytest.mark.asyncio
    async def test_two_of_three_valid_signatures(self):
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=2,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET),
                    mpa_mod.MPAApproverConfig("bob", mode="crypto", shared_secret=BOB_SECRET),
                    mpa_mod.MPAApproverConfig(
                        "charlie", mode="crypto", shared_secret=CHARLIE_SECRET
                    ),
                ],
            )
        )
        sigs = {
            "alice": _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd),
            "charlie": _make_crypto_sig(CHARLIE_SECRET, self.details, self.amount_usd),
        }
        await engine.request_approval(self.details, self.amount_usd, provided_signatures=sigs)

    @pytest.mark.asyncio
    async def test_wrong_signature_is_rejected(self):
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET)
                ],
            )
        )
        with pytest.raises(MPADeniedError) as exc_info:
            await engine.request_approval(
                self.details,
                self.amount_usd,
                provided_signatures={"alice": "deadbeef" * 8},
            )
        assert exc_info.value.approvals_received == 0
        assert exc_info.value.threshold == 1

    @pytest.mark.asyncio
    async def test_missing_signature_is_denied(self):
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET)
                ],
            )
        )
        with pytest.raises(MPADeniedError):
            await engine.request_approval(self.details, self.amount_usd, provided_signatures={})

    @pytest.mark.asyncio
    async def test_below_threshold_signatures_denied(self):
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=2,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET),
                    mpa_mod.MPAApproverConfig("bob", mode="crypto", shared_secret=BOB_SECRET),
                ],
            )
        )
        # Only alice signs — threshold is 2
        sigs = {"alice": _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd)}
        with pytest.raises(MPADeniedError) as exc_info:
            await engine.request_approval(self.details, self.amount_usd, provided_signatures=sigs)
        assert exc_info.value.approvals_received == 1
        assert exc_info.value.threshold == 2


class TestMPACryptoFreshness:
    """F-8 (2026-06-03): crypto countersignatures embed a timestamp and are
    rejected outside MPAConfig.max_signature_age_seconds, so a captured signature
    cannot be replayed for an identical payment after the ReplayGuard TTL."""

    def setup_method(self):
        self.details = _make_details(amount="2.00")
        self.amount_usd = 2.00

    def _engine(self, max_age: int = 300):
        return mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                max_signature_age_seconds=max_age,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET)
                ],
            )
        )

    @pytest.mark.asyncio
    async def test_fresh_signature_accepted(self):
        sig = _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd)  # now()
        await self._engine().request_approval(
            self.details, self.amount_usd, provided_signatures={"alice": sig}
        )

    @pytest.mark.asyncio
    async def test_stale_signature_rejected(self):
        old = int(time.time()) - 3600  # 1h ago, well past the 300s window
        sig = _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd, timestamp=old)
        with pytest.raises(MPADeniedError):
            await self._engine().request_approval(
                self.details, self.amount_usd, provided_signatures={"alice": sig}
            )

    @pytest.mark.asyncio
    async def test_legacy_format_without_timestamp_rejected(self):
        # A bare hex signature (old format, no "<ts>:" prefix) must not validate.
        legacy = hmac.new(
            ALICE_SECRET,
            mpa_mod._canonical_payload(self.details, self.amount_usd, 0),
            hashlib.sha256,
        ).hexdigest()
        with pytest.raises(MPADeniedError):
            await self._engine().request_approval(
                self.details, self.amount_usd, provided_signatures={"alice": legacy}
            )

    @pytest.mark.asyncio
    async def test_tampered_timestamp_rejected(self):
        # Take a valid sig, bump its timestamp — the HMAC no longer matches.
        sig = _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd)
        ts, _, hexsig = sig.partition(":")
        tampered = f"{int(ts) + 1}:{hexsig}"
        with pytest.raises(MPADeniedError):
            await self._engine().request_approval(
                self.details, self.amount_usd, provided_signatures={"alice": tampered}
            )

    def test_invalid_max_age_rejected(self):
        with pytest.raises(ValueError, match="max_signature_age_seconds"):
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                max_signature_age_seconds=0,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET)
                ],
            )


# ---------------------------------------------------------------------------
# Webhook mode
# ---------------------------------------------------------------------------


class TestMPAWebhookMode:
    def setup_method(self):
        self.details = _make_details(amount="3.00")
        self.amount_usd = 3.00
        self.engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=2,
                timeout_seconds=5.0,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice", mode="webhook", webhook_url="https://approvals.internal/alice"
                    ),
                    mpa_mod.MPAApproverConfig(
                        "bob", mode="webhook", webhook_url="https://approvals.internal/bob"
                    ),
                    mpa_mod.MPAApproverConfig(
                        "charlie", mode="webhook", webhook_url="https://approvals.internal/charlie"
                    ),
                ],
            )
        )

    @pytest.mark.asyncio
    async def test_all_approve(self):
        with respx.mock:
            for name in ("alice", "bob", "charlie"):
                respx.post(f"https://approvals.internal/{name}").mock(
                    return_value=httpx.Response(
                        200,
                        json={"approved": True, "approver_id": name},
                    )
                )
            await self.engine.request_approval(self.details, self.amount_usd)

    @pytest.mark.asyncio
    async def test_exactly_threshold_approvals(self):
        """Alice and Bob approve; Charlie denies. Threshold 2 → should pass."""
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(200, json={"approved": True, "approver_id": "alice"})
            )
            respx.post("https://approvals.internal/bob").mock(
                return_value=httpx.Response(200, json={"approved": True, "approver_id": "bob"})
            )
            respx.post("https://approvals.internal/charlie").mock(
                return_value=httpx.Response(
                    200, json={"approved": False, "approver_id": "charlie"}
                )
            )
            await self.engine.request_approval(self.details, self.amount_usd)

    @pytest.mark.asyncio
    async def test_below_threshold_approvals_raises(self):
        """Only one of three approves; threshold 2 → MPADeniedError."""
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(200, json={"approved": True, "approver_id": "alice"})
            )
            respx.post("https://approvals.internal/bob").mock(
                return_value=httpx.Response(200, json={"approved": False, "approver_id": "bob"})
            )
            respx.post("https://approvals.internal/charlie").mock(
                return_value=httpx.Response(
                    200, json={"approved": False, "approver_id": "charlie"}
                )
            )
            with pytest.raises(MPADeniedError) as exc_info:
                await self.engine.request_approval(self.details, self.amount_usd)
        assert exc_info.value.approvals_received == 1
        assert exc_info.value.threshold == 2

    @pytest.mark.asyncio
    async def test_webhook_http_error_counts_as_denied(self):
        """An HTTP error from an approver is treated as a denial."""
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(200, json={"approved": True, "approver_id": "alice"})
            )
            respx.post("https://approvals.internal/bob").mock(
                return_value=httpx.Response(500, text="Internal Server Error")
            )
            respx.post("https://approvals.internal/charlie").mock(
                return_value=httpx.Response(
                    200, json={"approved": False, "approver_id": "charlie"}
                )
            )
            with pytest.raises(MPADeniedError):
                await self.engine.request_approval(self.details, self.amount_usd)

    @pytest.mark.asyncio
    async def test_approved_error_message_is_informative(self):
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice", mode="webhook", webhook_url="https://approvals.internal/alice"
                    ),
                ],
            )
        )
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(200, json={"approved": False, "approver_id": "alice"})
            )
            with pytest.raises(MPADeniedError, match="0 of 1 required approvals"):
                await engine.request_approval(self.details, self.amount_usd)


# ---------------------------------------------------------------------------
# Webhook mode — HMAC response verification
# ---------------------------------------------------------------------------

WEBHOOK_SECRET = b"webhook-hmac-secret"


def _make_hmac_header(secret: bytes, body: bytes) -> str:
    """Compute the X-MPA-HMAC header value for a given response body."""
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


class TestMPAWebhookHMAC:
    """Tests for X-MPA-HMAC response authentication (CWE-295 fix)."""

    def setup_method(self):
        self.details = _make_details(amount="2.00")
        self.amount_usd = 2.00

    @pytest.mark.asyncio
    async def test_valid_hmac_header_counts_as_approval(self):
        """Webhook approver with shared_secret + correct X-MPA-HMAC → approved."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice",
                        mode="webhook",
                        webhook_url="https://approvals.internal/alice",
                        shared_secret=WEBHOOK_SECRET,
                    ),
                ],
            )
        )
        body = json.dumps({"approved": True, "approver_id": "alice"}).encode()
        header = _make_hmac_header(WEBHOOK_SECRET, body)
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(
                    200,
                    content=body,
                    headers={"Content-Type": "application/json", "X-MPA-HMAC": header},
                )
            )
            # Should not raise — one approval meets threshold 1
            await engine.request_approval(self.details, self.amount_usd)

    @pytest.mark.asyncio
    async def test_missing_hmac_header_treated_as_denied(self):
        """Webhook approver with shared_secret but no X-MPA-HMAC header → denied."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice",
                        mode="webhook",
                        webhook_url="https://approvals.internal/alice",
                        shared_secret=WEBHOOK_SECRET,
                    ),
                ],
            )
        )
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(
                    200,
                    json={"approved": True, "approver_id": "alice"},
                    # No X-MPA-HMAC header
                )
            )
            with pytest.raises(MPADeniedError, match="0 of 1 required approvals"):
                await engine.request_approval(self.details, self.amount_usd)

    @pytest.mark.asyncio
    async def test_wrong_hmac_header_treated_as_denied(self):
        """Webhook approver with shared_secret + tampered X-MPA-HMAC header → denied."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice",
                        mode="webhook",
                        webhook_url="https://approvals.internal/alice",
                        shared_secret=WEBHOOK_SECRET,
                    ),
                ],
            )
        )
        body = json.dumps({"approved": True, "approver_id": "alice"}).encode()
        wrong_header = "deadbeef" * 8  # 64 hex chars, wrong value
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(
                    200,
                    content=body,
                    headers={"Content-Type": "application/json", "X-MPA-HMAC": wrong_header},
                )
            )
            with pytest.raises(MPADeniedError, match="0 of 1 required approvals"):
                await engine.request_approval(self.details, self.amount_usd)

    @pytest.mark.asyncio
    async def test_no_shared_secret_skips_hmac_check(self):
        """Webhook approver without shared_secret accepts response without X-MPA-HMAC."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice",
                        mode="webhook",
                        webhook_url="https://approvals.internal/alice",
                        # No shared_secret — backwards-compatible path
                    ),
                ],
            )
        )
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(
                    200,
                    json={"approved": True, "approver_id": "alice"},
                    # No X-MPA-HMAC header — should still pass
                )
            )
            await engine.request_approval(self.details, self.amount_usd)


# ---------------------------------------------------------------------------
# Mixed mode (crypto + webhook)
# ---------------------------------------------------------------------------


class TestMPAMixedMode:
    def setup_method(self):
        self.details = _make_details(amount="5.00")
        self.amount_usd = 5.00

    @pytest.mark.asyncio
    async def test_crypto_plus_webhook_meets_threshold(self):
        """Alice provides crypto sig; Bob approves via webhook; threshold 2 → approved."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=2,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET),
                    mpa_mod.MPAApproverConfig(
                        "bob", mode="webhook", webhook_url="https://approvals.internal/bob"
                    ),
                ],
            )
        )
        sig = _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd)
        with respx.mock:
            respx.post("https://approvals.internal/bob").mock(
                return_value=httpx.Response(200, json={"approved": True, "approver_id": "bob"})
            )
            await engine.request_approval(
                self.details, self.amount_usd, provided_signatures={"alice": sig}
            )

    @pytest.mark.asyncio
    async def test_crypto_valid_but_webhook_denied_below_threshold(self):
        """Alice provides valid crypto sig; Bob denies; threshold 2 → MPADeniedError."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=2,
                approvers=[
                    mpa_mod.MPAApproverConfig("alice", mode="crypto", shared_secret=ALICE_SECRET),
                    mpa_mod.MPAApproverConfig(
                        "bob", mode="webhook", webhook_url="https://approvals.internal/bob"
                    ),
                ],
            )
        )
        sig = _make_crypto_sig(ALICE_SECRET, self.details, self.amount_usd)
        with respx.mock:
            respx.post("https://approvals.internal/bob").mock(
                return_value=httpx.Response(200, json={"approved": False, "approver_id": "bob"})
            )
            with pytest.raises(MPADeniedError):
                await engine.request_approval(
                    self.details, self.amount_usd, provided_signatures={"alice": sig}
                )


# ---------------------------------------------------------------------------
# Canonical payload determinism
# ---------------------------------------------------------------------------


class TestCanonicalPayload:
    def test_same_details_and_timestamp_produce_same_payload(self):
        details = _make_details()
        p1 = mpa_mod._canonical_payload(details, 1.00, 1000)
        p2 = mpa_mod._canonical_payload(details, 1.00, 1000)
        assert p1 == p2

    def test_different_amounts_produce_different_payloads(self):
        details = _make_details()
        p1 = mpa_mod._canonical_payload(details, 1.00, 1000)
        p2 = mpa_mod._canonical_payload(details, 2.00, 1000)
        assert p1 != p2

    def test_different_timestamp_produces_different_payload(self):
        # F-8: the timestamp is part of the signed material.
        details = _make_details()
        assert mpa_mod._canonical_payload(details, 1.00, 1000) != mpa_mod._canonical_payload(
            details, 1.00, 2000
        )

    def test_payload_is_valid_json(self):
        details = _make_details()
        payload = mpa_mod._canonical_payload(details, 1.00, 1700000000)
        parsed = json.loads(payload)
        assert parsed["resource_url"] == details.resource_url
        assert "amount_usd" in parsed
        assert parsed["timestamp"] == 1700000000


# ---------------------------------------------------------------------------
# Webhook outbound request HMAC — F-B regression (audit 2026-05-03)
# ---------------------------------------------------------------------------


class TestMPAWebhookOutboundHMAC:
    """Approver must be able to authenticate the engine via X-MPA-REQUEST-HMAC."""

    def setup_method(self):
        self.details = _make_details(amount="2.00")
        self.amount_usd = 2.00

    @pytest.mark.asyncio
    async def test_outbound_request_carries_hmac_when_shared_secret_set(self):
        """When approver has shared_secret, X-MPA-REQUEST-HMAC must match HMAC(secret, body)."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice",
                        mode="webhook",
                        webhook_url="https://approvals.internal/alice",
                        shared_secret=WEBHOOK_SECRET,
                    ),
                ],
            )
        )
        body = json.dumps({"approved": True, "approver_id": "alice"}).encode()
        resp_header = _make_hmac_header(WEBHOOK_SECRET, body)

        captured_requests: list[httpx.Request] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(
                200,
                content=body,
                headers={"Content-Type": "application/json", "X-MPA-HMAC": resp_header},
            )

        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(side_effect=_handler)
            await engine.request_approval(self.details, self.amount_usd)

        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert "X-MPA-REQUEST-HMAC" in req.headers
        expected = hmac.new(WEBHOOK_SECRET, req.content, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(req.headers["X-MPA-REQUEST-HMAC"], expected)

    @pytest.mark.asyncio
    async def test_outbound_request_omits_hmac_when_no_shared_secret(self):
        """Backwards-compat: no shared_secret → no header; approver runs unauthenticated."""
        engine = mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice",
                        mode="webhook",
                        webhook_url="https://approvals.internal/alice",
                    ),
                ],
            )
        )

        captured_requests: list[httpx.Request] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, json={"approved": True, "approver_id": "alice"})

        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(side_effect=_handler)
            await engine.request_approval(self.details, self.amount_usd)

        assert len(captured_requests) == 1
        assert "X-MPA-REQUEST-HMAC" not in captured_requests[0].headers


class TestDecodeChunkedBody:
    """Pure decoder for chunked MPA webhook response bodies (F-05 hardening)."""

    def test_single_chunk(self):
        assert mpa_mod._decode_chunked_body(b"5\r\nhello\r\n0\r\n") == b"hello"

    def test_multiple_chunks(self):
        assert mpa_mod._decode_chunked_body(b"3\r\nabc\r\n2\r\nde\r\n0\r\n") == b"abcde"

    def test_missing_crlf_raises(self):
        with pytest.raises(httpx.ProtocolError, match="Invalid chunked"):
            mpa_mod._decode_chunked_body(b"5")

    def test_bad_chunk_size_raises(self):
        with pytest.raises(httpx.ProtocolError, match="Invalid chunk size"):
            mpa_mod._decode_chunked_body(b"zz\r\ndata\r\n0\r\n")

    def test_truncated_chunk_raises(self):
        with pytest.raises(httpx.ProtocolError, match="Truncated"):
            mpa_mod._decode_chunked_body(b"9\r\nhi\r\n0\r\n")

    def test_bad_terminator_raises(self):
        with pytest.raises(httpx.ProtocolError, match="Invalid chunk terminator"):
            mpa_mod._decode_chunked_body(b"5\r\nhelloXX0\r\n")


class TestResolveAndCheckHostPaths:
    """Cover the DNS-failure, no-address, and dedup paths of host resolution by
    patching the running loop's getaddrinfo (offline, deterministic)."""

    @pytest.mark.asyncio
    async def test_dns_failure_raises(self, monkeypatch):
        loop = asyncio.get_running_loop()

        async def boom(*args, **kwargs):
            raise socket.gaierror("no such host")

        monkeypatch.setattr(loop, "getaddrinfo", boom)
        with pytest.raises(MPAWebhookURLError, match="DNS resolution failed"):
            await mpa_mod._resolve_and_check_host("nonexistent.invalid")

    @pytest.mark.asyncio
    async def test_no_addresses_raises(self, monkeypatch):
        loop = asyncio.get_running_loop()

        async def empty(*args, **kwargs):
            return []

        monkeypatch.setattr(loop, "getaddrinfo", empty)
        with pytest.raises(MPAWebhookURLError, match="no addresses"):
            await mpa_mod._resolve_and_check_host("empty.invalid")

    @pytest.mark.asyncio
    async def test_public_addresses_deduplicated(self, monkeypatch):
        loop = asyncio.get_running_loop()

        async def dup(*args, **kwargs):
            info = (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))
            return [info, info]

        monkeypatch.setattr(loop, "getaddrinfo", dup)
        result = await mpa_mod._resolve_and_check_host("example.test")
        assert result == ("93.184.216.34",)


class TestWebhookResponseSizeCap:
    """Audit F1 (2026-07-19, CWE-400): the plain-httpx branch — taken for an
    IP-literal webhook URL or with `dns_rebinding_protection` off — parsed the
    response body without bounding it, so a hostile approver could inflate a
    multi-GB body into Python objects via `resp.json()`. `_post_pinned_https`
    already capped its own read.
    """

    def _engine(self) -> mpa_mod.MPAEngine:
        return mpa_mod.MPAEngine(
            mpa_mod.MPAConfig(
                dns_rebinding_protection=False,
                threshold=1,
                timeout_seconds=5.0,
                approvers=[
                    mpa_mod.MPAApproverConfig(
                        "alice", mode="webhook", webhook_url="https://approvals.internal/alice"
                    )
                ],
            )
        )

    @pytest.mark.asyncio
    async def test_oversized_response_is_denied_not_parsed(self):
        oversized = b'{"approved": true, "pad": "' + b"A" * mpa_mod._MPA_RESPONSE_MAX_BYTES + b'"}'
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(
                    200, content=oversized, headers={"Content-Type": "application/json"}
                )
            )
            # An approving body that is over the cap must not count as an approval.
            with pytest.raises(MPADeniedError):
                await self._engine().request_approval(_make_details(amount="3.00"), 3.00)

    @pytest.mark.asyncio
    async def test_response_at_the_cap_is_still_accepted(self):
        pad = mpa_mod._MPA_RESPONSE_MAX_BYTES - len(b'{"approved": true, "pad": ""}')
        body = b'{"approved": true, "pad": "' + b"A" * pad + b'"}'
        assert len(body) == mpa_mod._MPA_RESPONSE_MAX_BYTES
        with respx.mock:
            respx.post("https://approvals.internal/alice").mock(
                return_value=httpx.Response(
                    200, content=body, headers={"Content-Type": "application/json"}
                )
            )
            await self._engine().request_approval(_make_details(amount="3.00"), 3.00)
