"""Proof-of-concept tests for adversary attack chains 02, 04, 05, 06.

Each test encodes an attack described in ``adversary-attack/chain-0N-*.md``:

  - Assert the attack is now blocked (positive control).
  - Where feasible, construct the exact hostile input the chain specifies
    (crafted 402 payload, Unicode-evasive metadata, malicious signer, etc.).

Any regression that re-opens a chain should cause at least one of these tests
to fail.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import replace

import httpx
import pytest
import respx

from presidio_x402 import HardenedX402Client
from presidio_x402._types import AuditEvent, PaymentDetails, PaymentResponse
from presidio_x402.exceptions import X402PaymentError
from presidio_x402.pii_filter import PIIFilter

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _RecordingAuditWriter:
    """Captures AuditEvent objects for later assertion."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


async def _mock_signer(details: PaymentDetails) -> PaymentResponse:
    return PaymentResponse(token="mock-signed-token", details=details)  # noqa: S106


_BENIGN_HEADER = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "0.01",
                "resource": "https://api.example.com/v1/data",
                "description": "API data access",
                "payTo": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "requiredDeadlineSeconds": 300,
            }
        ]
    }
)


# ---------------------------------------------------------------------------
# Chain 02 — Cross-process replay bypass via per-process fingerprint key
# ---------------------------------------------------------------------------
#
# Before the fix, each replica seeded ``_FINGERPRINT_KEY`` from
# ``secrets.token_bytes(32)`` at import time, so the same logical payment
# fingerprinted differently on each replica — a duplicate submission landed on
# a second replica was never recognised as a replay.
#
# After the fix, ``PRESIDIO_X402_FINGERPRINT_KEY`` is loaded from the
# environment; all replicas configured with the same hex string produce
# identical fingerprints and cross-replica replays are caught.


class TestChain02CrossProcessReplay:
    _KEY_HEX = "aa" * 32

    def _reimport_with_env(self, monkeypatch, value: str | None):
        if value is None:
            monkeypatch.delenv("PRESIDIO_X402_FINGERPRINT_KEY", raising=False)
        else:
            monkeypatch.setenv("PRESIDIO_X402_FINGERPRINT_KEY", value)
        import presidio_x402.replay_guard as module

        return importlib.reload(module)

    def test_poc_before_fix_replicas_would_diverge(self, monkeypatch):
        """Two independent per-process keys produce different fingerprints.

        This is the pre-fix failure condition we want to exclude in production.
        """
        mod_a = self._reimport_with_env(monkeypatch, None)
        key_a = mod_a._FINGERPRINT_KEY
        mod_b = self._reimport_with_env(monkeypatch, None)
        key_b = mod_b._FINGERPRINT_KEY
        assert key_a != key_b, (
            "Sanity check: two random per-process keys must differ, "
            "otherwise this POC can't demonstrate the attack."
        )

    def test_fix_shared_env_key_gives_identical_fingerprints(self, monkeypatch):
        """Two replicas booted with the same env key fingerprint identically."""
        mod_a = self._reimport_with_env(monkeypatch, self._KEY_HEX)
        fp_a = mod_a.compute_fingerprint(
            "https://api.example.com/v1/data",
            "0xabc",
            "0.01",
            "USDC",
            300,
        )
        mod_b = self._reimport_with_env(monkeypatch, self._KEY_HEX)
        fp_b = mod_b.compute_fingerprint(
            "https://api.example.com/v1/data",
            "0xabc",
            "0.01",
            "USDC",
            300,
        )
        assert fp_a == fp_b

    def test_fix_invalid_hex_falls_back_with_error_log(self, monkeypatch, caplog):
        """Malformed env var doesn't silently enable cross-process dedup."""
        import logging

        with caplog.at_level(logging.ERROR, logger="presidio_x402.replay_guard"):
            self._reimport_with_env(monkeypatch, "not-hex-data")
        assert any("not valid hex" in rec.getMessage() for rec in caplog.records)

    def test_fix_short_key_rejected(self, monkeypatch, caplog):
        """A key shorter than 16 bytes is refused (falls back, logs error)."""
        import logging

        with caplog.at_level(logging.ERROR, logger="presidio_x402.replay_guard"):
            self._reimport_with_env(monkeypatch, "aabb")  # 2 bytes
        assert any("shorter than 16 bytes" in rec.getMessage() for rec in caplog.records)

    def test_fix_missing_env_warns(self, monkeypatch, caplog):
        """Omitting the env var surfaces the operator warning."""
        import logging

        with caplog.at_level(logging.WARNING, logger="presidio_x402.replay_guard"):
            self._reimport_with_env(monkeypatch, None)
        assert any("per-process key" in rec.getMessage() for rec in caplog.records)

    @classmethod
    def teardown_class(cls):
        """Restore the replay_guard module to whatever the session was using."""
        import presidio_x402.replay_guard as module

        importlib.reload(module)


# ---------------------------------------------------------------------------
# Chain 04 — Unicode PII evasion (homoglyphs, zero-width, hyphen folds,
#                                 Unicode-digit false positives)
# ---------------------------------------------------------------------------
#
# Before the fix, the regex engine ran against the raw metadata string. An
# attacker could slip PII past the filter with Cyrillic lookalikes, zero-width
# joiners inside an email, or an en-dash between SSN groups; conversely,
# non-ASCII digits in ``\d`` caused spurious SSN/credit-card matches on
# legitimate non-English content.


class TestChain04UnicodeEvasion:
    def setup_method(self):
        self.filt = PIIFilter(mode="regex")

    def test_cyrillic_homoglyph_email_is_detected(self):
        """Email using Cyrillic 'а' (U+0430), 'е' (U+0435), 'р' (U+0440) normalizes to ASCII."""
        # "аlicе@exam\u0440le.com" — all three substitutions are in the fold map.
        hostile = "contact \u0430lic\u0435@exam\u0440le.com please"
        redacted, entities = self.filt.scan_and_redact(hostile)
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities), (
            f"Homoglyph email must be detected after NFKC + fold; got {entities!r}"
        )
        assert "<REDACTED>" in redacted

    def test_zero_width_joiner_inside_email_is_detected(self):
        """ZWSP/ZWJ/ZWNJ interspersed in an email are stripped before matching."""
        hostile = "send to alice\u200b@example\u200c.com"
        _, entities = self.filt.scan_and_redact(hostile)
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    def test_soft_hyphen_inside_email_is_detected(self):
        """Soft hyphens (U+00AD) are invisible in most renderers."""
        hostile = "send to alice\u00ad@example.com"
        _, entities = self.filt.scan_and_redact(hostile)
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    def test_en_dash_ssn_separator_is_detected(self):
        """SSN with U+2013 (en-dash) instead of ASCII '-' still matches."""
        # Realistic SSN with en-dash separators
        hostile = "ssn 123\u201345\u20136789 on file"
        _, entities = self.filt.scan_and_redact(hostile)
        assert any(e.entity_type == "US_SSN" for e in entities)

    def test_arabic_indic_digits_do_not_trigger_ssn_false_positive(self):
        """Pre-fix ``\\d`` matched U+0660-0669; restricted to ASCII ``[0-9]`` now."""
        # Arabic-Indic 1 2 3 4 5 6 7 8 9 (shape of a benign foreign-language ID)
        hostile = "id \u0661\u0662\u0663-\u0664\u0665-\u0666\u0667\u0668\u0669 benign"
        _, entities = self.filt.scan_and_redact(hostile)
        assert not any(e.entity_type == "US_SSN" for e in entities), (
            "Unicode decimal digits must not be treated as ASCII digits "
            "for structural PII matching."
        )

    def test_devanagari_digits_do_not_trigger_credit_card_false_positive(self):
        """Devanagari digits packed into 16 positions must not match CREDIT_CARD."""
        hostile = "token \u0966\u0967\u0968\u0969\u096a\u096b\u096c\u096d\u096e" * 2
        _, entities = self.filt.scan_and_redact(hostile)
        assert not any(e.entity_type == "CREDIT_CARD" for e in entities)


# ---------------------------------------------------------------------------
# Chain 05 — Payment data exfiltration via exception message leakage
# ---------------------------------------------------------------------------
#
# Before the fix, f-string exception messages embedded raw JSON fragments
# (including wallet/pay_to and resource URL), and ``error_message=str(exc)``
# propagated that unredacted text into the audit log.
#
# After the fix:
#   * Exception messages are constants ("Invalid X-PAYMENT header JSON", etc.)
#   * ``error_message`` is truncated via ``_safe_exc_message`` and passed
#     through the PIIFilter before audit emission.
#   * The original cause is preserved on ``__cause__`` for local debugging.


class TestChain05ExceptionExfiltration:
    # Sentinel strings chosen so any leak is trivially greppable.
    _SECRET_WALLET = "0xDEADBEEFCAFED00DDEADBEEFCAFED00DDEADBEEF"  # noqa: S105 — test sentinel
    _SECRET_KEY_FRAGMENT = "PRIVATE-KEY-FRAGMENT-abcdef1234"  # noqa: S105 — test sentinel
    # Structural-PII sentinel: the PII filter MUST scrub this from audit text.
    _SECRET_EMAIL = "leaked-signer-email@attacker.test"  # noqa: S105 — test sentinel

    @pytest.mark.asyncio
    async def test_site_a_malformed_json_does_not_leak_wallet_or_url(self):
        """Malformed JSON with an embedded wallet must not leak into the raised error."""
        audit = _RecordingAuditWriter()
        # Invalid JSON whose *surface text* contains wallet and URL hints.
        hostile_header = (
            f'{{"accepts": ["resource": "https://api.example.com/v1/data/{self._SECRET_WALLET}", '
            f'"payTo": "{self._SECRET_WALLET}"]'
        )
        with respx.mock:
            respx.get("https://api.example.com/v1/data").mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": hostile_header})
            )
            client = HardenedX402Client(payment_signer=_mock_signer, audit_writer=audit)
            try:
                with pytest.raises(X402PaymentError) as exc_info:
                    await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()

        # Raised message is a constant.
        assert str(exc_info.value) == "Invalid X-PAYMENT header JSON"
        assert self._SECRET_WALLET not in str(exc_info.value)

        # __cause__ still points to the JSON decoder exception for debugging.
        assert isinstance(exc_info.value.__cause__, json.JSONDecodeError)

        # Audit record contains no wallet fragment.
        assert audit.events, "Chain 05: expected an audit event for the blocked attempt"
        leaked = [
            e for e in audit.events if e.error_message and self._SECRET_WALLET in e.error_message
        ]
        assert not leaked, f"Wallet leaked into audit: {[e.error_message for e in leaked]!r}"

    @pytest.mark.asyncio
    async def test_site_b_missing_field_does_not_leak_other_fields(self):
        """KeyError on missing payTo must not leak the other provided fields."""
        # payTo omitted on purpose; url/amount carry wallet-like sentinel
        hostile_header = json.dumps(
            {
                "accepts": [
                    {
                        "scheme": "exact",
                        "network": "base-sepolia",
                        "maxAmountRequired": "0.01",
                        "resource": f"https://api.example.com/{self._SECRET_WALLET}",
                        "requiredDeadlineSeconds": 300,
                    }
                ]
            }
        )
        audit = _RecordingAuditWriter()
        with respx.mock:
            respx.get(f"https://api.example.com/{self._SECRET_WALLET}").mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": hostile_header})
            )
            client = HardenedX402Client(payment_signer=_mock_signer, audit_writer=audit)
            try:
                with pytest.raises(X402PaymentError) as exc_info:
                    await client.get(f"https://api.example.com/{self._SECRET_WALLET}")
            finally:
                await client.aclose()

        assert str(exc_info.value) == "Missing required field in X-PAYMENT entry"
        # __cause__ was suppressed for Site B (`from None`), so we should NOT
        # see a KeyError tail — but if it's there it mustn't carry payload.
        cause_text = str(exc_info.value.__cause__ or "")
        assert self._SECRET_WALLET not in cause_text

    @pytest.mark.asyncio
    async def test_site_c_signer_exception_not_reraised_in_message(self):
        """Signer exception text does not leak into the raised X402PaymentError.

        The fix contract is: ``X402PaymentError`` message is a constant; the
        original cause is preserved on ``__cause__`` for local debug only.
        Callers (and anything consuming ``str(exc)``) see no payload.
        """

        async def _leaky_signer(details: PaymentDetails) -> PaymentResponse:
            raise RuntimeError(
                f"Cannot sign with key {self._SECRET_KEY_FRAGMENT} "
                f"for wallet {self._SECRET_WALLET}"
            )

        with respx.mock:
            respx.get("https://api.example.com/v1/data").mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": _BENIGN_HEADER})
            )
            client = HardenedX402Client(payment_signer=_leaky_signer)
            try:
                with pytest.raises(X402PaymentError) as exc_info:
                    await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()

        msg = str(exc_info.value)
        assert msg == "Payment signing failed"
        assert self._SECRET_KEY_FRAGMENT not in msg
        assert self._SECRET_WALLET not in msg
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    @pytest.mark.asyncio
    async def test_site_c_signer_structural_pii_scrubbed_from_audit(self):
        """Structural PII (email) in a signer exception is redacted in audit emit."""

        async def _leaky_signer(details: PaymentDetails) -> PaymentResponse:
            raise RuntimeError(f"signer rejected contact {self._SECRET_EMAIL}")

        audit = _RecordingAuditWriter()
        with respx.mock:
            respx.get("https://api.example.com/v1/data").mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": _BENIGN_HEADER})
            )
            client = HardenedX402Client(payment_signer=_leaky_signer, audit_writer=audit)
            try:
                with pytest.raises(X402PaymentError):
                    await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()

        error_events = [e for e in audit.events if e.error_message]
        assert error_events
        for e in error_events:
            assert self._SECRET_EMAIL not in e.error_message, (
                f"PII filter must scrub email from audit error_message: {e.error_message!r}"
            )

    @pytest.mark.asyncio
    async def test_audit_error_message_is_length_capped(self):
        """Huge signer exception strings are truncated before audit emission."""

        giant = "A" * 10_000

        async def _huge_signer(details: PaymentDetails) -> PaymentResponse:
            raise RuntimeError(giant)

        audit = _RecordingAuditWriter()
        with respx.mock:
            respx.get("https://api.example.com/v1/data").mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": _BENIGN_HEADER})
            )
            client = HardenedX402Client(payment_signer=_huge_signer, audit_writer=audit)
            try:
                with pytest.raises(X402PaymentError):
                    await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()

        error_events = [e for e in audit.events if e.error_message]
        assert error_events, "Chain 05: signer error must produce an audit event"
        for e in error_events:
            assert len(e.error_message) < 200, (
                f"Audit error_message must be truncated, got len={len(e.error_message)}"
            )
            assert "[truncated]" in e.error_message


# ---------------------------------------------------------------------------
# Chain 06 — DNS / wallet-substitution hijack (pay_to swap)
# ---------------------------------------------------------------------------
#
# Before the fix, the client signed whatever ``payTo`` the 402 response
# declared. An attacker with control of DNS, a compromised resource origin,
# or an MITM position could swap the legitimate pay_to with their own wallet;
# the payment would complete and the funds would land in the attacker's
# wallet.
#
# After the fix, ``trusted_wallets`` lets the operator pin a per-origin
# pay_to allowlist. Any unknown pay_to for an origin in the map is rejected
# before signing.


def _header_for(pay_to: str, resource: str = "https://api.example.com/v1/data") -> str:
    return json.dumps(
        {
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base-sepolia",
                    "maxAmountRequired": "0.01",
                    "resource": resource,
                    "description": "API data access",
                    "payTo": pay_to,
                    "requiredDeadlineSeconds": 300,
                }
            ]
        }
    )


class TestChain06WalletSubstitution:
    _LEGIT = "0x1111111111111111111111111111111111111111"
    _ATTACKER = "0x9999999999999999999999999999999999999999"

    @pytest.mark.asyncio
    async def test_attack_succeeds_without_allowlist(self):
        """Baseline: with no allowlist, the attacker's pay_to is honored.

        This is the pre-mitigation behaviour. We include it so the POC chain
        fails loudly if someone removes the allowlist enforcement but expects
        the client to still reject unknown wallets.
        """
        signed_details: list[PaymentDetails] = []

        async def _capture_signer(details: PaymentDetails) -> PaymentResponse:
            signed_details.append(details)
            return PaymentResponse(token="mock-signed-token", details=details)  # noqa: S106

        with respx.mock:
            route = respx.get("https://api.example.com/v1/data")
            route.side_effect = [
                httpx.Response(402, headers={"X-PAYMENT": _header_for(self._ATTACKER)}),
                httpx.Response(200, text="ok"),
            ]
            client = HardenedX402Client(payment_signer=_capture_signer)
            try:
                resp = await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()

        assert resp.status_code == 200
        assert signed_details[0].pay_to == self._ATTACKER

    @pytest.mark.asyncio
    async def test_attacker_wallet_blocked_by_allowlist(self):
        """Swapped pay_to is rejected before signing when origin is pinned."""
        signed_details: list[PaymentDetails] = []

        async def _capture_signer(details: PaymentDetails) -> PaymentResponse:
            signed_details.append(details)
            return PaymentResponse(token="mock-signed-token", details=details)  # noqa: S106

        audit = _RecordingAuditWriter()
        attacker_header = _header_for(self._ATTACKER)
        with respx.mock:
            respx.get("https://api.example.com/v1/data").mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": attacker_header})
            )
            client = HardenedX402Client(
                payment_signer=_capture_signer,
                audit_writer=audit,
                trusted_wallets={"https://api.example.com": {self._LEGIT}},
            )
            try:
                with pytest.raises(X402PaymentError, match="not in trusted allowlist"):
                    await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()

        assert not signed_details, "Signer must not be invoked when allowlist rejects pay_to"
        wallet_events = [e for e in audit.events if e.event_type == "WALLET_BLOCKED"]
        assert wallet_events, "Chain 06: blocked event must land in the audit trail"

    @pytest.mark.asyncio
    async def test_allowlisted_wallet_passes(self):
        """Legit pay_to still signs and completes normally."""
        with respx.mock:
            route = respx.get("https://api.example.com/v1/data")
            route.side_effect = [
                httpx.Response(402, headers={"X-PAYMENT": _header_for(self._LEGIT)}),
                httpx.Response(200, text="ok"),
            ]
            client = HardenedX402Client(
                payment_signer=_mock_signer,
                trusted_wallets={"https://api.example.com": {self._LEGIT}},
            )
            try:
                resp = await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_origin_absent_from_allowlist_is_unrestricted(self):
        """Origins not in the map are not gated — operators opt in per-origin."""
        with respx.mock:
            route = respx.get("https://other.example.com/v1/data")
            route.side_effect = [
                httpx.Response(
                    402,
                    headers={
                        "X-PAYMENT": _header_for(
                            self._ATTACKER, resource="https://other.example.com/v1/data"
                        )
                    },
                ),
                httpx.Response(200, text="ok"),
            ]
            client = HardenedX402Client(
                payment_signer=_mock_signer,
                trusted_wallets={"https://api.example.com": {self._LEGIT}},
            )
            try:
                resp = await client.get("https://other.example.com/v1/data")
            finally:
                await client.aclose()
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_allowlist_origin_matches_ignoring_trailing_slash(self):
        """``https://api.example.com`` and ``https://api.example.com/`` pin the same origin."""
        attacker_header = _header_for(self._ATTACKER)
        with respx.mock:
            respx.get("https://api.example.com/v1/data").mock(
                return_value=httpx.Response(402, headers={"X-PAYMENT": attacker_header})
            )
            client = HardenedX402Client(
                payment_signer=_mock_signer,
                trusted_wallets={"https://api.example.com/": {self._LEGIT}},
            )
            try:
                with pytest.raises(X402PaymentError, match="not in trusted allowlist"):
                    await client.get("https://api.example.com/v1/data")
            finally:
                await client.aclose()


# Suppress "unused import" for ``replace`` — retained in case future POC tests
# need to mutate PaymentDetails fixtures without rebuilding them.
_ = replace
