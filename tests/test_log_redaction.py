"""Tests for sink-level secret redaction on the presidio_x402 logger (R2)."""

from __future__ import annotations

import logging

import pytest

from presidio_x402.log_redaction import (
    RedactingFilter,
    SecretRedactor,
    install_log_redaction,
)


class TestSecretRedactor:
    def setup_method(self):
        self.r = SecretRedactor()

    @pytest.mark.parametrize(
        ("raw", "must_not_contain", "must_contain"),
        [
            ("key=sk_live_abcDEF123456", "sk_live_abcDEF123456", "sk_live_"),
            ("anthropic sk-ant-api03-XyZ_-99", "XyZ_-99", "sk-ant-"),
            ("token Bearer abc.def.ghi end", "abc.def.ghi", "Bearer ***REDACTED***"),
            ("Authorization: Bearer abc.def.ghi", "abc.def.ghi", "Authorization: ***REDACTED***"),
            ("url?access_token=tok123&x=1", "tok123", "access_token="),
            ("url?api_key=KKK999&y=2", "KKK999", "api_key="),
            (
                # EVM private key / HMAC material: 32-byte hex (0x-prefixed)
                "signing with 0x" + "a" * 64,
                "0x" + "a" * 64,
                "0x***REDACTED***",
            ),
            (
                # bare 64-hex (e.g. a chain key dump)
                "chain_key=" + "b" * 64,
                "b" * 64,
                "***REDACTED***",
            ),
        ],
    )
    def test_redacts_secret_shapes(self, raw, must_not_contain, must_contain):
        out = self.r.redact(raw)
        assert must_not_contain not in out
        assert must_contain in out

    def test_wallet_address_not_redacted(self):
        # 20-byte (40 hex) addresses are pseudo-public and must survive.
        addr = "0x" + "c" * 40
        assert addr in self.r.redact(f"pay_to={addr}")

    def test_clean_text_unchanged(self):
        msg = "payment ok amount=0.01 USDC to base-sepolia"
        assert self.r.redact(msg) == msg


class TestInstallLogRedaction:
    def test_idempotent_single_filter_per_logger(self):
        install_log_redaction()
        before = [
            f for f in logging.getLogger("presidio_x402").filters if isinstance(f, RedactingFilter)
        ]
        install_log_redaction()
        after = [
            f for f in logging.getLogger("presidio_x402").filters if isinstance(f, RedactingFilter)
        ]
        assert len(before) == 1
        assert len(after) == 1

    def test_installed_at_import_on_parent(self):
        # importing presidio_x402 (done at module load) installs the filter
        filters = logging.getLogger("presidio_x402").filters
        assert any(isinstance(f, RedactingFilter) for f in filters)

    def test_covers_child_loggers(self):
        # A filter on the parent does not cover child records; install must attach
        # to each namespace logger. gateway logs through presidio_x402.gateway.
        child = logging.getLogger("presidio_x402.gateway")
        assert any(isinstance(f, RedactingFilter) for f in child.filters)

    def test_child_logger_record_is_redacted(self, caplog):
        install_log_redaction()
        child = logging.getLogger("presidio_x402.gateway")
        with caplog.at_level(logging.INFO, logger="presidio_x402.gateway"):
            child.info("leaked Bearer %s now", "abc.def.ghi")
        joined = " ".join(r.getMessage() for r in caplog.records)
        assert "abc.def.ghi" not in joined
        assert "Bearer ***REDACTED***" in joined

    def test_newly_created_child_logger_covered_after_reinstall(self):
        logging.getLogger("presidio_x402.brand_new_child")
        install_log_redaction()
        child = logging.getLogger("presidio_x402.brand_new_child")
        assert any(isinstance(f, RedactingFilter) for f in child.filters)
