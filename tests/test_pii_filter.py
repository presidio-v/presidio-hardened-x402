"""Tests for PIIFilter — PII detection and redaction in payment metadata."""

from __future__ import annotations

import pytest

from presidio_x402.pii_filter import PIIFilter


class TestPIIFilterRegexMode:
    """Tests for regex-mode PII detection (default, zero-setup)."""

    def setup_method(self):
        self.filt = PIIFilter(mode="regex")

    # ------------------------------------------------------------------
    # Email detection
    # ------------------------------------------------------------------
    def test_detects_email_in_plain_string(self):
        _, entities = self.filt.scan_and_redact("Contact alice@example.com for details")
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    def test_redacts_email_in_resource_url(self):
        redacted, entities = self.filt.scan_and_redact(
            "https://api.example.com/user/alice@example.com/data"
        )
        assert "alice@example.com" not in redacted
        assert "<EMAIL_ADDRESS>" in redacted
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    def test_email_original_text_preserved_in_entity_result(self):
        _, entities = self.filt.scan_and_redact("user@test.org")
        assert entities[0].original_text == "user@test.org"

    # ------------------------------------------------------------------
    # SSN detection
    # ------------------------------------------------------------------
    def test_detects_us_ssn_with_dashes(self):
        _, entities = self.filt.scan_and_redact("SSN: 123-45-6789")
        assert any(e.entity_type == "US_SSN" for e in entities)

    def test_detects_us_ssn_without_dashes(self):
        _, entities = self.filt.scan_and_redact("ssn=123456789 query")
        assert any(e.entity_type == "US_SSN" for e in entities)

    def test_does_not_detect_invalid_ssn_000(self):
        _, entities = self.filt.scan_and_redact("000-00-0000")
        # 000-xx-xxxx is invalid SSN prefix
        ssn_entities = [e for e in entities if e.entity_type == "US_SSN"]
        assert len(ssn_entities) == 0

    # ------------------------------------------------------------------
    # Credit card detection
    # ------------------------------------------------------------------
    def test_detects_visa_card_number(self):
        _, entities = self.filt.scan_and_redact("card=4111111111111111")
        assert any(e.entity_type == "CREDIT_CARD" for e in entities)

    def test_detects_mastercard_number(self):
        _, entities = self.filt.scan_and_redact("5500005555555559")
        assert any(e.entity_type == "CREDIT_CARD" for e in entities)

    # ------------------------------------------------------------------
    # Phone number detection
    # ------------------------------------------------------------------
    def test_detects_us_phone_with_dashes(self):
        _, entities = self.filt.scan_and_redact("Call 415-555-1234 now")
        assert any(e.entity_type == "PHONE_NUMBER" for e in entities)

    def test_detects_us_phone_with_parens(self):
        _, entities = self.filt.scan_and_redact("(415) 555-1234")
        assert any(e.entity_type == "PHONE_NUMBER" for e in entities)

    # ------------------------------------------------------------------
    # No false positives
    # ------------------------------------------------------------------
    def test_clean_url_no_entities(self):
        _, entities = self.filt.scan_and_redact("https://api.example.com/v1/resource")
        assert entities == []

    def test_empty_string_returns_empty(self):
        redacted, entities = self.filt.scan_and_redact("")
        assert redacted == ""
        assert entities == []

    def test_none_safe_string_passthrough(self):
        # No entities in a typical resource URL without PII
        _, entities = self.filt.scan_and_redact("https://payments.example.com/items/42")
        assert entities == []

    # ------------------------------------------------------------------
    # Entity filtering
    # ------------------------------------------------------------------
    def test_entity_filter_limits_detection(self):
        filt = PIIFilter(mode="regex", entities=["EMAIL_ADDRESS"])
        text = "email@example.com and SSN 123-45-6789"
        _, entities = filt.scan_and_redact(text)
        types = {e.entity_type for e in entities}
        assert "EMAIL_ADDRESS" in types
        assert "US_SSN" not in types

    def test_entity_filter_empty_list_finds_nothing(self):
        filt = PIIFilter(mode="regex", entities=[])
        _, entities = filt.scan_and_redact("alice@example.com 123-45-6789")
        assert entities == []

    # ------------------------------------------------------------------
    # Overlapping match handling
    # ------------------------------------------------------------------
    def test_overlapping_matches_deduplicated(self):
        # A string that could match multiple patterns should not double-redact
        text = "alice@example.com"
        redacted, entities = self.filt.scan_and_redact(text)
        assert redacted.count("<") == 1

    # ------------------------------------------------------------------
    # scan_payment_fields
    # ------------------------------------------------------------------
    def test_scan_payment_fields_returns_four_tuple(self):
        result = self.filt.scan_payment_fields(
            resource_url="https://api.example.com/user/alice@example.com",
            description="Data for alice@example.com",
            reason="user=alice@example.com",
        )
        clean_url, clean_desc, clean_reason, all_entities = result
        assert "alice@example.com" not in clean_url
        assert "alice@example.com" not in clean_desc
        assert "alice@example.com" not in clean_reason
        assert len(all_entities) == 3

    def test_scan_payment_fields_clean_input_unchanged(self):
        clean_url, clean_desc, clean_reason, entities = self.filt.scan_payment_fields(
            resource_url="https://api.example.com/items/42",
            description="Item access",
            reason="API call",
        )
        assert clean_url == "https://api.example.com/items/42"
        assert clean_desc == "Item access"
        assert clean_reason == "API call"
        assert entities == []

    # ------------------------------------------------------------------
    # Custom redaction template
    # ------------------------------------------------------------------
    def test_custom_redaction_template(self):
        filt = PIIFilter(mode="regex", redaction_template="[REDACTED:{entity_type}]")
        redacted, _ = filt.scan_and_redact("alice@example.com")
        assert "[REDACTED:EMAIL_ADDRESS]" in redacted

    # ------------------------------------------------------------------
    # NLP mode import error
    # ------------------------------------------------------------------
    def test_nlp_mode_import_error_without_spacy(self, monkeypatch):
        """NLP mode raises ImportError with helpful message if Presidio NLP is unavailable."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name in ("presidio_analyzer", "presidio_anonymizer"):
                raise ImportError("mocked: not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(ImportError, match="NLP mode requires"):
            PIIFilter(mode="nlp")
