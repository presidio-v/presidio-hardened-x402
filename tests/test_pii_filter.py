"""Tests for PIIFilter — PII detection and redaction in payment metadata."""

from __future__ import annotations

import sys
import types

import pytest

from presidio_x402.exceptions import X402PaymentError
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
        assert "<REDACTED>" in redacted
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

    def test_detects_visa_card_number_with_dashes_in_url(self):
        redacted, entities = self.filt.scan_and_redact(
            "https://pay.example/checkout?card=4111-1111-1111-1111"
        )
        assert "4111-1111-1111-1111" not in redacted
        assert "<REDACTED>" in redacted
        assert any(e.entity_type == "CREDIT_CARD" for e in entities)

    def test_detects_card_number_with_spaces(self):
        redacted, entities = self.filt.scan_and_redact("card 5500 0055 5555 5559")
        assert "5500 0055 5555 5559" not in redacted
        assert any(e.entity_type == "CREDIT_CARD" for e in entities)

    def test_detects_card_number_with_unicode_hyphens_after_normalisation(self):
        redacted, entities = self.filt.scan_and_redact("card=4111\u20111111\u20111111\u20111111")
        assert "4111-1111-1111-1111" not in redacted
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

    def test_scan_payment_fields_redacts_separated_cards_in_all_primary_fields(self):
        clean_url, clean_desc, clean_reason, entities = self.filt.scan_payment_fields(
            resource_url="https://pay.example?card=4111-1111-1111-1111",
            description="use 5500 0055 5555 5559",
            reason="fallback card 3714-496353-98431",
        )
        assert "4111-1111-1111-1111" not in clean_url
        assert "5500 0055 5555 5559" not in clean_desc
        assert "3714-496353-98431" not in clean_reason
        assert sum(1 for e in entities if e.entity_type == "CREDIT_CARD") == 3

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
    # NLP mode branch behavior (dependency-free fakes)
    # ------------------------------------------------------------------
    def test_nlp_scan_uses_analyzer_results_and_custom_operator(self, monkeypatch):
        class FakeOperatorConfig:
            def __init__(self, operator_name, params):
                self.operator_name = operator_name
                self.params = params

        monkeypatch.setitem(
            sys.modules,
            "presidio_anonymizer.entities",
            types.SimpleNamespace(OperatorConfig=FakeOperatorConfig),
        )

        class Finding:
            entity_type = "EMAIL_ADDRESS"
            start = 8
            end = 25
            score = 0.9

        class LowConfidenceFinding:
            entity_type = "PHONE_NUMBER"
            start = 0
            end = 7
            score = 0.1

        class FakeAnalyzer:
            def analyze(self, *, text, entities, language):
                assert text == "Contact alice@example.com"
                assert entities == ["EMAIL_ADDRESS"]
                assert language == "en"
                return [Finding(), LowConfidenceFinding()]

        class FakeAnonymizer:
            def anonymize(self, *, text, analyzer_results, operators):
                assert len(analyzer_results) == 1
                cfg = operators["EMAIL_ADDRESS"]
                assert cfg.operator_name == "replace"
                assert cfg.params == {"new_value": "[EMAIL_ADDRESS]"}
                return types.SimpleNamespace(
                    text=text.replace("alice@example.com", "[EMAIL_ADDRESS]")
                )

        filt = PIIFilter(
            mode="regex",
            entities=["EMAIL_ADDRESS"],
            redaction_template="[{entity_type}]",
            min_score=0.5,
        )
        filt.mode = "nlp"
        filt._analyzer = FakeAnalyzer()
        filt._anonymizer = FakeAnonymizer()

        redacted, entities = filt.scan_and_redact("Contact alice@example.com")

        assert redacted == "Contact [EMAIL_ADDRESS]"
        assert len(entities) == 1
        assert entities[0].entity_type == "EMAIL_ADDRESS"
        assert entities[0].original_text == "alice@example.com"

    def test_nlp_mode_registers_structural_recognizers(self, monkeypatch):
        # Regression: NLP mode must be a SUPERSET of regex mode. Presidio's predefined
        # US_SSN/PHONE recognizers score plain dashed patterns ~0.05 (below min_score),
        # so without registering our high-confidence structural recognizers the *paid*
        # NLP tier silently misses SSNs and phone numbers the free regex tier catches.
        from presidio_x402.pii_filter import _REGEX_PATTERNS, _STRUCTURAL_NLP_SCORE

        registered = []

        class FakePattern:
            def __init__(self, *, name, regex, score):
                self.name, self.regex, self.score = name, regex, score

        class FakePatternRecognizer:
            def __init__(self, *, supported_entity, name, patterns):
                self.supported_entity = supported_entity
                self.patterns = patterns

        class FakeRegistry:
            def add_recognizer(self, rec):
                registered.append(rec)

        class FakeAnalyzer:
            def __init__(self):
                self.registry = FakeRegistry()

        monkeypatch.setitem(
            sys.modules,
            "presidio_analyzer",
            types.SimpleNamespace(
                AnalyzerEngine=FakeAnalyzer,
                Pattern=FakePattern,
                PatternRecognizer=FakePatternRecognizer,
            ),
        )
        monkeypatch.setitem(
            sys.modules,
            "presidio_anonymizer",
            types.SimpleNamespace(AnonymizerEngine=lambda: object()),
        )

        PIIFilter(mode="nlp")

        got = {r.supported_entity: r.patterns[0].score for r in registered}
        expected = {name for name, _ in _REGEX_PATTERNS}
        assert expected <= set(got), f"missing structural recognizers: {expected - set(got)}"
        # the two the bare AnalyzerEngine specifically dropped
        assert "US_SSN" in got and "PHONE_NUMBER" in got
        assert all(score == _STRUCTURAL_NLP_SCORE for score in got.values())

    def test_nlp_scan_returns_original_text_when_all_results_below_threshold(self, monkeypatch):
        class FakeOperatorConfig:
            def __init__(self, operator_name, params):
                self.operator_name = operator_name
                self.params = params

        monkeypatch.setitem(
            sys.modules,
            "presidio_anonymizer.entities",
            types.SimpleNamespace(OperatorConfig=FakeOperatorConfig),
        )

        class LowConfidenceFinding:
            entity_type = "EMAIL_ADDRESS"
            start = 8
            end = 25
            score = 0.1

        class FakeAnalyzer:
            def analyze(self, *, text, entities, language):  # noqa: ARG002
                return [LowConfidenceFinding()]

        class FakeAnonymizer:
            def anonymize(self, **kwargs):  # pragma: no cover - should not be called
                raise AssertionError("anonymizer should not run without accepted findings")

        filt = PIIFilter(mode="regex", min_score=0.5)
        filt.mode = "nlp"
        filt._analyzer = FakeAnalyzer()
        filt._anonymizer = FakeAnonymizer()

        redacted, entities = filt.scan_and_redact("Contact alice@example.com")

        assert redacted == "Contact alice@example.com"
        assert entities == []

    # ------------------------------------------------------------------
    # scan_dict — recursive PII scan over arbitrary JSON data
    # (closes F-A 2026-05-03 — extra field bypassed REQ-1 PII scanner)
    # ------------------------------------------------------------------
    def test_scan_dict_redacts_string_values(self):
        clean, entities = self.filt.scan_dict({"user_id": "alice@example.com", "tier": "gold"})
        assert "alice@example.com" not in str(clean)
        assert clean["tier"] == "gold"
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    def test_scan_dict_redacts_pii_in_keys(self):
        """F2 (2026-06-07): PII embedded as a dict key is detected and redacted.

        A hostile 402 server can place PII in a key (e.g. {"alice@example.com": ...}).
        The key must be scanned, not copied verbatim, so it cannot reach MPA webhooks
        or the audit log unredacted.
        """
        clean, entities = self.filt.scan_dict({"alice@example.com": "ignored_value"})
        assert "alice@example.com" not in str(clean)
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    def test_scan_dict_redacts_pii_in_nested_keys(self):
        clean, entities = self.filt.scan_dict({"outer": {"bob@example.com": "v"}})
        assert "bob@example.com" not in str(clean)
        assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)

    def test_scan_dict_recurses_nested_dicts_and_lists(self):
        clean, entities = self.filt.scan_dict(
            {
                "contacts": [
                    {"email": "alice@example.com"},
                    {"email": "bob@example.com"},
                ],
            }
        )
        assert "alice@example.com" not in str(clean)
        assert "bob@example.com" not in str(clean)
        assert sum(1 for e in entities if e.entity_type == "EMAIL_ADDRESS") == 2

    def test_scan_dict_preserves_non_string_primitives(self):
        clean, entities = self.filt.scan_dict(
            {"amount_cents": 100, "active": True, "ratio": 0.5, "missing": None}
        )
        assert clean == {"amount_cents": 100, "active": True, "ratio": 0.5, "missing": None}
        assert entities == []

    def test_scan_dict_empty(self):
        clean, entities = self.filt.scan_dict({})
        assert clean == {}
        assert entities == []

    def test_scan_dict_rejects_excessive_nesting(self):
        """F-04 (2026-06-03): deeply nested data raises a structured payment
        error rather than an uncaught RecursionError."""
        deep: object = "leaf"
        for _ in range(200):
            deep = {"k": deep}
        with pytest.raises(X402PaymentError, match="nesting exceeds maximum depth"):
            self.filt.scan_dict(deep)

    def test_scan_dict_allows_reasonable_nesting(self):
        # A modestly nested structure is still scanned normally.
        nested = {"a": {"b": {"c": ["alice@example.com"]}}}
        clean, entities = self.filt.scan_dict(nested)
        assert entities and entities[0].entity_type == "EMAIL_ADDRESS"
        assert clean["a"]["b"]["c"][0] != "alice@example.com"

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
