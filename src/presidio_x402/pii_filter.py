"""PII detection and redaction for x402 payment metadata.

Scans payment metadata fields (resource URL, description, reason) using either:
  - ``regex`` mode: fast structural PII detection (emails, SSNs, credit cards,
    phone numbers, IBANs) — zero-setup, no NLP model required
  - ``nlp`` mode: full Presidio NER pipeline (PERSON, ORG, location, etc.) —
    requires ``presidio-hardened-x402[nlp]`` and a downloaded spaCy model

Usage::

    filt = PIIFilter(mode="regex", entities=["EMAIL_ADDRESS", "US_SSN"])
    redacted_url, entities = filt.scan_and_redact("https://api.example.com/user/alice@example.com")
    # redacted_url: "https://api.example.com/user/<EMAIL_ADDRESS>"
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger("presidio_x402.pii_filter")

REDACTED_TEMPLATE = "<{entity_type}>"

# ---------------------------------------------------------------------------
# Regex-mode PII patterns
# Ordered: most specific first to avoid overlapping matches
# ---------------------------------------------------------------------------
_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Structural: emails
    (
        "EMAIL_ADDRESS",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
    ),
    # Structural: US SSNs (with or without dashes)
    (
        "US_SSN",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
    ),
    # Structural: credit/debit card numbers (13–19 digit, major networks)
    (
        "CREDIT_CARD",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3,6})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}"
            r"|(?:2131|1800|35\d{3})\d{11})\b"
        ),
    ),
    # Structural: US phone numbers
    (
        "PHONE_NUMBER",
        re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
        ),
    ),
    # Structural: IBAN (EU bank accounts)
    (
        "IBAN_CODE",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})\b"),
    ),
    # Structural: IPv4 addresses (common in resource URLs, may be PII in some contexts)
    (
        "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    ),
]

_REGEX_ENTITY_NAMES = {name for name, _ in _REGEX_PATTERNS}


@dataclass
class EntityResult:
    """A single detected PII entity."""

    entity_type: str
    start: int
    end: int
    score: float
    original_text: str


class PIIFilter:
    """Scans and redacts PII from x402 payment metadata strings.

    Parameters
    ----------
    mode:
        ``"regex"`` (default) — pattern-based, zero-setup, covers structural PII.
        ``"nlp"`` — full Presidio analyzer with spaCy NER; covers free-text PII
        (PERSON, ORG, LOCATION) in addition to structural patterns. Requires
        ``pip install presidio-hardened-x402[nlp]`` and a downloaded spaCy model.
    entities:
        List of Presidio entity type strings to detect. ``None`` → detect all
        supported types for the chosen mode.
    redaction_template:
        Format string for redacted values. Default: ``"<{entity_type}>"``.
    """

    def __init__(
        self,
        *,
        mode: Literal["regex", "nlp"] = "regex",
        entities: list[str] | None = None,
        redaction_template: str = REDACTED_TEMPLATE,
    ) -> None:
        self.mode = mode
        self.entities = set(entities) if entities is not None else None
        self.redaction_template = redaction_template
        self._analyzer = None
        self._anonymizer = None

        if mode == "nlp":
            self._init_presidio_nlp()

    def _init_presidio_nlp(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine

            self._analyzer = AnalyzerEngine()
            self._anonymizer = AnonymizerEngine()
            logger.debug("PIIFilter initialized in NLP mode")
        except ImportError as exc:
            raise ImportError(
                "NLP mode requires: pip install presidio-hardened-x402[nlp] "
                "and python -m spacy download en_core_web_sm"
            ) from exc

    def _active_patterns(self) -> list[tuple[str, re.Pattern[str]]]:
        if self.entities is None:
            return _REGEX_PATTERNS
        return [(name, pat) for name, pat in _REGEX_PATTERNS if name in self.entities]

    def scan_and_redact(self, text: str) -> tuple[str, list[EntityResult]]:
        """Scan *text* for PII, redact matches, and return ``(redacted_text, results)``.

        Parameters
        ----------
        text:
            The string to scan (resource URL, description, or reason field).

        Returns
        -------
        tuple[str, list[EntityResult]]
            The redacted string and a list of detected entities (with original positions).
        """
        if not text:
            return text, []

        if self.mode == "nlp" and self._analyzer is not None:
            return self._scan_nlp(text)
        return self._scan_regex(text)

    def _scan_regex(self, text: str) -> tuple[str, list[EntityResult]]:
        results: list[EntityResult] = []
        redacted = text

        # Track offset shifts as substitutions change string length
        offset = 0
        # Collect all matches first to handle overlaps deterministically
        all_matches: list[tuple[str, re.Match[str]]] = []
        for entity_type, pattern in self._active_patterns():
            for m in pattern.finditer(text):
                all_matches.append((entity_type, m))

        # Sort by start position; for overlapping matches keep the first one
        all_matches.sort(key=lambda t: t[1].start())
        deduplicated: list[tuple[str, re.Match[str]]] = []
        last_end = -1
        for entity_type, m in all_matches:
            if m.start() >= last_end:
                deduplicated.append((entity_type, m))
                last_end = m.end()

        for entity_type, m in deduplicated:
            replacement = self.redaction_template.format(entity_type=entity_type)
            start_adj = m.start() + offset
            end_adj = m.end() + offset
            results.append(
                EntityResult(
                    entity_type=entity_type,
                    start=m.start(),
                    end=m.end(),
                    score=1.0,
                    original_text=m.group(0),
                )
            )
            redacted = redacted[:start_adj] + replacement + redacted[end_adj:]
            offset += len(replacement) - (m.end() - m.start())

        return redacted, results

    def _scan_nlp(self, text: str) -> tuple[str, list[EntityResult]]:
        from presidio_anonymizer.entities import OperatorConfig

        entities_to_analyze = list(self.entities) if self.entities else None
        analyzer_results = self._analyzer.analyze(
            text=text,
            entities=entities_to_analyze,
            language="en",
        )

        entity_results = [
            EntityResult(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=r.score,
                original_text=text[r.start : r.end],
            )
            for r in analyzer_results
        ]

        if not analyzer_results:
            return text, []

        # Build per-entity-type operator config for custom template
        operators = {
            r.entity_type: OperatorConfig(
                "replace",
                {"new_value": self.redaction_template.format(entity_type=r.entity_type)},
            )
            for r in analyzer_results
        }
        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators,
        )
        return anonymized.text, entity_results

    def scan_payment_fields(
        self,
        resource_url: str,
        description: str,
        reason: str,
    ) -> tuple[str, str, str, list[EntityResult]]:
        """Scan and redact all three metadata fields.

        Returns ``(clean_url, clean_description, clean_reason, all_entities)``.
        """
        clean_url, url_entities = self.scan_and_redact(resource_url)
        clean_desc, desc_entities = self.scan_and_redact(description)
        clean_reason, reason_entities = self.scan_and_redact(reason)
        all_entities = url_entities + desc_entities + reason_entities

        if all_entities:
            types = [e.entity_type for e in all_entities]
            logger.warning(
                "PII detected in x402 payment metadata: %s",
                ", ".join(sorted(set(types))),
            )

        return clean_url, clean_desc, clean_reason, all_entities
