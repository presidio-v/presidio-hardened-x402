"""PII detection and redaction for x402 payment metadata.

Scans payment metadata fields (resource URL, description, reason) using either:
  - ``regex`` mode: fast structural PII detection (emails, SSNs, credit cards,
    phone numbers, IBANs) — zero-setup, no NLP model required
  - ``nlp`` mode: full Presidio NER pipeline (PERSON, ORG, location, etc.) —
    requires ``presidio-hardened-x402[nlp]`` and a downloaded spaCy model

Usage::

    filt = PIIFilter(mode="regex", entities=["EMAIL_ADDRESS", "US_SSN"])
    redacted_url, entities = filt.scan_and_redact("https://api.example.com/user/alice@example.com")
    # redacted_url: "https://api.example.com/user/<REDACTED>"

    # To include entity type in the placeholder (for audit-only pipelines):
    filt = PIIFilter(mode="regex", redaction_template="<{entity_type}>")
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger("presidio_x402.pii_filter")

REDACTED_TEMPLATE = "<REDACTED>"

# Invisible codepoints stripped before matching: zero-width space/non-joiner/joiner,
# byte-order mark, soft hyphen. Present them in metadata purely to evade regex.
_INVISIBLE_CODEPOINTS = frozenset({0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD, 0x2060})

# Cyrillic → ASCII homoglyph map. Manual (no external dep) coverage of the
# Latin-lookalike Cyrillic letters commonly used in evasion.
_HOMOGLYPH_FOLD = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "х": "x",
        "Х": "X",
        "у": "y",
        "У": "Y",
        "і": "i",
        "І": "I",
        "ј": "j",
        "Ј": "J",
        "ѕ": "s",
        "Ѕ": "S",
        "к": "k",
        "К": "K",
        "н": "H",
        "М": "M",
        "Т": "T",
        "В": "B",
    }
)

# Hyphen-like characters folded to ASCII hyphen-minus.
_HYPHEN_FOLD = str.maketrans(
    {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "\ufe58": "-",
        "\ufe63": "-",
        "\uff0d": "-",
    }
)


def _normalise(text: str) -> str:
    """Canonicalise *text* to foil regex-evasion via Unicode encoding tricks.

    Steps: NFKC → strip invisible codepoints → fold Cyrillic homoglyphs and
    hyphen-like characters to ASCII equivalents.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if ord(c) not in _INVISIBLE_CODEPOINTS)
    text = text.translate(_HOMOGLYPH_FOLD)
    text = text.translate(_HYPHEN_FOLD)
    return text


# ---------------------------------------------------------------------------
# Regex-mode PII patterns
# Ordered: most specific first to avoid overlapping matches.
# All digit classes are ASCII-only ([0-9]) to avoid false positives on
# Unicode decimal-digit codepoints (Arabic-Indic, Devanagari, etc.).
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
        re.compile(r"\b(?!000|666|9[0-9]{2})[0-9]{3}[-\s]?(?!00)[0-9]{2}[-\s]?(?!0000)[0-9]{4}\b"),
    ),
    # Structural: credit/debit card numbers (13–19 digit, major networks)
    (
        "CREDIT_CARD",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3,6})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}"
            r"|(?:2131|1800|35[0-9]{3})[0-9]{11})\b"
        ),
    ),
    # Structural: US phone numbers
    (
        "PHONE_NUMBER",
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s][0-9]{3}[-.\s][0-9]{4}\b"),
    ),
    # Structural: IBAN (EU bank accounts)
    (
        "IBAN_CODE",
        re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})\b"),
    ),
    # Structural: IPv4 addresses (common in resource URLs, may be PII in some contexts)
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
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
        min_score: float = 0.5,
    ) -> None:
        self.mode = mode
        self.entities = set(entities) if entities is not None else None
        self.redaction_template = redaction_template
        self.min_score = min_score
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

        # Canonicalise before matching — closes Unicode regex-evasion paths
        # (homoglyphs, zero-width chars, non-ASCII hyphens). Output is the
        # normalised form so downstream callers see a clean, canonical string.
        text = _normalise(text)

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
        # Filter by minimum confidence score
        analyzer_results = [r for r in analyzer_results if r.score >= self.min_score]

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

    def scan_dict(self, data: object) -> tuple[object, list[EntityResult]]:
        """Recursively scan and redact string values in arbitrary JSON-shaped data.

        Used for the ``extra`` field of :class:`PaymentDetails`, which is server-
        controlled JSON that must be treated as untrusted. Dicts and lists are
        traversed; strings are passed through :meth:`scan_and_redact`; all other
        primitives (int, float, bool, None) are returned unchanged.

        Returns ``(redacted_data, entities)``. ``redacted_data`` is a new
        container of the same shape as the input.
        """
        if isinstance(data, str):
            return self.scan_and_redact(data)
        if isinstance(data, dict):
            redacted_dict: dict[object, object] = {}
            entities: list[EntityResult] = []
            for k, v in data.items():
                clean_v, v_entities = self.scan_dict(v)
                redacted_dict[k] = clean_v
                entities.extend(v_entities)
            return redacted_dict, entities
        if isinstance(data, list):
            redacted_list: list[object] = []
            entities = []
            for item in data:
                clean_item, item_entities = self.scan_dict(item)
                redacted_list.append(clean_item)
                entities.extend(item_entities)
            return redacted_list, entities
        return data, []
