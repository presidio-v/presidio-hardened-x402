"""Data types for the presidio-hardened-x402 synthetic PII corpus.

A corpus sample represents a single x402 payment metadata triple
(resource_url, description, reason) with ground-truth PII labels.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class EntityLabel:
    """Ground-truth label for a single PII entity occurrence.

    Positions (start, end) are byte-offsets into the named ``field`` string,
    following the same convention as Presidio's ``RecognizerResult``.
    """

    field: str
    """Which metadata field contains this entity: ``resource_url``, ``description``, or ``reason``."""

    entity_type: str
    """Presidio entity type string, e.g. ``EMAIL_ADDRESS``, ``PERSON``, ``US_SSN``."""

    start: int
    """Inclusive start character offset within the field string."""

    end: int
    """Exclusive end character offset within the field string."""

    original_text: str
    """The exact substring that was injected / is the ground-truth PII."""

    surface_form: str = ""
    """The surface-form variant name (e.g. ``bare``, ``url_encoded``, ``slug``).
    Informational only; used for error analysis."""


@dataclass
class CorpusSample:
    """A single x402 metadata sample with ground-truth PII labels.

    Samples are either PII-positive (``pii_positive=True``, ``labels`` non-empty)
    or clean baseline (``pii_positive=False``, ``labels`` empty).
    """

    id: str
    """Unique sample identifier, e.g. ``syn-00042``."""

    category: str
    """Use-case category: one of ``ai_inference``, ``data_access``, ``medical``,
    ``compute``, ``media``, ``financial``, ``generic``."""

    resource_url: str
    description: str
    reason: str

    pii_positive: bool
    """True if at least one PII entity is present across the three fields."""

    labels: list[EntityLabel] = field(default_factory=list)
    """Ground-truth entity labels. Empty for clean samples."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CorpusSample:
        labels = [EntityLabel(**lbl) for lbl in data.pop("labels", [])]
        return cls(**data, labels=labels)
