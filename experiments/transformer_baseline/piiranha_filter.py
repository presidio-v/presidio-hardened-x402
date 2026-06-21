"""Piiranha (DeBERTa-v3 PII) wrapper exposing PIIFilter's interface.

Implements ``scan_and_redact(text)`` and ``scan_payment_fields(...)`` so the
existing ``experiments/evaluate.py`` and ``experiments/run_latency.py`` can
score Piiranha against the 2,000-sample x402 corpus with partial-span
matching, identical to Presidio runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

from .label_mapping import PIIRANHA_TO_X402

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass
class _Result:
    """Minimal entity record matching the shape evaluate.py expects."""

    entity_type: str
    start: int
    end: int
    score: float


_PIPELINE_CACHE: dict[tuple[str, str], object] = {}


def _get_pipeline(model_id: str, device: str):
    """Cache the HuggingFace pipeline so a config sweep doesn't reload weights."""
    key = (model_id, device)
    pipe = _PIPELINE_CACHE.get(key)
    if pipe is None:
        tok = AutoTokenizer.from_pretrained(model_id)
        mod = AutoModelForTokenClassification.from_pretrained(model_id)
        pipe = pipeline(
            "token-classification",
            model=mod,
            tokenizer=tok,
            aggregation_strategy="simple",
            device=0 if device == "cuda" else -1,
        )
        _PIPELINE_CACHE[key] = pipe
    return pipe


class PiiranhaFilter:
    MODEL_ID = "iiiorg/piiranha-v1-detect-personal-information"

    def __init__(
        self,
        *,
        min_score: float = 0.5,
        device: str = "cpu",
        entities: Iterable[str] | None = None,
    ):
        self.mode = "transformer"
        self.min_score = min_score
        self.entities = set(entities) if entities else None
        self._pipe = _get_pipeline(self.MODEL_ID, device)

    def scan_and_redact(self, text: str) -> tuple[str, list[_Result]]:
        if not text:
            return text, []
        raw = self._pipe(text)
        results: list[_Result] = []
        for ent in raw:
            if ent["score"] < self.min_score:
                continue
            group = ent["entity_group"]
            x402_type = PIIRANHA_TO_X402.get(group)
            if x402_type is None:
                continue
            if self.entities is not None and x402_type not in self.entities:
                continue
            results.append(
                _Result(
                    entity_type=x402_type,
                    start=int(ent["start"]),
                    end=int(ent["end"]),
                    score=float(ent["score"]),
                )
            )
        redacted = self._redact(text, results)
        return redacted, results

    @staticmethod
    def _redact(text: str, results: list[_Result]) -> str:
        if not results:
            return text
        out = text
        for r in sorted(results, key=lambda r: -r.start):
            out = out[: r.start] + f"<{r.entity_type}>" + out[r.end :]
        return out

    def scan_payment_fields(self, resource_url: str, description: str, reason: str):
        return tuple(self.scan_and_redact(f) for f in (resource_url, description, reason))
