"""Precision/recall evaluation helpers for PIIFilter against the synthetic corpus.

Given a list of ``CorpusSample`` ground-truth labels and PIIFilter scan results,
computes per-entity-type and aggregate precision, recall, and F1.

Usage::

    from corpus.schema import CorpusSample
    from presidio_x402.pii_filter import PIIFilter
    from experiments.evaluate import evaluate_corpus

    filter = PIIFilter(mode="regex", entities=["EMAIL_ADDRESS", "US_SSN"])
    report = evaluate_corpus(samples, filter)
    print(report.summary())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from corpus.schema import CorpusSample


@dataclass
class EntityMetrics:
    """Per-entity-type confusion matrix and derived metrics."""

    entity_type: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def row(self) -> dict:
        return {
            "entity_type": self.entity_type,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class EvaluationReport:
    """Aggregate evaluation report across all entity types."""

    per_entity: dict[str, EntityMetrics] = field(default_factory=dict)
    # Sample-level (binary: was the sample correctly flagged as PII-positive/negative?)
    sample_tp: int = 0  # PII-positive correctly flagged
    sample_fp: int = 0  # Clean sample incorrectly flagged
    sample_fn: int = 0  # PII-positive missed entirely
    sample_tn: int = 0  # Clean sample correctly passed

    @property
    def sample_precision(self) -> float:
        d = self.sample_tp + self.sample_fp
        return self.sample_tp / d if d else 0.0

    @property
    def sample_recall(self) -> float:
        d = self.sample_tp + self.sample_fn
        return self.sample_tp / d if d else 0.0

    @property
    def sample_f1(self) -> float:
        p, r = self.sample_precision, self.sample_recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def micro_precision(self) -> float:
        tp = sum(m.tp for m in self.per_entity.values())
        fp = sum(m.fp for m in self.per_entity.values())
        return tp / (tp + fp) if (tp + fp) else 0.0

    def micro_recall(self) -> float:
        tp = sum(m.tp for m in self.per_entity.values())
        fn = sum(m.fn for m in self.per_entity.values())
        return tp / (tp + fn) if (tp + fn) else 0.0

    def micro_f1(self) -> float:
        p, r = self.micro_precision(), self.micro_recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def summary(self) -> str:
        lines = [
            "=== Entity-level metrics ===",
            f"{'Entity':<22} {'P':>6} {'R':>6} {'F1':>6} {'TP':>5} {'FP':>5} {'FN':>5}",
            "-" * 58,
        ]
        for m in sorted(self.per_entity.values(), key=lambda m: -m.f1):
            lines.append(
                f"{m.entity_type:<22} {m.precision:>6.3f} {m.recall:>6.3f} {m.f1:>6.3f}"
                f" {m.tp:>5} {m.fp:>5} {m.fn:>5}"
            )
        lines += [
            "-" * 58,
            f"{'MICRO':.<22} {self.micro_precision():>6.3f} {self.micro_recall():>6.3f}"
            f" {self.micro_f1():>6.3f}",
            "",
            "=== Sample-level (binary) ===",
            f"  Precision: {self.sample_precision:.4f}",
            f"  Recall:    {self.sample_recall:.4f}",
            f"  F1:        {self.sample_f1:.4f}",
            f"  TP={self.sample_tp}  FP={self.sample_fp}"
            f"  FN={self.sample_fn}  TN={self.sample_tn}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "per_entity": [m.row() for m in self.per_entity.values()],
            "micro_precision": round(self.micro_precision(), 4),
            "micro_recall": round(self.micro_recall(), 4),
            "micro_f1": round(self.micro_f1(), 4),
            "sample_precision": round(self.sample_precision, 4),
            "sample_recall": round(self.sample_recall, 4),
            "sample_f1": round(self.sample_f1, 4),
            "sample_tp": self.sample_tp,
            "sample_fp": self.sample_fp,
            "sample_fn": self.sample_fn,
            "sample_tn": self.sample_tn,
        }


def _overlaps(pred_start: int, pred_end: int, gold_start: int, gold_end: int) -> bool:
    """True if two character spans overlap (partial match counts)."""
    return pred_start < gold_end and pred_end > gold_start


def evaluate_corpus(
    samples: list["CorpusSample"],
    pii_filter,  # PIIFilter instance
    *,
    overlap_mode: str = "partial",
) -> EvaluationReport:
    """Evaluate ``pii_filter`` against ground-truth labels in *samples*.

    Parameters
    ----------
    samples:
        Corpus samples with ground-truth ``labels``.
    pii_filter:
        A ``PIIFilter`` instance (from ``presidio_x402.pii_filter``).
    overlap_mode:
        ``"partial"`` (any character overlap = match) or ``"exact"``
        (start and end must match exactly).

    Returns
    -------
    EvaluationReport
    """
    report = EvaluationReport()

    for sample in samples:
        # Collect predictions across all three fields
        preds_by_field: dict[str, list[tuple[str, int, int]]] = {
            "resource_url": [],
            "description": [],
            "reason": [],
        }

        for fname, fval in (
            ("resource_url", sample.resource_url),
            ("description", sample.description),
            ("reason", sample.reason),
        ):
            if not fval:
                continue
            _, entities = pii_filter.scan_and_redact(fval)
            for ent in entities:
                preds_by_field[fname].append((ent.entity_type, ent.start, ent.end))

        any_pred = any(preds_by_field[f] for f in preds_by_field)

        # Sample-level accounting
        if sample.pii_positive:
            if any_pred:
                report.sample_tp += 1
            else:
                report.sample_fn += 1
        else:
            if any_pred:
                report.sample_fp += 1
            else:
                report.sample_tn += 1

        # Entity-level accounting: match each ground-truth label to a prediction
        matched_preds: set[tuple[str, str, int, int]] = set()

        for gold in sample.labels:
            etype = gold.entity_type
            if etype not in report.per_entity:
                report.per_entity[etype] = EntityMetrics(entity_type=etype)
            metrics = report.per_entity[etype]

            field_preds = preds_by_field.get(gold.field, [])
            found = False
            for pred_etype, pred_start, pred_end in field_preds:
                pred_key = (gold.field, pred_etype, pred_start, pred_end)
                if pred_key in matched_preds:
                    continue
                type_match = pred_etype == etype
                if overlap_mode == "exact":
                    span_match = pred_start == gold.start and pred_end == gold.end
                else:
                    span_match = _overlaps(pred_start, pred_end, gold.start, gold.end)
                if type_match and span_match:
                    metrics.tp += 1
                    matched_preds.add(pred_key)
                    found = True
                    break
            if not found:
                metrics.fn += 1

        # FP: predictions not matched to any gold label
        for fname, preds in preds_by_field.items():
            for pred_etype, pred_start, pred_end in preds:
                pred_key = (fname, pred_etype, pred_start, pred_end)
                if pred_key not in matched_preds:
                    if pred_etype not in report.per_entity:
                        report.per_entity[pred_etype] = EntityMetrics(entity_type=pred_etype)
                    report.per_entity[pred_etype].fp += 1

    return report
