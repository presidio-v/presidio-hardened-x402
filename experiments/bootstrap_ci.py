"""Bootstrap 95% confidence intervals for the recommended Presidio NLP config.

Approach: case-bootstrap over corpus samples. Run Presidio NLP once to collect
per-sample (per-entity) TP/FP/FN, then resample samples with replacement N times
and recompute micro-P/R/F1 + per-entity F1 from the aggregated counts.

This is the standard non-parametric CI procedure for classifier metrics; see
Wilson (1927) for the analytic alternative when only proportions are needed.

Usage::

    python -m experiments.bootstrap_ci
    python -m experiments.bootstrap_ci --n-bootstrap 10000 --seed 42
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from corpus.generate import CORPUS_DIR, load_corpus
from experiments.evaluate import _overlaps  # noqa: PLC2701

RESULTS_DIR = Path(__file__).parent / "results"

ALL_ENTITIES = [
    "EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER",
    "US_SSN", "CREDIT_CARD", "IBAN_CODE",
]


def _per_sample_counts(samples, pii_filter) -> list[dict[str, list[int]]]:
    """For each sample, return {entity_type: [tp, fp, fn]}.

    Mirrors evaluate_corpus's matching logic; partial-span overlap.
    """
    out = []
    for sample in samples:
        per_field = {"resource_url": [], "description": [], "reason": []}
        for fname, fval in (
            ("resource_url", sample.resource_url),
            ("description", sample.description),
            ("reason", sample.reason),
        ):
            if not fval:
                continue
            _, ents = pii_filter.scan_and_redact(fval)
            for e in ents:
                per_field[fname].append((e.entity_type, e.start, e.end))

        per_entity: dict[str, list[int]] = {et: [0, 0, 0] for et in ALL_ENTITIES}
        matched_preds: set = set()

        for gold in sample.labels:
            etype = gold.entity_type
            preds = per_field.get(gold.field, [])
            found = False
            for pe, ps, pe_end in preds:
                key = (gold.field, pe, ps, pe_end)
                if key in matched_preds:
                    continue
                if pe == etype and _overlaps(ps, pe_end, gold.start, gold.end):
                    per_entity.setdefault(etype, [0, 0, 0])[0] += 1
                    matched_preds.add(key)
                    found = True
                    break
            if not found:
                per_entity.setdefault(etype, [0, 0, 0])[2] += 1

        for fname, preds in per_field.items():
            for pe, ps, pe_end in preds:
                key = (fname, pe, ps, pe_end)
                if key not in matched_preds:
                    per_entity.setdefault(pe, [0, 0, 0])[1] += 1

        out.append(per_entity)
    return out


def _aggregate(per_sample: list[dict[str, list[int]]], indices: np.ndarray):
    """Sum per-sample counts at the given resample indices."""
    totals: dict[str, list[int]] = {et: [0, 0, 0] for et in ALL_ENTITIES}
    for i in indices:
        for et, (tp, fp, fn) in per_sample[i].items():
            if et not in totals:
                totals[et] = [0, 0, 0]
            totals[et][0] += tp
            totals[et][1] += fp
            totals[et][2] += fn
    return totals


def _f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def bootstrap(
    samples,
    pii_filter,
    *,
    n_bootstrap: int = 10000,
    seed: int = 42,
) -> dict:
    print(f"  Running Presidio NLP over {len(samples)} samples...")
    per_sample = _per_sample_counts(samples, pii_filter)
    print(f"  Bootstrap-resampling {n_bootstrap} times (seed={seed})...")

    rng = np.random.default_rng(seed)
    N = len(per_sample)

    micro_p = np.empty(n_bootstrap)
    micro_r = np.empty(n_bootstrap)
    micro_f1 = np.empty(n_bootstrap)
    per_entity_f1: dict[str, np.ndarray] = {
        et: np.empty(n_bootstrap) for et in ALL_ENTITIES
    }

    for k in range(n_bootstrap):
        idx = rng.integers(0, N, size=N)
        totals = _aggregate(per_sample, idx)
        TP = sum(t[0] for t in totals.values())
        FP = sum(t[1] for t in totals.values())
        FN = sum(t[2] for t in totals.values())
        p, r, f1 = _f1(TP, FP, FN)
        micro_p[k] = p
        micro_r[k] = r
        micro_f1[k] = f1
        for et in ALL_ENTITIES:
            tp, fp, fn = totals.get(et, (0, 0, 0))
            _, _, f1_e = _f1(tp, fp, fn)
            per_entity_f1[et][k] = f1_e

    def _ci(arr: np.ndarray) -> tuple[float, float, float]:
        return (
            float(np.percentile(arr, 2.5)),
            float(np.percentile(arr, 50)),
            float(np.percentile(arr, 97.5)),
        )

    return {
        "n_samples": N,
        "n_bootstrap": n_bootstrap,
        "seed": seed,
        "micro_precision": _ci(micro_p),
        "micro_recall": _ci(micro_r),
        "micro_f1": _ci(micro_f1),
        "per_entity_f1": {et: _ci(per_entity_f1[et]) for et in ALL_ENTITIES},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap CIs for Presidio NLP")
    parser.add_argument("--corpus", type=Path, default=CORPUS_DIR / "corpus.jsonl")
    parser.add_argument("--n-bootstrap", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-score", type=float, default=0.4)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "bootstrap_ci.json")
    args = parser.parse_args()

    from presidio_x402.pii_filter import PIIFilter

    print(f"Loading corpus from {args.corpus}...")
    samples = load_corpus(args.corpus)
    print(f"  Loaded {len(samples)} samples.")

    print(f"Building PIIFilter(mode=nlp, all entities, min_score={args.min_score})...")
    f = PIIFilter(mode="nlp", entities=ALL_ENTITIES, min_score=args.min_score)

    result = bootstrap(samples, f, n_bootstrap=args.n_bootstrap, seed=args.seed)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print("\n=== 95% bootstrap CIs (Presidio NLP recommended config) ===")
    p_lo, p_med, p_hi = result["micro_precision"]
    r_lo, r_med, r_hi = result["micro_recall"]
    f_lo, f_med, f_hi = result["micro_f1"]
    print(f"  micro precision: {p_med:.3f}  [{p_lo:.3f}, {p_hi:.3f}]")
    print(f"  micro recall:    {r_med:.3f}  [{r_lo:.3f}, {r_hi:.3f}]")
    print(f"  micro F1:        {f_med:.3f}  [{f_lo:.3f}, {f_hi:.3f}]")
    print()
    print("  Per-entity F1:")
    for et in ALL_ENTITIES:
        lo, med, hi = result["per_entity_f1"][et]
        print(f"    {et:<16} {med:.3f}  [{lo:.3f}, {hi:.3f}]")
    print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
