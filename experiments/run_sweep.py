"""Precision/recall parameter sweep over PIIFilter configurations.

Sweeps the following axes (from explore/hypothesis-rq.md):
  - pii_mode:      regex | nlp
  - pii_entities:  combinations of entity type subsets
  - min_score:     0.30, 0.40, 0.50, 0.60, 0.70 (regex mode always returns 1.0; only meaningful for nlp)

For each configuration, runs ``evaluate_corpus`` against the synthetic corpus
and writes one JSON result row to ``experiments/results/sweep_results.jsonl``.

Usage::

    python -m experiments.run_sweep                   # full sweep, regex mode only
    python -m experiments.run_sweep --mode nlp        # include nlp mode (requires spaCy)
    python -m experiments.run_sweep --sample 200      # quick run on 200 random samples
    python -m experiments.run_sweep --out /tmp/out.jsonl

The sweep is designed to be resumable: rows are written incrementally so a
partial run can be inspected or restarted.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from itertools import combinations
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path when invoked as module
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from corpus.generate import CORPUS_DIR, load_corpus
from experiments.evaluate import evaluate_corpus

RESULTS_DIR = Path(__file__).parent / "results"

# ---------------------------------------------------------------------------
# Sweep axes
# ---------------------------------------------------------------------------

ALL_ENTITY_TYPES = [
    "EMAIL_ADDRESS",
    "PERSON",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
]

# We sweep these entity subsets: all individual types + the full set
_ENTITY_SUBSETS: list[list[str]] = [[et] for et in ALL_ENTITY_TYPES] + [ALL_ENTITY_TYPES]

# min_score thresholds — only relevant for nlp mode
_MIN_SCORES = [0.30, 0.40, 0.50, 0.60, 0.70]

# For regex mode, min_score has no effect (regex always returns 1.0); sweep it anyway
# so the results table is uniform.
_REGEX_MIN_SCORES = [0.50]  # only one needed; regex ignores it


def _build_configs(modes: list[str]) -> list[dict[str, Any]]:
    """Build all (mode, entities, min_score) configurations to sweep."""
    configs = []
    for mode in modes:
        scores = _MIN_SCORES if mode == "nlp" else _REGEX_MIN_SCORES
        for entities in _ENTITY_SUBSETS:
            for min_score in scores:
                configs.append({
                    "mode": mode,
                    "entities": sorted(entities),
                    "min_score": min_score,
                })
    return configs


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_sweep(
    modes: list[str],
    corpus_path: Path,
    out_path: Path,
    sample_n: int | None = None,
    overlap_mode: str = "partial",
) -> None:
    """Execute the full sweep and write results to *out_path* (JSONL)."""
    from presidio_x402.pii_filter import PIIFilter

    print(f"Loading corpus from {corpus_path}...")
    samples = load_corpus(corpus_path)
    if sample_n is not None and sample_n < len(samples):
        import random
        rng = random.Random(42)
        samples = rng.sample(samples, sample_n)
        print(f"  Downsampled to {len(samples)} samples.")
    else:
        print(f"  Loaded {len(samples)} samples.")

    configs = _build_configs(modes)
    print(f"Sweep: {len(configs)} configurations across modes={modes}")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as fh:
        for i, cfg in enumerate(configs, 1):
            mode = cfg["mode"]
            entities = cfg["entities"]
            min_score = cfg["min_score"]

            # Build filter — pass min_score only for nlp mode
            try:
                if mode == "nlp":
                    pii_filter = PIIFilter(mode="nlp", entities=entities, min_score=min_score)
                else:
                    pii_filter = PIIFilter(mode="regex", entities=entities)
            except Exception as exc:
                print(f"  [{i}/{len(configs)}] SKIP mode={mode} entities={entities} "
                      f"min_score={min_score}: {exc}")
                continue

            t0 = time.perf_counter()
            report = evaluate_corpus(samples, pii_filter, overlap_mode=overlap_mode)
            elapsed = time.perf_counter() - t0

            row = {
                "mode": mode,
                "entities": entities,
                "min_score": min_score,
                "n_samples": len(samples),
                "overlap_mode": overlap_mode,
                "elapsed_s": round(elapsed, 3),
                **report.to_dict(),
            }
            fh.write(json.dumps(row) + "\n")
            fh.flush()

            print(
                f"  [{i:>3}/{len(configs)}] mode={mode:<5} "
                f"entities=[{','.join(e[:3] for e in entities)}...]  "
                f"min_score={min_score}  "
                f"P={report.micro_precision():.3f}  R={report.micro_recall():.3f}  "
                f"F1={report.micro_f1():.3f}  ({elapsed:.1f}s)"
            )

    print(f"\nResults written to {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Precision/recall sweep over PIIFilter configs")
    parser.add_argument(
        "--mode", choices=["regex", "nlp", "both"], default="regex",
        help="PIIFilter mode(s) to sweep (default: regex)",
    )
    parser.add_argument(
        "--corpus", type=Path, default=CORPUS_DIR / "corpus.jsonl",
        help="Path to corpus JSONL file",
    )
    parser.add_argument(
        "--out", type=Path, default=RESULTS_DIR / "sweep_results.jsonl",
        help="Output JSONL path",
    )
    parser.add_argument(
        "--sample", type=int, default=None,
        help="Downsample corpus to N samples for quick runs",
    )
    parser.add_argument(
        "--overlap", choices=["partial", "exact"], default="partial",
        help="Span matching mode (default: partial)",
    )
    args = parser.parse_args()

    modes = ["regex", "nlp"] if args.mode == "both" else [args.mode]
    run_sweep(
        modes=modes,
        corpus_path=args.corpus,
        out_path=args.out,
        sample_n=args.sample,
        overlap_mode=args.overlap,
    )


if __name__ == "__main__":
    main()
