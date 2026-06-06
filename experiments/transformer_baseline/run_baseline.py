"""Precision/recall sweep for the Piiranha (DeBERTa-v3 PII) baseline.

Mirrors ``experiments/run_sweep.py`` but uses ``PiiranhaFilter``. The sweep
covers (entity_subset x min_score) combinations matching the existing NLP
sweep so per-detector results sit on the same axes in the paper's tables.

Usage::

    python -m experiments.transformer_baseline.run_baseline
    python -m experiments.transformer_baseline.run_baseline --sample 200    # quick
    python -m experiments.transformer_baseline.run_baseline --device cuda   # GPU
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from corpus.generate import CORPUS_DIR, load_corpus
from experiments.evaluate import evaluate_corpus
from experiments.run_sweep import ALL_ENTITY_TYPES
from experiments.transformer_baseline.piiranha_filter import PiiranhaFilter

RESULTS_DIR = Path(__file__).parent.parent / "results"

_ENTITY_SUBSETS: list[list[str]] = [[et] for et in ALL_ENTITY_TYPES] + [ALL_ENTITY_TYPES]
_MIN_SCORES = [0.30, 0.40, 0.50, 0.60, 0.70]


def _build_configs() -> list[dict[str, Any]]:
    return [
        {"entities": sorted(entities), "min_score": ms}
        for entities in _ENTITY_SUBSETS
        for ms in _MIN_SCORES
    ]


def run_sweep(
    corpus_path: Path,
    out_path: Path,
    *,
    sample_n: int | None = None,
    overlap_mode: str = "partial",
    device: str = "cpu",
) -> None:
    print(f"Loading corpus from {corpus_path}...")
    samples = load_corpus(corpus_path)
    if sample_n is not None and sample_n < len(samples):
        import random

        rng = random.Random(42)
        samples = rng.sample(samples, sample_n)
        print(f"  Downsampled to {len(samples)} samples.")
    else:
        print(f"  Loaded {len(samples)} samples.")

    configs = _build_configs()
    print(f"Sweep: {len(configs)} configurations on Piiranha (device={device})")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as fh:
        for i, cfg in enumerate(configs, 1):
            entities = cfg["entities"]
            min_score = cfg["min_score"]

            pii_filter = PiiranhaFilter(min_score=min_score, device=device, entities=entities)

            t0 = time.perf_counter()
            report = evaluate_corpus(samples, pii_filter, overlap_mode=overlap_mode)
            elapsed = time.perf_counter() - t0

            row = {
                "backend": "piiranha",
                "model": PiiranhaFilter.MODEL_ID,
                "entities": entities,
                "min_score": min_score,
                "n_samples": len(samples),
                "overlap_mode": overlap_mode,
                "device": device,
                "elapsed_s": round(elapsed, 3),
                **report.to_dict(),
            }
            fh.write(json.dumps(row) + "\n")
            fh.flush()

            print(
                f"  [{i:>3}/{len(configs)}] entities=[{','.join(e[:3] for e in entities)}...] "
                f"min_score={min_score}  P={report.micro_precision():.3f} "
                f"R={report.micro_recall():.3f} F1={report.micro_f1():.3f} "
                f"({elapsed:.1f}s)"
            )

    print(f"\nResults written to {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Piiranha baseline sweep")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=CORPUS_DIR / "corpus.jsonl",
        help="Path to corpus JSONL file",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=RESULTS_DIR / "baseline_eval.jsonl",
        help="Output JSONL path",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        help="Downsample corpus to N samples for quick runs",
    )
    parser.add_argument(
        "--overlap",
        choices=["partial", "exact"],
        default="partial",
        help="Span matching mode (default: partial)",
    )
    parser.add_argument(
        "--device",
        choices=["cpu", "cuda"],
        default="cpu",
        help="Inference device (default: cpu)",
    )
    args = parser.parse_args()

    run_sweep(
        corpus_path=args.corpus,
        out_path=args.out,
        sample_n=args.sample,
        overlap_mode=args.overlap,
        device=args.device,
    )


if __name__ == "__main__":
    main()
