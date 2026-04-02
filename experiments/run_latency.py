"""Latency benchmark for PIIFilter.scan_payment_fields.

Measures p50, p95, and p99 latency (ms) for PIIFilter in regex and nlp modes
across a random sample of corpus entries. Results are written to
``experiments/results/latency_results.json``.

Usage::

    python -m experiments.run_latency                     # 500 warm-up + 1000 timed
    python -m experiments.run_latency --mode nlp          # nlp mode (requires spaCy)
    python -m experiments.run_latency --n 500             # 500 timed iterations
    python -m experiments.run_latency --out /tmp/lat.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from corpus.generate import CORPUS_DIR, load_corpus
from experiments.run_sweep import ALL_ENTITY_TYPES

RESULTS_DIR = Path(__file__).parent / "results"


def _percentile(data: list[float], p: float) -> float:
    """Return the p-th percentile of sorted data."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = (p / 100) * (len(sorted_data) - 1)
    lo = int(idx)
    hi = lo + 1
    if hi >= len(sorted_data):
        return sorted_data[-1]
    frac = idx - lo
    return sorted_data[lo] + frac * (sorted_data[hi] - sorted_data[lo])


def benchmark(
    mode: str,
    corpus_path: Path,
    n_warmup: int = 200,
    n_timed: int = 1000,
    entities: list[str] | None = None,
) -> dict:
    """Run latency benchmark for the given mode.

    Returns a dict with p50/p95/p99 in milliseconds.
    """
    from presidio_x402.pii_filter import PIIFilter

    samples = load_corpus(corpus_path)
    if not samples:
        raise ValueError(f"No samples found in {corpus_path}")

    print(f"  Building PIIFilter(mode={mode!r})...")
    pii_filter = PIIFilter(mode=mode, entities=entities)

    # Cycle through corpus for variety
    n_samples = len(samples)

    print(f"  Warming up ({n_warmup} iterations)...")
    for i in range(n_warmup):
        s = samples[i % n_samples]
        pii_filter.scan_payment_fields(s.resource_url, s.description, s.reason)

    print(f"  Timing ({n_timed} iterations)...")
    latencies_ms: list[float] = []
    for i in range(n_timed):
        s = samples[i % n_samples]
        t0 = time.perf_counter()
        pii_filter.scan_payment_fields(s.resource_url, s.description, s.reason)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies_ms.append(elapsed_ms)

    result = {
        "mode": mode,
        "entities": entities or (list(pii_filter.entities) if pii_filter.entities else list(ALL_ENTITY_TYPES)),
        "n_warmup": n_warmup,
        "n_timed": n_timed,
        "p50_ms": round(_percentile(latencies_ms, 50), 3),
        "p95_ms": round(_percentile(latencies_ms, 95), 3),
        "p99_ms": round(_percentile(latencies_ms, 99), 3),
        "mean_ms": round(statistics.mean(latencies_ms), 3),
        "min_ms": round(min(latencies_ms), 3),
        "max_ms": round(max(latencies_ms), 3),
    }

    print(
        f"  Results: p50={result['p50_ms']:.2f}ms  "
        f"p95={result['p95_ms']:.2f}ms  p99={result['p99_ms']:.2f}ms"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="PIIFilter latency benchmark")
    parser.add_argument(
        "--mode", choices=["regex", "nlp", "both"], default="regex",
        help="PIIFilter mode(s) to benchmark (default: regex)",
    )
    parser.add_argument(
        "--corpus", type=Path, default=CORPUS_DIR / "corpus.jsonl",
        help="Path to corpus JSONL file",
    )
    parser.add_argument(
        "--out", type=Path, default=RESULTS_DIR / "latency_results.json",
        help="Output JSON path",
    )
    parser.add_argument("--n", type=int, default=1000, help="Number of timed iterations")
    parser.add_argument("--warmup", type=int, default=200, help="Number of warm-up iterations")
    args = parser.parse_args()

    modes = ["regex", "nlp"] if args.mode == "both" else [args.mode]
    results = []

    for mode in modes:
        print(f"\n--- Benchmarking mode={mode} ---")
        try:
            result = benchmark(
                mode=mode,
                corpus_path=args.corpus,
                n_warmup=args.warmup,
                n_timed=args.n,
            )
            results.append(result)
        except Exception as exc:
            print(f"  ERROR: {exc}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nLatency results written to {args.out}")


if __name__ == "__main__":
    main()
