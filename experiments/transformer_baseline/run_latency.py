"""Latency benchmark for the Piiranha (DeBERTa-v3 PII) baseline.

Mirrors ``experiments/run_latency.py``: 200 warmup + 1000 timed iterations
cycling through the corpus, calling ``scan_payment_fields`` per sample, and
recording p50/p95/p99 in milliseconds.

Usage::

    python -m experiments.transformer_baseline.run_latency
    python -m experiments.transformer_baseline.run_latency --device cuda
    python -m experiments.transformer_baseline.run_latency --n 200 --warmup 50
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from corpus.generate import CORPUS_DIR, load_corpus
from experiments.run_sweep import ALL_ENTITY_TYPES
from experiments.transformer_baseline.piiranha_filter import PiiranhaFilter

RESULTS_DIR = Path(__file__).parent.parent / "results"


def _percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    idx = (p / 100) * (len(s) - 1)
    lo = int(idx)
    hi = lo + 1
    if hi >= len(s):
        return s[-1]
    return s[lo] + (idx - lo) * (s[hi] - s[lo])


def benchmark(
    corpus_path: Path,
    *,
    n_warmup: int = 200,
    n_timed: int = 1000,
    device: str = "cpu",
    entities: list[str] | None = None,
    min_score: float = 0.5,
) -> dict:
    samples = load_corpus(corpus_path)
    if not samples:
        raise ValueError(f"No samples found in {corpus_path}")

    print(f"  Building PiiranhaFilter(device={device!r}, min_score={min_score})...")
    pii_filter = PiiranhaFilter(min_score=min_score, device=device, entities=entities)

    n = len(samples)
    print(f"  Warming up ({n_warmup} iterations)...")
    for i in range(n_warmup):
        s = samples[i % n]
        pii_filter.scan_payment_fields(s.resource_url, s.description, s.reason)

    print(f"  Timing ({n_timed} iterations)...")
    latencies_ms: list[float] = []
    for i in range(n_timed):
        s = samples[i % n]
        t0 = time.perf_counter()
        pii_filter.scan_payment_fields(s.resource_url, s.description, s.reason)
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    return {
        "backend": "piiranha",
        "model": PiiranhaFilter.MODEL_ID,
        "device": device,
        "entities": entities or list(ALL_ENTITY_TYPES),
        "min_score": min_score,
        "n_warmup": n_warmup,
        "n_timed": n_timed,
        "p50_ms": round(_percentile(latencies_ms, 50), 3),
        "p95_ms": round(_percentile(latencies_ms, 95), 3),
        "p99_ms": round(_percentile(latencies_ms, 99), 3),
        "mean_ms": round(statistics.mean(latencies_ms), 3),
        "min_ms": round(min(latencies_ms), 3),
        "max_ms": round(max(latencies_ms), 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Piiranha latency benchmark")
    parser.add_argument("--corpus", type=Path, default=CORPUS_DIR / "corpus.jsonl")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "baseline_latency.json")
    parser.add_argument("--n", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--device", choices=["cpu", "cuda"], default="cpu")
    args = parser.parse_args()

    print(f"\n--- Benchmarking Piiranha (device={args.device}) ---")
    result = benchmark(
        corpus_path=args.corpus,
        n_warmup=args.warmup,
        n_timed=args.n,
        device=args.device,
    )
    print(
        f"  Results: p50={result['p50_ms']:.2f}ms  "
        f"p95={result['p95_ms']:.2f}ms  p99={result['p99_ms']:.2f}ms"
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump([result], fh, indent=2)
    print(f"\nLatency results written to {args.out}")


if __name__ == "__main__":
    main()
