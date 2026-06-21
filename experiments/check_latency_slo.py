"""Check PIIFilter latency results against the v0.6.0 p99 SLO."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DEFAULT_BASELINE = Path(__file__).parent / "results" / "latency_results.json"


def _load(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON array of latency result objects")
    return [item for item in data if isinstance(item, dict)]


def _mode_result(results: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    for result in results:
        if result.get("mode") == mode:
            return result
    raise ValueError(f"no latency result for mode={mode!r}")


def _p99(result: dict[str, Any], *, label: str) -> float:
    raw = result.get("p99_ms")
    if not isinstance(raw, int | float):
        raise ValueError(f"{label} result is missing numeric p99_ms")
    return float(raw)


def check_latency_slo(
    results_path: Path,
    *,
    mode: str = "regex",
    baseline_path: Path = DEFAULT_BASELINE,
    max_p99_ms: float = 50.0,
    baseline_multiplier: float = 10.0,
    min_regression_budget_ms: float = 5.0,
) -> None:
    """Raise ValueError if a benchmark result violates the p99 SLO.

    The hard SLO is 50 ms. The baseline tolerance catches large regressions while
    allowing normal CI jitter: the p99 must stay under the stricter of the hard
    SLO and ``max(baseline * multiplier, baseline + min_budget)``.
    """
    current = _mode_result(_load(results_path), mode)
    baseline = _mode_result(_load(baseline_path), mode)
    current_p99 = _p99(current, label="current")
    baseline_p99 = _p99(baseline, label="baseline")
    tolerance_p99 = max(
        baseline_p99 * baseline_multiplier,
        baseline_p99 + min_regression_budget_ms,
    )
    allowed_p99 = min(max_p99_ms, tolerance_p99)
    if current_p99 > allowed_p99:
        raise ValueError(
            f"{mode} p99 latency {current_p99:.3f} ms exceeds allowed "
            f"{allowed_p99:.3f} ms (baseline {baseline_p99:.3f} ms, hard SLO "
            f"{max_p99_ms:.3f} ms)"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Enforce PIIFilter p99 latency SLO")
    parser.add_argument("results", type=Path, help="Benchmark results JSON")
    parser.add_argument("--mode", default="regex", help="Latency result mode to check")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--max-p99-ms", type=float, default=50.0)
    parser.add_argument("--baseline-multiplier", type=float, default=10.0)
    parser.add_argument("--min-regression-budget-ms", type=float, default=5.0)
    args = parser.parse_args()
    check_latency_slo(
        args.results,
        mode=args.mode,
        baseline_path=args.baseline,
        max_p99_ms=args.max_p99_ms,
        baseline_multiplier=args.baseline_multiplier,
        min_regression_budget_ms=args.min_regression_budget_ms,
    )


if __name__ == "__main__":
    main()
