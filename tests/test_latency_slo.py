"""Tests for the latency SLO checker used by CI."""

from __future__ import annotations

import json

import pytest

from experiments.check_latency_slo import check_latency_slo


def _write_results(path, p99_ms: float) -> None:
    path.write_text(json.dumps([{"mode": "regex", "p99_ms": p99_ms}]), encoding="utf-8")


def test_check_latency_slo_accepts_current_within_budget(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    _write_results(baseline, 1.0)
    _write_results(current, 2.0)

    check_latency_slo(current, baseline_path=baseline, max_p99_ms=50.0)


def test_check_latency_slo_rejects_regression(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    _write_results(baseline, 1.0)
    _write_results(current, 60.0)

    with pytest.raises(ValueError, match="exceeds allowed"):
        check_latency_slo(current, baseline_path=baseline, max_p99_ms=50.0)
