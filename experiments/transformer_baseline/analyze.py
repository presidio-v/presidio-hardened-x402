"""Compare Piiranha baseline results against the Presidio sweep.

Produces a side-by-side per-entity comparison table and the head-to-head
all-entities row that goes into Table III of the paper. Reads:

  - experiments/results/sweep_results_both.jsonl  (Presidio regex+nlp)
  - experiments/results/baseline_eval.jsonl       (Piiranha)

Usage::

    python -m experiments.transformer_baseline.analyze
    python -m experiments.transformer_baseline.analyze --out /tmp/cmp.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ALL_ENTITIES = [
    "EMAIL_ADDRESS",
    "PERSON",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _is_all_entities(row: dict[str, Any]) -> bool:
    return sorted(row.get("entities", [])) == sorted(ALL_ENTITIES)


def _best_all_entities(rows: list[dict[str, Any]], filter_fn=None) -> dict[str, Any] | None:
    candidates = [r for r in rows if _is_all_entities(r)]
    if filter_fn is not None:
        candidates = [r for r in candidates if filter_fn(r)]
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.get("micro_f1", 0))


def _per_entity_rows(row: dict[str, Any]) -> dict[str, dict[str, float]]:
    return {e["entity_type"]: e for e in row.get("per_entity", [])}


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare Piiranha vs Presidio")
    parser.add_argument(
        "--presidio",
        type=Path,
        default=Path("experiments/results/sweep_results_both.jsonl"),
    )
    parser.add_argument(
        "--piiranha",
        type=Path,
        default=Path("experiments/results/baseline_eval.jsonl"),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("experiments/results/baseline_comparison.json"),
    )
    args = parser.parse_args()

    presidio = _load_jsonl(args.presidio) if args.presidio.exists() else []
    piiranha = _load_jsonl(args.piiranha) if args.piiranha.exists() else []

    print(f"Presidio rows: {len(presidio)}")
    print(f"Piiranha rows: {len(piiranha)}")

    best_regex = _best_all_entities(presidio, lambda r: r.get("mode") == "regex")
    best_nlp = _best_all_entities(presidio, lambda r: r.get("mode") == "nlp")
    best_piiranha = _best_all_entities(piiranha)

    out = {
        "best_regex": best_regex,
        "best_nlp": best_nlp,
        "best_piiranha": best_piiranha,
    }

    print("\n=== Best all-entities config per backend ===")
    for label, row in [("regex", best_regex), ("nlp", best_nlp), ("piiranha", best_piiranha)]:
        if row is None:
            print(f"  {label:<10} (no data)")
            continue
        ms = row.get("min_score", "-")
        print(
            f"  {label:<10} min_score={ms}  "
            f"P={row.get('micro_precision', 0):.3f}  "
            f"R={row.get('micro_recall', 0):.3f}  "
            f"F1={row.get('micro_f1', 0):.3f}"
        )

    print("\n=== Per-entity F1 (best all-entities config per backend) ===")
    print(f"{'Entity':<16} {'regex':>8} {'nlp':>8} {'piiranha':>10}")
    print("-" * 46)
    rx = _per_entity_rows(best_regex) if best_regex else {}
    nlp = _per_entity_rows(best_nlp) if best_nlp else {}
    pir = _per_entity_rows(best_piiranha) if best_piiranha else {}
    for ent in ALL_ENTITIES:
        rx_f1 = rx.get(ent, {}).get("f1", 0.0)
        nlp_f1 = nlp.get(ent, {}).get("f1", 0.0)
        pir_f1 = pir.get(ent, {}).get("f1", 0.0)
        print(f"{ent:<16} {rx_f1:>8.3f} {nlp_f1:>8.3f} {pir_f1:>10.3f}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nComparison written to {args.out}")


if __name__ == "__main__":
    main()
