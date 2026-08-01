# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Surface-form robustness probe for PIIFilter.

The seeded corpus (``corpus/generate.py``, seed 42) samples email addresses from five
surface forms: bare, ``mailto:``, subdomain/plus-tagged, uppercase, and numeric local
part. It contains no percent-encoded form, so the sweep does not measure whether the
filter recovers an email address that has been URL-encoded into a path or query string
-- the form an x402 ``resource`` URL most plausibly carries.

This probe measures that directly, outside the corpus, so the corpus and every result
deposited against it stay byte-identical. Each case is a single string in a realistic
x402 ``resource`` URL shape; a case passes if the filter reports EMAIL_ADDRESS.

Usage::

    python -m experiments.surface_form_probe
    python -m experiments.surface_form_probe --min-score 0.5
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

RESULTS_DIR = Path(__file__).parent / "results"

_LOCAL = "alice.martin"
_DOMAIN = "example.com"
_ADDR = f"{_LOCAL}@{_DOMAIN}"

# (variant, in-corpus?, text). ``in_corpus`` marks the forms the seeded corpus already
# exercises, so the probe reports the encoded forms against a known-good control.
CASES: list[tuple[str, bool, str]] = [
    ("bare (control, in corpus)", True, f"https://api.example.com/v1/users/{_ADDR}/exports"),
    ("query param (control, in corpus)", True, f"https://api.example.com/v1/records?user={_ADDR}"),
    (
        "percent-encoded @ (%40), path segment",
        False,
        f"https://api.example.com/v1/users/{_LOCAL}%40{_DOMAIN}/exports",
    ),
    (
        "percent-encoded @ (%40), query value",
        False,
        f"https://api.example.com/v1/records?user={_LOCAL}%40{_DOMAIN}",
    ),
    (
        "percent-encoded @ and dot (%40, %2E)",
        False,
        "https://api.example.com/v1/users/alice%2Emartin%40example%2Ecom/exports",
    ),
    (
        "double-encoded @ (%2540)",
        False,
        f"https://api.example.com/v1/users/{_LOCAL}%2540{_DOMAIN}/exports",
    ),
    (
        "uppercase percent-encoding in mailto",
        False,
        f"mailto:{_LOCAL}%40{_DOMAIN}",
    ),
    (
        "plus-encoded local part (%2B tag)",
        False,
        f"https://api.example.com/v1/users/{_LOCAL}%2Bapi%40{_DOMAIN}/exports",
    ),
]


def run(min_score: float) -> dict:
    """Scan every probe case and record whether EMAIL_ADDRESS was reported."""
    from presidio_x402.pii_filter import PIIFilter

    pii_filter = PIIFilter(mode="nlp", entities=None, min_score=min_score)

    cases = []
    for variant, in_corpus, text in CASES:
        redacted, ents = pii_filter.scan_and_redact(text)
        types = sorted({e.entity_type for e in ents})
        cases.append(
            {
                "variant": variant,
                "in_corpus": in_corpus,
                "input": text,
                "redacted": redacted,
                "entities": types,
                "email_detected": "EMAIL_ADDRESS" in types,
            }
        )

    encoded = [c for c in cases if not c["in_corpus"]]
    return {
        "config": {"mode": "nlp", "entities": "all", "min_score": min_score},
        "n_cases": len(cases),
        "n_encoded_cases": len(encoded),
        "n_encoded_detected": sum(1 for c in encoded if c["email_detected"]),
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Email surface-form robustness probe")
    parser.add_argument("--min-score", type=float, default=0.5)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "surface_form_probe.json")
    args = parser.parse_args()

    result = run(args.min_score)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"=== Email surface-form probe (nlp, all entities, min_score={args.min_score}) ===")
    for c in result["cases"]:
        mark = "DETECT" if c["email_detected"] else " MISS "
        tag = "corpus" if c["in_corpus"] else "encoded"
        print(f"  [{mark}] ({tag}) {c['variant']:<42} entities={','.join(c['entities']) or '-'}")
    print(
        f"\n  encoded forms detected: {result['n_encoded_detected']}/{result['n_encoded_cases']}"
    )
    print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
