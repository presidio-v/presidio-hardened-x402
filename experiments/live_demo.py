# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Controlled demonstration of PIIFilter on metadata derived from live x402 endpoints.

Reproduces the controlled-demonstration table in the live data study. Each case is a
metadata triple whose *field structure* is taken from an endpoint observed during the
2026-04-04 HTTP probe (see ``v0.2.1/data/scan_results.jsonl``), with a realistic but
non-real entity value planted where real caller data would appear. No live traffic and
no real user data is involved.

The probe recorded only the ``resource``/``description`` strings the endpoints actually
returned; the planted values here model what those fields would carry once a caller
supplies input to the documented parameter of each endpoint.

Two cases are deliberately adversarial to this middleware rather than flattering to it:
``password-strength`` plants the value its parameter actually documents -- a password,
for which no recogniser exists in any configuration -- and ``user-data API, encoded``
plants the percent-encoded form of an address that the unencoded case recovers. Both are
expected to miss. They are included because a demonstration that only plants detectable
types measures the plant, not the filter.

Usage::

    python -m experiments.live_demo
    python -m experiments.live_demo --min-score 0.5 --out results/live_demo.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

RESULTS_DIR = Path(__file__).parent / "results"

ALL_ENTITIES = [
    "EMAIL_ADDRESS",
    "PERSON",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
]


@dataclass
class DemoCase:
    """One controlled-demonstration input.

    Attributes
    ----------
    case:
        Human-readable label for the endpoint or endpoint family.
    pattern:
        Structural risk pattern (P1 query-parameter passthrough, P2 request-body
        reflection, P3 path-segment identifier).
    carrier_field:
        Metadata field into which the endpoint design places the caller value.
    planted:
        The entity type deliberately planted in ``carrier_field``.
    fields:
        The full metadata triple submitted to the filter.
    """

    case: str
    pattern: str
    carrier_field: str
    planted: str
    fields: dict[str, str] = field(default_factory=dict)


# Field structures taken from endpoints observed in the 2026-04-04 probe; planted
# values are synthetic. `ip-info`, `whois` and `password-strength` are fatihai
# endpoints seen live; the user-data, medical and billing cases model the
# path-segment pattern (P3) documented in the probe's structural analysis.
DEMO_CASES: list[DemoCase] = [
    DemoCase(
        case="ip-info",
        pattern="P1",
        carrier_field="resource_url",
        planted="IP_ADDRESS",
        fields={
            "resource_url": "https://x402.fatihai.app/api/ip-info?ip=203.0.113.42",
            "description": "IP geolocation lookup",
            "reason": "",
        },
    ),
    DemoCase(
        case="user-data API",
        pattern="P3",
        carrier_field="resource_url",
        planted="EMAIL_ADDRESS",
        fields={
            "resource_url": "https://api.example.com/v1/user/alice.martin@corp.io/profile",
            "description": "User profile export",
            "reason": "",
        },
    ),
    DemoCase(
        case="verify-email",
        pattern="P2",
        carrier_field="reason",
        planted="EMAIL_ADDRESS",
        fields={
            "resource_url": "https://x402.fatihai.app/api/verify-email",
            "description": "Email deliverability verification",
            "reason": "email=alice.martin@corp.io; session=sess-7f21a",
        },
    ),
    DemoCase(
        case="medical API",
        pattern="P3",
        carrier_field="reason",
        planted="US_SSN",
        fields={
            "resource_url": "https://api.medrecords.io/patient/records/export",
            "description": "Medical record export",
            "reason": "patient_ref=312-45-6789",
        },
    ),
    DemoCase(
        case="billing API",
        pattern="P3",
        carrier_field="description",
        planted="CREDIT_CARD",
        fields={
            "resource_url": "https://api.example.com/v1/billing/statement",
            "description": "Statement for card 4111111111111111 held by Maria Garcia",
            "reason": "",
        },
    ),
    DemoCase(
        case="whois lookup",
        pattern="P1",
        carrier_field="resource_url",
        planted="PERSON",
        fields={
            "resource_url": "https://x402.fatihai.app/api/whois?registrant=john-smith",
            "description": "Domain registration lookup",
            "reason": "",
        },
    ),
    DemoCase(
        case="password-strength",
        pattern="P1",
        carrier_field="resource_url",
        planted="PHONE_NUMBER",
        fields={
            "resource_url": "https://x402.fatihai.app/api/password-strength?password=415-555-0182",
            "description": "Password strength scoring",
            "reason": "",
        },
    ),
    DemoCase(
        case="password-strength (documented value)",
        pattern="P1",
        carrier_field="resource_url",
        planted="PASSWORD",
        fields={
            "resource_url": (
                "https://x402.fatihai.app/api/password-strength?password=Hunter2!swordfish"
            ),
            "description": "Password strength scoring",
            "reason": "",
        },
    ),
    DemoCase(
        case="user-data API, encoded",
        pattern="P3",
        carrier_field="resource_url",
        planted="EMAIL_ADDRESS",
        fields={
            "resource_url": "https://api.example.com/v1/user/alice.martin%40corp.io/profile",
            "description": "User profile export",
            "reason": "",
        },
    ),
]


def run(min_score: float) -> dict:
    """Run every demo case through the recommended PIIFilter configuration."""
    from presidio_x402.pii_filter import PIIFilter

    # The library default entity set, not the six types the corpus sweep sweeps: the
    # live endpoints carry IP addresses and URLs, which are outside the corpus taxonomy.
    # Recorded explicitly in the output so the two configurations are never conflated.
    pii_filter = PIIFilter(mode="nlp", entities=None, min_score=min_score)

    cases = []
    for case in DEMO_CASES:
        per_field = {}
        detected: set[str] = set()
        for fname, fval in case.fields.items():
            if not fval:
                continue
            redacted, ents = pii_filter.scan_and_redact(fval)
            types = sorted({e.entity_type for e in ents})
            detected.update(types)
            per_field[fname] = {
                "input": fval,
                "redacted": redacted,
                "entities": types,
            }
        cases.append(
            {
                "case": case.case,
                "pattern": case.pattern,
                "carrier_field": case.carrier_field,
                "planted_entity": case.planted,
                "planted_detected": case.planted in per_field[case.carrier_field]["entities"],
                "entities_detected": sorted(detected),
                "action": "REDACT" if detected else "ALLOW",
                "fields": per_field,
            }
        )

    n_planted = sum(1 for c in cases if c["planted_detected"])
    n_redacted = sum(1 for c in cases if c["action"] == "REDACT")
    # URL is a structural (non-PII) entity the filter also reports; count how often it
    # fires, and how often it fires alongside a planted entity in the same field.
    n_url = sum(1 for c in cases if "URL" in c["entities_detected"])
    n_url_with_planted = sum(
        1
        for c in cases
        if "URL" in c["fields"][c["carrier_field"]]["entities"]
        and len(c["fields"][c["carrier_field"]]["entities"]) > 1
    )

    return {
        "config": {
            "mode": "nlp",
            "entity_set": "library default (adds URL, IP_ADDRESS beyond the corpus six)",
            "min_score": min_score,
        },
        "n_cases": len(cases),
        "n_planted_detected": n_planted,
        "n_redacted": n_redacted,
        "n_cases_with_url_entity": n_url,
        "n_cases_url_alongside_planted": n_url_with_planted,
        "entity_types_intercepted": sorted(
            {c["planted_entity"] for c in cases if c["planted_detected"]}
        ),
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Controlled demo on live endpoint shapes")
    parser.add_argument("--min-score", type=float, default=0.5)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "live_demo.json")
    args = parser.parse_args()

    result = run(args.min_score)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"=== Controlled demonstration (nlp, all entities, min_score={args.min_score}) ===")
    for c in result["cases"]:
        mark = "OK " if c["planted_detected"] else "MISS"
        print(
            f"  [{mark}] {c['case']:<20} {c['pattern']}  {c['carrier_field']:<13} "
            f"planted={c['planted_entity']:<14} detected={','.join(c['entities_detected'])}"
        )
    print(
        f"\n  planted entities detected: {result['n_planted_detected']}/{result['n_cases']}"
        f"   redacted: {result['n_redacted']}/{result['n_cases']}"
    )
    print(
        f"  URL entity reported in {result['n_cases_with_url_entity']} cases "
        f"({result['n_cases_url_alongside_planted']} alongside the planted entity)"
    )
    print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
