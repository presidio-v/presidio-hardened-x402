"""Synthetic corpus generator for presidio-hardened-x402 PII detection experiments.

Generates a labeled dataset of x402 payment metadata samples (resource_url,
description, reason) spanning seven use-case categories with controlled PII injection.

Usage::

    python -m corpus.generate                  # writes corpus.jsonl + corpus_meta.json
    python -m corpus.generate --seed 99        # reproducible with custom seed
    python -m corpus.generate --n 500 --out /tmp/small.jsonl

Design:
  - 2,000 total samples; ~40% PII-positive by default
  - 7 use-case categories distributed proportionally
  - Each PII entity injected in one of 3–5 surface-form variants
  - Ground-truth labels record field, entity_type, start, end, original_text
  - Deterministic given fixed seed (default: 42)
"""

from __future__ import annotations

import argparse
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .schema import CorpusSample, EntityLabel

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
DEFAULT_SEED = 42
DEFAULT_N = 2000
DEFAULT_PII_RATE = 0.40

CORPUS_DIR = Path(__file__).parent


# ---------------------------------------------------------------------------
# Entity surface-form libraries
# ---------------------------------------------------------------------------

@dataclass
class SurfaceForm:
    name: str
    text: str  # the literal PII text to inject


def _email_forms() -> list[SurfaceForm]:
    pairs = [
        ("bare", "alice.martin@example.com"),
        ("bare", "bob.jones@corp.io"),
        ("bare", "carol_92@health-records.org"),
        ("bare", "dave+api@payments.dev"),
        ("bare", "eve.wilson@university.edu"),
        ("bare", "frank@data.example.net"),
        ("mailto", "mailto:grace@example.com"),
        ("complex", "henry.ford+tag@subdomain.example.com"),
        ("uppercase", "IRIS@DOMAIN.COM"),
        ("numeric_local", "user123@example.com"),
    ]
    return [SurfaceForm(name=n, text=t) for n, t in pairs]


def _person_forms() -> list[SurfaceForm]:
    pairs = [
        ("full_name", "John Smith"),
        ("full_name", "Maria Garcia"),
        ("full_name", "Wei Chen"),
        ("full_name", "Aisha Patel"),
        ("full_name", "Lars Eriksson"),
        ("slug", "john-smith"),
        ("slug", "maria-garcia"),
        ("underscore", "john_smith"),
        ("abbreviated", "J.Smith"),
        ("last_first", "Garcia,Maria"),
        ("first_only", "Aisha"),
    ]
    return [SurfaceForm(name=n, text=t) for n, t in pairs]


def _phone_forms() -> list[SurfaceForm]:
    pairs = [
        ("dashes", "415-555-0182"),
        ("parens", "(415) 555-0182"),
        ("dots", "415.555.0182"),
        ("international", "+14155550182"),
        ("dashes", "312-555-0147"),
        ("parens", "(312) 555-0147"),
        ("dashes", "646-555-0193"),
    ]
    return [SurfaceForm(name=n, text=t) for n, t in pairs]


def _ssn_forms() -> list[SurfaceForm]:
    pairs = [
        ("dashes", "312-45-6789"),
        ("dashes", "421-67-8910"),
        ("no_sep", "312456789"),
        ("spaces", "312 45 6789"),
        ("dashes", "533-12-3456"),
    ]
    return [SurfaceForm(name=n, text=t) for n, t in pairs]


def _credit_card_forms() -> list[SurfaceForm]:
    pairs = [
        ("visa", "4111111111111111"),
        ("mastercard", "5500005555555559"),
        ("visa", "4012888888881881"),
        ("amex", "371449635398431"),
        ("discover", "6011111111111117"),
    ]
    return [SurfaceForm(name=n, text=t) for n, t in pairs]


def _iban_forms() -> list[SurfaceForm]:
    pairs = [
        ("de", "DE89370400440532013000"),
        ("gb", "GB29NWBK60161331926819"),
        ("fr", "FR7630006000011234567890189"),
        ("nl", "NL91ABNA0417164300"),
        ("es", "ES9121000418450200051332"),
    ]
    return [SurfaceForm(name=n, text=t) for n, t in pairs]


ENTITY_FORMS: dict[str, list[SurfaceForm]] = {
    "EMAIL_ADDRESS": _email_forms(),
    "PERSON": _person_forms(),
    "PHONE_NUMBER": _phone_forms(),
    "US_SSN": _ssn_forms(),
    "CREDIT_CARD": _credit_card_forms(),
    "IBAN_CODE": _iban_forms(),
}

# Injection probability weights (must sum to 1.0) — from explore/feasibility.md
ENTITY_TYPE_WEIGHTS: dict[str, float] = {
    "EMAIL_ADDRESS": 0.40,
    "PERSON": 0.25,
    "PHONE_NUMBER": 0.15,
    "US_SSN": 0.10,
    "CREDIT_CARD": 0.05,
    "IBAN_CODE": 0.05,
}

# ---------------------------------------------------------------------------
# URL / description / reason templates
# Each template uses {SLOT} as the injection point.
# Templates without {SLOT} are clean baselines.
# ---------------------------------------------------------------------------

@dataclass
class Template:
    text: str
    slot: str | None  # field name that {SLOT} lives in, or None if clean
    compatible_types: list[str] | None = None  # entity types this template accepts; None = any


def _inject(template_text: str, entity_text: str) -> tuple[str, int, int]:
    """Replace first ``{SLOT}`` in template_text with entity_text.

    Returns (result_string, start_offset, end_offset).
    """
    idx = template_text.index("{SLOT}")
    result = template_text[:idx] + entity_text + template_text[idx + 6:]
    return result, idx, idx + len(entity_text)


# --- URL templates per category ---

_URL_TEMPLATES: dict[str, list[Template]] = {
    "ai_inference": [
        Template("https://api.openai-compat.com/v1/completions?user={SLOT}", "resource_url",
                 ["EMAIL_ADDRESS"]),
        Template("https://inference.example.com/v1/chat?session=abc&for={SLOT}", "resource_url",
                 ["EMAIL_ADDRESS"]),
        Template("https://ai.example.com/v1/models/llm-7b/invoke?user={SLOT}", "resource_url",
                 ["PERSON", "EMAIL_ADDRESS"]),
        Template("https://llm.example.com/v1/generate?requester={SLOT}", "resource_url",
                 ["PERSON"]),
        Template("https://inference.example.com/v1/embed", None),
        Template("https://api.example.com/v1/completions", None),
        Template("https://ai.example.com/v1/models/gpt-4", None),
        Template("https://api.example.com/v1/tokenize", None),
    ],
    "data_access": [
        Template("https://data.example.com/datasets/{SLOT}/private", "resource_url",
                 ["PERSON"]),
        Template("https://api.example.com/v1/records?ssn={SLOT}", "resource_url",
                 ["US_SSN"]),
        Template("https://storage.example.com/users/{SLOT}/exports", "resource_url",
                 ["EMAIL_ADDRESS"]),
        Template("https://api.example.com/v1/users/{SLOT}/profile", "resource_url",
                 ["PERSON"]),
        Template("https://api.example.com/v2/items/42", None),
        Template("https://data.example.com/public/datasets/open-data", None),
        Template("https://storage.example.com/v1/buckets/public/objects/file.csv", None),
    ],
    "medical": [
        Template("https://health.example.com/patient/{SLOT}/records", "resource_url",
                 ["PERSON"]),
        Template("https://labs.example.com/results?patient_phone={SLOT}", "resource_url",
                 ["PHONE_NUMBER"]),
        Template("https://ehr.example.com/records/{SLOT}/history", "resource_url",
                 ["US_SSN"]),
        Template("https://health.example.com/patient/{SLOT}/prescriptions", "resource_url",
                 ["PERSON"]),
        Template("https://health.example.com/api/appointments", None),
        Template("https://ehr.example.com/api/v1/schedules", None),
        Template("https://labs.example.com/api/v1/panels/lipid", None),
    ],
    "compute": [
        Template("https://compute.example.com/gpu/allocate?user={SLOT}", "resource_url",
                 ["EMAIL_ADDRESS"]),
        Template("https://compute.example.com/quota/{SLOT}", "resource_url",
                 ["PERSON"]),
        Template("https://hpc.example.com/v1/jobs/submit?owner={SLOT}", "resource_url",
                 ["EMAIL_ADDRESS"]),
        Template("https://jobs.example.com/v1/jobs/job-7a3f2c/status", None),
        Template("https://compute.example.com/v1/instances/inst-abc123", None),
        Template("https://hpc.example.com/v1/queue/default", None),
        Template("https://compute.example.com/v1/gpu/inventory", None),
    ],
    "media": [
        Template("https://cdn.example.com/users/{SLOT}/photos/album1", "resource_url",
                 ["EMAIL_ADDRESS"]),
        Template("https://media.example.com/content/{SLOT}/feed", "resource_url",
                 ["PERSON"]),
        Template("https://assets.example.com/private/{SLOT}/gallery", "resource_url",
                 ["PERSON"]),
        Template("https://cdn.example.com/media/{SLOT}/videos/latest", "resource_url",
                 ["EMAIL_ADDRESS"]),
        Template("https://assets.example.com/images/public/landscape.jpg", None),
        Template("https://cdn.example.com/v1/stream/public/video123", None),
        Template("https://media.example.com/public/feed/trending", None),
    ],
    "financial": [
        Template("https://banking.example.com/accounts/{SLOT}/balance", "resource_url",
                 ["IBAN_CODE"]),
        Template("https://payments.example.com/cards/{SLOT}/limit", "resource_url",
                 ["CREDIT_CARD"]),
        Template("https://finance.example.com/transfers?from={SLOT}&amount=100", "resource_url",
                 ["IBAN_CODE"]),
        Template("https://banking.example.com/statements?account={SLOT}", "resource_url",
                 ["IBAN_CODE"]),
        Template("https://api.example.com/v1/fx/rates", None),
        Template("https://payments.example.com/v1/fees/schedule", None),
        Template("https://finance.example.com/v1/instruments/public", None),
    ],
    "generic": [
        Template("https://api.example.com/v2/items/42", None),
        Template("https://api.example.com/v2/users/usr_abc123", None),
        Template("https://api.example.com/health", None),
        Template("https://api.example.com/v1/ping", None),
        Template("https://api.example.com/v2/search?q=openapi", None),
        Template("https://api.example.com/v1/status", None),
        Template("https://api.example.com/v2/catalog/items", None),
    ],
}

# --- Description templates ---

_DESC_TEMPLATES: dict[str, list[Template]] = {
    "ai_inference": [
        Template("AI inference request for user {SLOT}", "description", ["EMAIL_ADDRESS", "PERSON"]),
        Template("Model invocation on behalf of {SLOT}", "description", ["PERSON"]),
        Template("LLM completion task", None),
        Template("Embedding generation", None),
    ],
    "data_access": [
        Template("Dataset access for {SLOT}", "description", ["PERSON"]),
        Template("Record retrieval for patient SSN {SLOT}", "description", ["US_SSN"]),
        Template("User data export", None),
        Template("Public dataset access", None),
    ],
    "medical": [
        Template("Medical records for {SLOT}", "description", ["PERSON"]),
        Template("Lab results for patient {SLOT}", "description", ["PERSON"]),
        Template("EHR access", None),
        Template("Appointment scheduling", None),
    ],
    "compute": [
        Template("GPU allocation for {SLOT}", "description", ["EMAIL_ADDRESS", "PERSON"]),
        Template("Compute job submission", None),
        Template("HPC resource request", None),
    ],
    "media": [
        Template("Private gallery access for {SLOT}", "description", ["PERSON", "EMAIL_ADDRESS"]),
        Template("Content feed for {SLOT}", "description", ["PERSON"]),
        Template("Public media stream", None),
        Template("CDN asset delivery", None),
    ],
    "financial": [
        Template("Account balance query for IBAN {SLOT}", "description", ["IBAN_CODE"]),
        Template("Card limit check", None),
        Template("FX rate lookup", None),
    ],
    "generic": [
        Template("API resource access", None),
        Template("Data retrieval", None),
        Template("Service request", None),
    ],
}

# --- Reason templates ---

_REASON_TEMPLATES: dict[str, list[Template]] = {
    "ai_inference": [
        Template("user={SLOT}", "reason", ["EMAIL_ADDRESS"]),
        Template("agent_id=agent-v1", None),
        Template("", None),
    ],
    "data_access": [
        Template("ssn={SLOT}", "reason", ["US_SSN"]),
        Template("ref={SLOT}", "reason", ["EMAIL_ADDRESS"]),
        Template("request_id=abc123", None),
        Template("", None),
    ],
    "medical": [
        Template("patient_phone={SLOT}", "reason", ["PHONE_NUMBER"]),
        Template("patient={SLOT}", "reason", ["PERSON"]),
        Template("clinic_ref=CL-001", None),
        Template("", None),
    ],
    "compute": [
        Template("owner={SLOT}", "reason", ["EMAIL_ADDRESS"]),
        Template("job_ref=job-abc", None),
        Template("", None),
    ],
    "media": [
        Template("user={SLOT}", "reason", ["EMAIL_ADDRESS"]),
        Template("", None),
    ],
    "financial": [
        Template("account={SLOT}", "reason", ["IBAN_CODE"]),
        Template("card={SLOT}", "reason", ["CREDIT_CARD"]),
        Template("", None),
    ],
    "generic": [
        Template("", None),
        Template("request_id=req-999", None),
    ],
}

# ---------------------------------------------------------------------------
# Sample generation helpers
# ---------------------------------------------------------------------------

CATEGORIES = list(_URL_TEMPLATES.keys())

# How many samples per category (proportional, sums to DEFAULT_N)
_CATEGORY_WEIGHTS = {
    "ai_inference": 0.18,
    "data_access": 0.18,
    "medical": 0.15,
    "compute": 0.13,
    "media": 0.13,
    "financial": 0.13,
    "generic": 0.10,
}


def _pick_entity_type(rng: random.Random, compatible: list[str] | None) -> str:
    types = list(ENTITY_TYPE_WEIGHTS.keys())
    weights = list(ENTITY_TYPE_WEIGHTS.values())
    if compatible:
        filtered = [(t, w) for t, w in zip(types, weights) if t in compatible]
        if filtered:
            types, weights = zip(*filtered)
            types, weights = list(types), list(weights)
    return rng.choices(types, weights=weights, k=1)[0]


def _pick_surface(rng: random.Random, entity_type: str) -> SurfaceForm:
    return rng.choice(ENTITY_FORMS[entity_type])


def _fill_template(
    rng: random.Random,
    template: Template,
    entity_type: str,
    surface: SurfaceForm,
) -> tuple[str, EntityLabel | None]:
    """Fill a template with a surface form.

    Returns (filled_text, label_or_None).
    """
    if template.slot is None or "{SLOT}" not in template.text:
        return template.text, None
    filled, start, end = _inject(template.text, surface.text)
    label = EntityLabel(
        field=template.slot,
        entity_type=entity_type,
        start=start,
        end=end,
        original_text=surface.text,
        surface_form=surface.name,
    )
    return filled, label


def _generate_sample(
    rng: random.Random,
    sample_id: str,
    category: str,
    pii_positive: bool,
    pii_rate: float,
) -> CorpusSample:
    """Generate a single labeled corpus sample."""
    labels: list[EntityLabel] = []

    # --- Decide which fields will carry PII ---
    # Field distribution: URL 35%, description 25%, reason 20%, multi-field 20%
    # (of PII-positive samples)
    if pii_positive:
        field_roll = rng.random()
        inject_url = False
        inject_desc = False
        inject_reason = False
        if field_roll < 0.35:
            inject_url = True
        elif field_roll < 0.60:
            inject_desc = True
        elif field_roll < 0.80:
            inject_reason = True
        else:
            # multi-field: pick 2
            inject_url = True
            inject_desc = rng.random() < 0.5
            inject_reason = not inject_desc

    # --- Build URL ---
    url_templates_pii = [
        t for t in _URL_TEMPLATES[category]
        if t.slot == "resource_url" and t.compatible_types
    ]
    url_templates_clean = [
        t for t in _URL_TEMPLATES[category] if t.slot is None
    ]

    if pii_positive and inject_url and url_templates_pii:
        url_tmpl = rng.choice(url_templates_pii)
        entity_type = _pick_entity_type(rng, url_tmpl.compatible_types)
        surface = _pick_surface(rng, entity_type)
        url, label = _fill_template(rng, url_tmpl, entity_type, surface)
        if label:
            labels.append(label)
    else:
        url_tmpl = rng.choice(url_templates_clean or _URL_TEMPLATES[category])
        url = url_tmpl.text.replace("{SLOT}", "")

    # --- Build description ---
    desc_templates_pii = [
        t for t in _DESC_TEMPLATES[category]
        if t.slot == "description" and t.compatible_types
    ]
    desc_templates_clean = [
        t for t in _DESC_TEMPLATES[category] if t.slot is None
    ]

    if pii_positive and inject_desc and desc_templates_pii:
        desc_tmpl = rng.choice(desc_templates_pii)
        entity_type = _pick_entity_type(rng, desc_tmpl.compatible_types)
        surface = _pick_surface(rng, entity_type)
        desc, label = _fill_template(rng, desc_tmpl, entity_type, surface)
        if label:
            labels.append(label)
    else:
        desc_tmpl = rng.choice(desc_templates_clean or _DESC_TEMPLATES[category])
        desc = desc_tmpl.text

    # --- Build reason ---
    reason_templates_pii = [
        t for t in _REASON_TEMPLATES[category]
        if t.slot == "reason" and t.compatible_types
    ]
    reason_templates_clean = [
        t for t in _REASON_TEMPLATES[category] if t.slot is None
    ]

    if pii_positive and inject_reason and reason_templates_pii:
        reason_tmpl = rng.choice(reason_templates_pii)
        entity_type = _pick_entity_type(rng, reason_tmpl.compatible_types)
        surface = _pick_surface(rng, entity_type)
        reason, label = _fill_template(rng, reason_tmpl, entity_type, surface)
        if label:
            labels.append(label)
    else:
        reason_tmpl = rng.choice(reason_templates_clean or _REASON_TEMPLATES[category])
        reason = reason_tmpl.text

    # Recheck actual PII positivity (edge: pii_positive=True but no compatible templates)
    actual_pii = len(labels) > 0

    return CorpusSample(
        id=sample_id,
        category=category,
        resource_url=url,
        description=desc,
        reason=reason,
        pii_positive=actual_pii,
        labels=labels,
    )


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_corpus(
    n: int = DEFAULT_N,
    pii_rate: float = DEFAULT_PII_RATE,
    seed: int = DEFAULT_SEED,
) -> list[CorpusSample]:
    """Generate a reproducible synthetic corpus of *n* labeled x402 metadata samples.

    Parameters
    ----------
    n:
        Total number of samples to generate.
    pii_rate:
        Fraction of samples that should be PII-positive (0.0–1.0).
    seed:
        Random seed for reproducibility.

    Returns
    -------
    list[CorpusSample]
        The generated corpus; PII-positive and clean samples are shuffled together.
    """
    rng = random.Random(seed)

    # Determine per-category counts
    category_counts: dict[str, int] = {}
    remaining = n
    cats = list(_CATEGORY_WEIGHTS.keys())
    for i, cat in enumerate(cats):
        if i == len(cats) - 1:
            category_counts[cat] = remaining
        else:
            count = round(n * _CATEGORY_WEIGHTS[cat])
            category_counts[cat] = count
            remaining -= count

    samples: list[CorpusSample] = []
    global_idx = 0

    for cat, count in category_counts.items():
        n_pii = round(count * pii_rate)
        pii_flags = [True] * n_pii + [False] * (count - n_pii)
        rng.shuffle(pii_flags)

        for i, pii_positive in enumerate(pii_flags):
            sample_id = f"syn-{global_idx:05d}"
            sample = _generate_sample(rng, sample_id, cat, pii_positive, pii_rate)
            samples.append(sample)
            global_idx += 1

    # Final shuffle so categories are interleaved
    rng.shuffle(samples)
    # Re-assign IDs after shuffle so they remain sequential
    for i, s in enumerate(samples):
        s.id = f"syn-{i:05d}"

    return samples


def write_corpus(
    samples: list[CorpusSample],
    out_path: Path,
) -> None:
    """Write corpus to JSONL file."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for sample in samples:
            fh.write(json.dumps(sample.to_dict()) + "\n")


def write_meta(
    samples: list[CorpusSample],
    meta_path: Path,
) -> dict:
    """Write corpus summary statistics to JSON and return the stats dict."""
    n_positive = sum(1 for s in samples if s.pii_positive)
    n_negative = len(samples) - n_positive

    entity_counts: dict[str, int] = {}
    field_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}

    for s in samples:
        category_counts[s.category] = category_counts.get(s.category, 0) + 1
        for lbl in s.labels:
            entity_counts[lbl.entity_type] = entity_counts.get(lbl.entity_type, 0) + 1
            field_counts[lbl.field] = field_counts.get(lbl.field, 0) + 1

    total_entities = sum(entity_counts.values())

    meta = {
        "n_total": len(samples),
        "n_pii_positive": n_positive,
        "n_pii_negative": n_negative,
        "pii_rate": round(n_positive / len(samples), 4),
        "total_pii_entities": total_entities,
        "entity_type_counts": entity_counts,
        "entity_type_rates": {
            k: round(v / total_entities, 4) if total_entities else 0
            for k, v in entity_counts.items()
        },
        "field_counts": field_counts,
        "category_counts": category_counts,
    }

    meta_path.parent.mkdir(parents=True, exist_ok=True)
    with meta_path.open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    return meta


def load_corpus(path: Path) -> list[CorpusSample]:
    """Load a corpus from a JSONL file."""
    samples = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(CorpusSample.from_dict(json.loads(line)))
    return samples


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic x402 PII corpus")
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="Number of samples")
    parser.add_argument("--pii-rate", type=float, default=DEFAULT_PII_RATE,
                        help="Fraction of PII-positive samples (0–1)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=CORPUS_DIR / "corpus.jsonl")
    parser.add_argument("--meta", type=Path, default=CORPUS_DIR / "corpus_meta.json")
    args = parser.parse_args()

    print(f"Generating {args.n} samples (seed={args.seed}, pii_rate={args.pii_rate})...")
    samples = generate_corpus(n=args.n, pii_rate=args.pii_rate, seed=args.seed)

    write_corpus(samples, args.out)
    meta = write_meta(samples, args.meta)

    print(f"Wrote {len(samples)} samples to {args.out}")
    print(f"  PII-positive: {meta['n_pii_positive']} ({meta['pii_rate']:.1%})")
    print(f"  PII-negative: {meta['n_pii_negative']}")
    print(f"  Total entities: {meta['total_pii_entities']}")
    print("  Entity type distribution:")
    for etype, rate in sorted(meta["entity_type_rates"].items(),
                               key=lambda x: -x[1]):
        print(f"    {etype:<20} {rate:.1%}  ({meta['entity_type_counts'][etype]})")
    print(f"Wrote metadata to {args.meta}")


if __name__ == "__main__":
    main()
