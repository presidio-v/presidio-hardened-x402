---
license: mit
language:
- en
tags:
- pii
- privacy
- x402
- payments
- synthetic
- named-entity-recognition
pretty_name: x402 PII Metadata Corpus
size_categories:
- 1K<n<10K
task_categories:
- token-classification
task_ids:
- named-entity-recognition
---

# x402 PII Metadata Corpus

Synthetic labelled corpus of 2,000 x402 payment metadata triples for PII filter evaluation.
Released alongside the paper **"Hardening x402: Privacy-Preserving Agentic Payments via Pre-Execution Metadata Filtering"**.

- **Paper:** [arXiv:2604.11430](https://arxiv.org/abs/2604.11430) [cs.CR]
- **Canonical archive:** [IEEE DataPort doi:10.21227/kpsz-nq73](https://doi.org/10.21227/kpsz-nq73)
- **Code:** [presidio-v/presidio-hardened-x402](https://github.com/presidio-v/presidio-hardened-x402)

## Dataset description

Each record represents one x402 payment metadata triple (`resource_url`, `description`, `reason`)
drawn from seven API categories. 36% of samples contain at least one synthetic PII entity
injected into one of the three fields, with ground-truth span labels.

### Fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Sample identifier (`syn-NNNNN`) |
| `category` | string | API category (`media`, `medical`, `financial`, `data_access`, `generic`, `compute`, `ai_inference`) |
| `resource_url` | string | Synthetic x402 resource URL |
| `description` | string | Payment description field |
| `reason` | string | Payment reason field |
| `pii_positive` | bool | `true` if any PII entity is present |
| `labels` | list | Ground-truth entity annotations (see below) |

### Label schema

```json
{
  "entity_type": "EMAIL_ADDRESS",
  "field": "description",
  "start": 24,
  "end": 45,
  "value": "<synthetic value>"
}
```

Entity types: `PERSON`, `EMAIL_ADDRESS`, `US_SSN`, `IBAN_CODE`, `CREDIT_CARD`, `PHONE_NUMBER`.

### Corpus statistics

| Split | Samples |
|---|---|
| train (all) | 2,000 |

| Entity type | Count | Share |
|---|---|---|
| PERSON | 321 | 36.7% |
| EMAIL_ADDRESS | 313 | 35.8% |
| IBAN_CODE | 96 | 11.0% |
| US_SSN | 85 | 9.7% |
| PHONE_NUMBER | 32 | 3.7% |
| CREDIT_CARD | 28 | 3.2% |

## Usage

```python
from datasets import load_dataset

ds = load_dataset("vstantch/x402-pii-corpus")
print(ds["train"][0])
```

## Citation

```bibtex
@misc{stantchev2026hardeningx402,
  title   = {Hardening x402: Privacy-Preserving Agentic Payments via Pre-Execution Metadata Filtering},
  author  = {Stantchev, Vladimir},
  year    = {2026},
  eprint  = {2604.11430},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
}
```

Corpus data also archived at IEEE DataPort:

```bibtex
@misc{stantchev2026dataset,
  author       = {Stantchev, Vladimir},
  title        = {Hardening x402: PII Filter Corpus, Sweep Results, and Live Ecosystem Data},
  year         = {2026},
  publisher    = {IEEE DataPort},
  doi          = {10.21227/kpsz-nq73},
  howpublished = {IEEE DataPort, \url{https://doi.org/10.21227/kpsz-nq73}},
}
```
