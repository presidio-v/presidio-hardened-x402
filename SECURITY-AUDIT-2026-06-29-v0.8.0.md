# Independent Security Audit — v0.8.0 (library scope)

Date: 2026-06-29

Scope: `presidio-hardened-x402` v0.8.0 public library in `tools/` — the PII
filter (regex/NLP modes), `action_ref` primitive, the composed-envelope
`screen_ref` leg, log hygiene, the release/publish workflow, and supply-chain
provenance.

Verdict: **GO.** The v0.8.0 release cycle underwent an independent, multi-round
adversarial security audit. The library scope cleared with no open
Critical/High/Medium findings. Each round re-attempted the prior round's
bypasses; the final round found no new issues in scope.

## Library findings assessed

| Severity | Finding | Assessment | Remediation |
|---|---|---|---|
| Medium | NLP mode could silently miss structured identifiers | Valid. A bare `AnalyzerEngine` scored some structured identifiers (e.g. `US_SSN`, `PHONE_NUMBER`) below threshold, so `mode="nlp"` detected fewer entities than the zero-setup `mode="regex"`. | `pii_filter.py` now registers the structural pattern recognizers on top of the spaCy NER pipeline, making NLP a strict **superset** of regex. Verified: `mode="nlp"` detects/redacts SSN, phone, credit card, email, IBAN, IP, plus NER entities. |
| Low | `action_ref` byte-determinism gaps | Valid. Empty entity-type sets and non-NFC field encodings could yield a different `action_ref` for the same logical action. | `action_ref` rejects empty entity-type sets and NFC-normalizes its fields before hashing (audit F1/F2). |
| Low | PII-bearing URL could reach a log sink | Valid. The missing-payment-header warning logged the raw resource URL. | The URL is redacted before the warning is logged. |
| Info | Supply-chain provenance should be explicit and measured | Valid release-hardening item. | Weekly OpenSSF Scorecard workflow + README badge; Scorecard Token-Permissions / SAST / Signed-Releases / Branch-Protection remediations; SLSA Build L3 provenance documented. |

## Release gate

Before tagging v0.8.0, run:

```bash
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
/Users/vstantch/.local/bin/uv lock --check
/Users/vstantch/.local/bin/uv run --extra audit --extra evidence --extra redis --extra audit-s3 --extra langchain --extra prometheus --extra otel --extra schema pip-audit --progress-spinner=off --skip-editable
.venv/bin/python -m pytest tests/ -x -q --tb=short
```

Audit run results (final round): `ruff` clean, `pytest` 502 passed / 1 skipped,
`pip-audit` no known vulnerabilities.

## Note

The full multi-round audit reports (which also cover internal, non-published
service components outside this package) are retained in the private security
record, not in this public repository.
