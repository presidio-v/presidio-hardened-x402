# Changelog

All notable changes to `presidio-hardened-x402` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING (crypto-mode MPA):** countersignatures are now freshness-bound. The
  wire format is `"<unix_ts>:<hmac_hex>"` and the signed payload includes the
  approver's timestamp; the engine rejects signatures outside the new
  `MPAConfig.max_signature_age_seconds` window (default 300s). This prevents a
  captured countersignature from being replayed for an identical payment once the
  ReplayGuard TTL elapses (F-8, audit 2026-06-03). Approvers should produce
  signatures with the new `build_countersignature()` helper; bare-hex signatures
  from prior versions no longer validate.

### Added
- `mpa.build_countersignature(shared_secret, details, amount_usd)` — public
  helper that produces the timestamped crypto-mode countersignature.
- Sink-level secret redaction: `install_log_redaction()` attaches a
  `RedactingFilter` (`SecretRedactor`) to every logger in the `presidio_x402`
  namespace at import time, scrubbing API keys, bearer tokens, and 32-byte hex
  key/signature material from log records before they reach any handler. Wallet
  *addresses* (20-byte) are intentionally preserved. Closes the call-site-only
  redaction gap flagged by the third-party family audit (rec R2, 2026-06-06).

### Security
- Harden `_parse_402_header` against non-dict `accepts[]` entries. A hostile 402
  server sending a primitive (e.g. `{"accepts": ["exact"]}`) previously raised an
  uncaught `AttributeError` that bypassed the sanitised audit path; non-dict
  entries are now skipped and surface as the structured "No supported payment
  scheme" `X402PaymentError` (F1, audit 2026-06-07; CWE-20).
- `PIIFilter.scan_dict` now scans and redacts string **keys** in addition to
  values. PII embedded as a dict key (e.g. `{"alice@example.com": ...}`) in the
  server-controlled `extra` field previously passed through unredacted to MPA
  webhooks and the audit log (F2, audit 2026-06-07; CWE-200).
- Add explicit `idna>=3.15` floor (previously only transitive via httpx) to
  evict CVE-2026-45409 on a fresh resolve (defense-in-depth; family audit rec R3).
- Pin all GitHub Actions in CI/CodeQL workflows to commit SHAs (was floating
  `@v6`/`@v7` tags), closing a supply-chain tag-mutation vector. Dependabot's
  `github-actions` ecosystem keeps the pins current (config audit, 2026-06-07).

### Added (packaging)
- Top-level `LICENSE` file (MIT) so GitHub detects the license badge; the
  package already declared `license = "MIT"` in `pyproject.toml` (config audit).

### Documentation
- `SECURITY.md` now documents which security controls are automatic vs. opt-in,
  removing ambiguity in the prior controls list (family audit rec R5).

## [0.4.0] — 2026-05-17

The screening-api release. Pairs the published `screen.presidio-group.eu`
service (deploy 2026-04-20) with the library `remote_screening=True` mode.

### Added
- `screening_client.ScreeningClient` — httpx-injectable client for the hosted
  Presidio screening service; opt-in via `HardenedX402Client(remote_screening=True)`.
- Per-origin `pay_to` allowlist in `gateway.py` (chain-06 mitigation).

### Changed
- `compute_fingerprint` now canonicalises `pay_to` (lowercase) and `currency`
  (uppercase) before HMAC, closing the case-variant replay-bypass surface (F1,
  audit 2026-05-17).
- `audit_log` now logs at ERROR when `PRESIDIO_X402_CHAIN_KEY` is unset,
  matching the existing `replay_guard` pattern (F2, audit 2026-05-17).
- Replay fingerprint canonicalisation switched from pipe-joined string to
  JSON-array encoding to avoid server-controlled-`resource_url` collisions
  (F-D, audit 2026-05-10).
- Replay detection event now emits at ERROR with a structured `extra` payload
  for SIEM correlation (F-E, audit 2026-05-10).
- Bandit SAST step in `tools/.github/workflows/codeql.yml` no longer uses
  `--exit-zero`; MEDIUM+ findings at MEDIUM+ confidence now block CI (F-C,
  audit 2026-05-10).

### Security
- New length cap on the `X-PAYMENT` header (64 KiB) before `json.loads`,
  blocking client-side DoS from hostile 402 servers (F3, audit 2026-05-17).
- Outbound MPA HMAC + response-side `compare_digest` validation closes the
  chain-07 SSRF surface (F-A/F-B, audit 2026-05-03).
- PII filter `scan_dict` now covers the `extra` metadata dict on
  `PaymentDetails`, closing the chain-04 / F-A surface (audit 2026-05-03).
- Dependency bumps: `urllib3` 2.6.3 → 2.7.0 (CVE-2026-44431, CVE-2026-44432),
  `langsmith` 0.7.32 → 0.8.4 (CVE-2026-45134), `python-multipart` 0.0.26 →
  0.0.27 (CVE-2026-42561), `langchain-core` 1.3.0 → 1.3.3 (CVE-2026-44843),
  `python-dotenv` 1.1.1 → 1.2.2 (GHSA-mf9w-mj56-hr94).

### Notes
- 274 tests pass on Python 3.10 / 3.11 / 3.12 / 3.13.
- 8 adversary chains dispositioned per `adversary-attack/README.md` (3 CLOSED,
  3 MITIGATED-config, 2 PARTIAL with residual scope deferred to v0.5.0).
- Two configuration env vars are required for full security posture in
  multi-replica / persistent deployments: `PRESIDIO_X402_FINGERPRINT_KEY` and
  `PRESIDIO_X402_CHAIN_KEY`. Both fall back to per-process keys with ERROR-level
  startup logs; hard startup-gates are queued for v0.5.0.

## [0.3.0] — 2026-04 (no changelog entry kept)

Multi-party authorisation engine (`MPAEngine`), policy-as-code JSON Schema
(`x402_policy_schema.py`), Prometheus metrics (`MetricsCollector`), Helm chart
and Docker sidecar image. See `git log v0.2.0..v0.3.0` for detail.
