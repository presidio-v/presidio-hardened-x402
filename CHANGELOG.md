# Changelog

All notable changes to `presidio-hardened-x402` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **MiCA/EU evidence module** (`mica.py`, session-3 T3): emits Ed25519-signed
  (or HMAC-SHA256) compliance-supporting evidence in the cross-repo
  `presidio-hardened/evidence-ref@1` wire format over a verified audit window.
  The obligation map is data with per-entry legal basis, verification status,
  confidence, and deployment-flag conditions (MiCA Art. 68(8)/(9), DORA
  Arts. 9/17, GDPR Art. 5(1)(c); opt-in MiCA Art. 92(1) PPAET input and DORA
  Art. 9(4) MPA items). Honest-claims enforcement: attestations are emitted only
  when the audit window evidences them; an explicit TFR Art. 14(4)
  layer-separation record prevents redaction-vs-travel-rule overclaiming; AMLR
  citations are absent until article-level verification (guarded by test).
  Fail-closed throughout: broken audit chain, missing key, empty window, or
  missing deployment flags refuse to sign. Research memo with per-claim
  verification status: `docs/mica-obligations.md`. New optional extra
  `[evidence]` (cryptography>=46.0.6); HMAC mode needs no extra. Public API:
  `build_evidence`, `Obligation`, `OBLIGATION_MAP`, `EvidenceError`.

## [0.5.0] — 2026-06-12

The OEM embed-kit release (session-3 T1+T2). Includes everything previously
listed under Unreleased (MPA freshness binding, sink-level redaction, F1/F2
hardening) — folded into this version. Founder-signed release pending.

### Added
- **Rail-agnostic screening core:** `core.ScreeningPipeline` — the four-control
  sequence (PII → trusted-wallet → policy → replay → MPA, with audit and
  speculative-commit rollback) extracted verbatim from the gateway. Operates on
  `PaymentDetails` alone; contains no payment-protocol assumptions. Behaviour,
  audit events, metrics, and exceptions are byte-identical to v0.4.0.
- **Binding layer:** `bindings/x402.X402Binding` owns everything x402-specific
  (402 status, `X-PAYMENT` header, scheme `exact`, `accepts[]` parsing with the
  F-04/F1 hardening). New `PaymentProtocolBinding` protocol in `_types`;
  `HardenedX402Client(binding=...)` accepts a custom rail binding — the hedge
  against payment-rail fragmentation (Stripe ACP/Tempo, AP2).
- `PIIFilter.scan_fields(mapping)` — rail-agnostic generalisation of
  `scan_payment_fields` for bindings with different metadata field names.
- **Partner conformance suite:** `python -m presidio_x402.conformance` — 7
  end-to-end checks (API surface, pre-signing redaction, fail-closed PII block,
  policy block, replay + rollback, audit-chain integrity incl. tamper
  detection, binding parse hardening). No network; exit 0/1. Runs in CI on
  every push and intended for OEM partners' CI on every upgrade.
- **SEMVER.md** — public-API definition, pre-1.0 semver profile, behavioural
  security invariants that outrank API stability, partner pin guidance.
- Integration quickstarts: `docs/quickstarts/{coinbase-cdp,langchain,crewai}.md`.
- SBOM job (CycloneDX) in CI; conformance-suite step in the test matrix.

### Fixed
- `ComplianceReport` chain verification now resolves the chain key live from
  the `audit_log` module instead of a value snapshot taken at import. The
  snapshot silently desynced writer and verifier when the key changed after
  import (module reload), failing the chain check on untampered logs. Found by
  the new partner conformance suite running inside the full pytest matrix.

### Changed
- `gateway.py` is now a thin composition of `ScreeningPipeline` + the configured
  binding. All pre-v0.5.0 import paths keep working, including the grandfathered
  gateway aliases (`_parse_402_header`, `_HEADER_PAYMENT`, `_SUPPORTED_SCHEME`,
  `_amount_to_usd`) — kept until v1.0.0 per SEMVER.md.
- Roadmap re-slotted: the previously planned v0.5.0 scope (multi-tenant key
  scoping, enterprise audit sinks, SLSA L3, key-env startup gates) moves to
  v0.6.0; the SLO payment broker moves to v0.7.0. Rationale: OEM outreach (Q3)
  needs the embed kit first; see PRESIDIO-REQ.md.
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
