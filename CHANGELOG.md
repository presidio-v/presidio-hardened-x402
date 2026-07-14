# Changelog

All notable changes to `presidio-hardened-x402` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.1] — 2026-07-14

### Security
- **Dependency audit remediation.** Added explicit minimum-safe floors for
  `click>=8.3.3` (PYSEC-2026-2132) and `setuptools>=83.0.0`
  (PYSEC-2026-3447), and refreshed `uv.lock` so the release-extra
  `pip-audit` gate resolves a clean graph.
- **Log exposure hardening.** The missing `X-PAYMENT` header warning no longer
  includes the request URL, avoiding accidental clear-text logging of
  PII-bearing paths or query strings. Regression coverage asserts that
  email/token-shaped URL material is omitted.

### Changed
- Updated the pinned `astral-sh/setup-uv` GitHub Action from v8.3.0 to v8.3.2.

## [0.9.0] — 2026-07-05

### Added
- **Capability certificates (`presidio-hardened/capability-grant@1`).** A
  signed, offline-verifiable, attenuable spending grant format for turning
  operator policy into a portable capability chain. Grants use the family
  canonical JSON profile, detached Ed25519 signatures, SHA-256 content
  addressing, float-free amount encoding, monotone caveat attenuation, strict
  expiry, and a `PolicyConfig` bridge for admitted chains.
- **Decision-ref emission (`presidio-hardened-x402/payment-decision@1`).** A signed,
  portable, offline-verifiable record of one payment decision — the per-control gate
  verdicts (`pii → trusted_wallet → policy → replay → mpa`), hashed inputs, and the
  effective policy hash bound into the family `evidence-ref@1` envelope, with a thin,
  recomputable `decision_ref` correlation id (Pillar II of the Computational
  Jurisprudence program). New `presidio_x402.decision_ref` module: `DecisionRefEmitter`,
  `build_payment_decision_content`, `build_decision_evidence`, `compute_decision_ref`,
  `verify_decision_ref`, `f_controls`, `ControlResults`, file/null writers, and an
  offline CLI verifier (`python -m presidio_x402.decision_ref`). Emission is **opt-in
  via `HardenedX402Client(decision_ref_emitter=...)` and off by default** — behaviour is
  byte-identical to prior releases when unset, and there is no network I/O on the emit
  path. The verifier fails closed with distinct reasons (hash mismatch, non-recomputable
  verdict, self-approval `signer_equals_runtime`, unknown signer, bad signature, broken
  parent linkage) and, when the policy came from a `capability-grant@1` chain, checks
  provenance linkage to the chain's terminal `grant_hash`. PII-freedom is structural: the
  record carries only hashes and entity-type labels, never a raw metadata string; the
  `offer_hash` is the SHA-256 digest of the raw 402 offer bytes as received and is omitted
  with `offer_hash_absent: "not-retained"` when those bytes are unavailable. Wire format
  pinned by `tests/conformance/decision-ref/` and
  `plan/presidio-evidence-decision-ref-design.md`.

## [0.8.1] — 2026-06-29

### Fixed
- **`pii_filter.py` — PHONE span boundary.** The structural phone pattern's
  leading `\b` with an optional `\(?` truncated parenthesized / `+1` numbers
  (`(415) 555-0182` matched as `415) 555-0182`), leaving the leading `(`
  un-redacted and mis-aligning the redaction span. The area code is now matched
  as a whole unit (`(NNN)` or `NNN` + separator) with digit lookarounds. Full
  forms are captured; no change to credit-card / SSN matching.

## [0.8.0] — 2026-06-29

PII-completeness, byte-determinism, and supply-chain hardening (library). The
headline change: NLP mode is now a structural **superset** of regex, so the
high-accuracy engine can no longer silently miss the structured identifiers
(SSN, phone, credit card, …) that the zero-setup regex engine already caught.

### Added
- **`screen_ref` leg** for composed-envelope screening pointers — a signed,
  PII-free screening verdict block that other parties can canonicalize and
  countersign alongside their own evidence refs.

### Changed
- **`pii_filter.py` — NLP mode is a superset of regex.** `mode="nlp"` now
  registers the structural pattern recognizers (`US_SSN`, `PHONE_NUMBER`,
  `CREDIT_CARD`, `EMAIL_ADDRESS`, `IBAN`, `IP_ADDRESS`) on top of the spaCy NER
  pipeline, so it detects every entity regex mode does *plus* the NER entities.
  Previously a bare `AnalyzerEngine` scored some structured identifiers below
  threshold and let them through. The default zero-setup `mode="regex"` is
  unchanged; `mode="nlp"` still requires the spaCy model extra.

### Security
- **`action_ref.py`** rejects empty entity-type sets and NFC-normalizes its
  fields before hashing, closing two byte-determinism gaps so the same action
  always yields the same `action_ref` (audit F1/F2).
- **Log hygiene:** the missing-payment-header warning redacts the resource URL
  before logging, so a PII-bearing URL cannot reach a log sink.
- **Supply chain:** weekly OpenSSF Scorecard workflow + README badge; Scorecard
  Token-Permissions / SAST / Signed-Releases / Branch-Protection remediations;
  SLSA Build L3 provenance documented.
- **Independent multi-round security audit** of the v0.8.0 release cycle —
  library scope cleared (PII recognizer completeness, `action_ref` determinism,
  log hygiene, supply chain) with no Critical/High/Medium findings; see
  [`SECURITY-AUDIT-2026-06-29-v0.8.0.md`](SECURITY-AUDIT-2026-06-29-v0.8.0.md).

## [0.7.0] — 2026-06-21

Market-based SLO enforcement (library). The agent becomes an economic actor that
pays for capacity upgrades when infrastructure degrades — but only on a
cryptographically **verified** degradation signal. The empirical evaluation,
cs.DC preprint, and a real/mock capacity provider are tracked separately on the
publication track and are not part of this library release.

### Added
- **`slo_broker.py`** — `SLOPaymentBroker`: wraps `HardenedX402Client`; on a
  verified `SLOTrigger` applies cooldown + tier escalation + per-event/daily caps,
  buys capacity via a pluggable `CapacityProvider` (default `X402CapacityProvider`),
  and emits `SLO_PAYMENT_TRIGGERED` / `SLO_PAYMENT_BLOCKED` audit events. Decisions
  are serialized (`asyncio.Lock`) so concurrent triggers cannot both pass cooldown.
- **`slo_policy.py`** — `SLOPaymentPolicy(PolicyConfig)`: `latency_threshold_ms`,
  `max_per_slo_event_usd`, `cooldown_seconds`, `max_daily_slo_usd`,
  `tier_escalation_rules`. As a `PolicyConfig` subclass, SLO spend also counts
  against the ordinary budgets (shared ledger).
- **`arch_translucency_adapter.py`** — `ArchTranslucencyAdapter` + `SLOTrigger`:
  fail-closed gate that accepts a degradation signal only when content↔hash and
  signature↔trusted-signer both verify (`mica.verify_ref`), with an optional signer
  allow-list and an overridable `field_map`.
- **Provisioning PII entities** — opt-in `WORKLOAD_CLASS`, `DATA_CLASSIFICATION`,
  `QUERY_PATTERN` (`PROVISIONING_ENTITIES`) redact workload context before it reaches
  a third-party compute provider. Default PII behaviour is unchanged.

### Security
- **T-SLO-1 (spending drain):** the SLO trigger is an *authorization, not a metric* —
  a spoofed or misconfigured degradation signal cannot trigger a payment because it
  carries no valid signature. Cooldown + caps are defence-in-depth.
- **T-SLO-2 (workload-metadata leakage):** provisioning PII entities (above).
- **T-SLO-3 (vendor lock-in):** pluggable `CapacityProvider` registry.
- **Third-party audit remediation:** production-tree conformance checks no longer use
  bare `assert`, CI now runs `pip-audit` across release extras, and the v0.7.0 audit
  remediation record is included in the source tree.

### Notes
- Validated end-to-end against the real `presidio-hardened-arch-translucency`
  evidence producer + signing-bridge sidecar (degrade → sign → verify → pay; wrong
  key rejected). The public wire contract remains pinned by the vendored
  `evidence-ref@1` vectors and the v0.7.0 audit remediation record.

## [0.6.0] — 2026-06-21

The production-hardening and evidence-substrate release. v0.6.0 closes the
v0.6.0 hardening payload, records human-pentest retest closure with no open
Critical/High/Medium findings, and keeps prompt-injection / agent-bound response
scanning issue #23 deferred outside this release.

### Added
- **Enterprise remote audit sinks** (`audit_sinks.py`): `S3AuditWriter`,
  `SplunkAuditWriter`, `DatadogAuditWriter`, and `MultiAuditWriter` provide
  bounded, fail-safe fan-out to object storage and SIEM/log-intake targets. The
  Splunk sink requires HTTPS HEC URLs; the Datadog sink validates the `site`
  hostname component.
- **OpenTelemetry spans** for security-control activations. The optional `[otel]`
  extra adds `opentelemetry-api`; absent the extra, span creation is a no-op.
- **Policy hot-reload**: `PolicyEngine.update_config()` and
  `HardenedX402Client.update_policy()` allow thread-safe runtime policy swaps
  without reconstructing the client.
- **Per-tenant replay namespaces** in `ReplayGuard`, preserving replay isolation
  for multi-tenant deployments that share Redis.
- **Hard startup gates** for production key material:
  `PRESIDIO_X402_REQUIRE_CHAIN_KEY=1` and
  `PRESIDIO_X402_REQUIRE_FINGERPRINT_KEY=1` hard-fail when stable keys are absent.
- **Latency SLO CI gate**: regex PII p99 is benchmarked and fails CI above the
  50 ms budget.
- **All-matrix coverage upload**: Codecov now receives coverage for each Python
  matrix leg instead of Python 3.12 only. This closes GitHub issue #49 when the
  v0.6.0 branch merges.
- **SLSA/OIDC release hardening**: the publish workflow uses PyPI Trusted
  Publishing, generates a CycloneDX SBOM, attaches release assets only after
  successful PyPI publish, and creates build provenance attestations.
- **Docker supply-chain pinning**: `tools/docker/Dockerfile` digest-pins the
  Python base image and installs the spaCy model from a hash-pinned wheel.
- **Human pentest spec and retest evidence** are recorded in the internal
  security-audit artifacts. Both Medium findings from the pentest protocol were
  remediated and retested.
- **Action reference primitive**: `compute_action_ref()` and
  `format_action_ref_timestamp()` expose deterministic action-ref derivation for
  pre-execution decision trails.
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
  `[evidence]` (cryptography>=48.0.1); HMAC mode needs no extra. Public API:
  `build_evidence`, `Obligation`, `OBLIGATION_MAP`, `EvidenceError`.
- **Evidence read path**: `verify_ref`, `verify_ed25519`, `verify_hmac`,
  `load_trust_store`, and `parse_document` verify the vendored
  `evidence-ref@1` vectors fail-closed with trust-store rotation support.

### Changed
- Amount parsing and policy ledgers now use `Decimal` internally to avoid float
  drift around spending-policy boundaries.
- The CrewAI optional extra remains intentionally empty until CrewAI's unresolved
  `chromadb` CVE has a fixed version; the adapter stays importable for
  integrators who install and audit CrewAI separately.

### Fixed
- Hosted screening client 200 responses are now validated for top-level object
  shape, bounded string redacted fields, bounded string entity types, and bounded
  entity counts.
- `verify_ref()` now returns `False` instead of raising for malformed raw trust
  entries, matching the documented fail-closed boolean contract.
- Regex-mode credit-card redaction now catches common dashed, spaced, and
  Unicode-hyphen-normalized card numbers in `resource_url`, `description`, and
  `reason`.

### Security
- Added explicit minimum-safe dependency floors for `urllib3>=2.7.0`,
  `cryptography>=48.0.1`, and `idna>=3.15`; project-scoped and all-extras
  dependency audits report no known vulnerabilities.
- Release workflow actions are pinned to immutable commit SHAs.
- Issue #23 (third-party prompt/content injection into agent-bound envelopes) is
  explicitly deferred and remains open; it is not a v0.6.0 release blocker.

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
