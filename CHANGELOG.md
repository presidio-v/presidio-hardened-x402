# Changelog

All notable changes to `presidio-hardened-x402` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **`PIIFilter` missed percent-encoded PII — a silent redaction bypass.**
  `_normalise` closed the Unicode evasion paths (NFKC, invisible codepoints,
  Cyrillic homoglyphs, hyphen folding) but did no percent-decoding, so
  `alice.martin%40example.com` — the ordinary way an address appears inside a URL
  path or query string — never reached the email pattern in a form it could
  match. `experiments/surface_form_probe.py` measured **0 of 6** encoded forms
  detected against v0.11.0 at the recommended configuration, with both unencoded
  controls detected; the address passed through unredacted into the payment
  payload. `resource_url` is by construction a URL and carries 45% of the entity
  labels in the evaluation corpus, so this was the most likely encoding for real
  x402 metadata to use.

  Matching now runs additionally against a **bounded percent-decode** of the
  input, with the resulting spans mapped back to the caller's own bytes. The
  decode is capped at two rounds (enough for double-encoded `%2540`; not
  "decode until stable", which would make the normaliser an amplification vector
  on hostile input), is skipped entirely when the input holds no well-formed
  escape, and passes malformed escapes through verbatim rather than raising —
  the filter is fail-closed on exceptions, so a decode error would block an
  otherwise legitimate payment. Decoding is used for **matching only**: the
  returned string is still the caller's, so benign escapes are not rewritten and
  URL semantics are preserved (`%2F` is not `/`). Both `regex` and `nlp` modes
  are covered, as is `scan_dict`. Re-running the probe now reports 6/6 detected
  and 0/6 surviving. No published evaluation number moves — the corpus contains
  zero `%` characters. See `plan/percent-decoding-redaction-bypass.md`.
- **MPA webhook response body was unbounded on the plain-httpx path**
  (CWE-400, audit finding F1 of 2026-07-19). `_MPA_RESPONSE_MAX_BYTES` was
  enforced while streaming inside `_post_pinned_https` but not on the
  `self._httpx.post()` branch, taken for an IP-literal webhook URL or with
  `dns_rebinding_protection` disabled; `resp.json()` then parsed an unbounded
  body. A hostile approver at such a URL could exhaust agent process memory. The
  cap is now applied on both branches before the response is verified or parsed.
  Reaching it requires operator-level misconfiguration *and* a hostile approver.

### Changed
- NLP-mode install instructions now name **`en_core_web_lg`**, not
  `en_core_web_sm`, in `README.md`, `docker/Dockerfile` (hash-pinned to the same
  wheel the deployed service uses), and the `ImportError` hint raised by
  `PIIFilter(mode="nlp")`. `en_core_web_lg` is what Presidio's default NLP engine
  loads and what the published evaluation used; the previous instructions
  produced an image in which `mode="nlp"` could not start.

## [0.11.0] — 2026-07-27

### Added
- **`CapabilityEnforcer` — `capability-grant@1` enforced on the payment path (E2 /
  CJ-EVAL Phase A+B).** A thin, **opt-in, default-off** `ScreeningPipeline` stage
  that makes each outgoing x402 payment prove it is authorised by a verified
  `presidio-hardened/capability-grant@1` chain **before** signing/transmission. It
  slots in between the trusted-wallet allowlist and the policy engine (`PII →
  trusted-wallet → capability → policy → replay → MPA`) — a pure predicate placed
  ahead of the stateful gates, so a block needs no compensating rollback. It
  **reuses** the released pieces rather than reimplementing them: `verify_chain` /
  `VerifiedGrantChain.check_payment` (per-call cap, endpoint prefix, validity
  window), `policy_config_from_chain`, and `decision_ref` for a block-time signed
  `payment-decision@1` DENY parent-linked to the chain's terminal `grant_hash`. Two
  modes: a *configured* pre-verified chain, or *per-call* verification of a
  presented chain. When unset, **no capability code runs and behaviour is
  byte-identical** to prior releases; no network I/O on any path. New
  `presidio_x402.capability_enforcer` module (`CapabilityEnforcer`, `StageTiming`),
  wired into `ScreeningPipeline` / `HardenedX402Client` via the additive
  `capability_enforcer=` parameter. `ScreeningPipeline.apply(stage_timings=…)`
  optionally reports the monotonic per-stage breakdown `redaction | capability
  verification | evidence write`. Measures the *released* grant@1 artifact
  end-to-end; ZK-tier numbers remain literature-cited (CJ-EVAL Phase C). See
  `plan/e2-capability-enforcer-design.md` and the harnesses under `experiments/`
  (`e2_replay.py`, `e2_chains.py`, `e2_violations.py` + `e2_violations.jsonl`).

## [0.10.1] — 2026-07-27

### Security
- **`DecisionRefEmitter` no longer leaks its signing key via `repr` (F1, CWE-312).**
  The Ed25519 private key in `signing_key` surfaced through the auto-generated
  dataclass `repr`, so debug logging of the emitter or any traceback holding it
  exposed key material. The field is now `field(repr=False)` — still required and
  readable by the signing path, but absent from `repr`/tracebacks/debug logs. A
  regression test asserts the key is not in `repr()`. (`asdict()` still emits the
  field — inherent to dataclasses; `repr` was the finding's exposure vector.)

## [0.10.0] — 2026-07-27

### Added
- **Treasury binding — `settlement-ref@1`, a signed off-chain join record.** A
  `payment-decision@1` record says *why* a payment was allowed but carries no
  transaction hash, so it cannot be reconciled against the settlement it
  authorized. The new artifact closes that gap: a signed `evidence-ref@1`
  envelope, under the same policy signer, committing to `{decision_ref, chain
  (CAIP-2), tx_hash, block_number, log_index}` and nothing else. It is
  deliberately **not** the on-chain anchor an earlier design sketched — an
  ERC-3009 settlement's calldata carries no decision digest, so a
  `calldata_digest` check would verify nothing, and a "decision precedes
  settlement" check compares the settlement's own block time with itself. The
  record asserts only what the signer can: *this decision, that transaction,
  signed*. The stronger pre-settlement on-chain commitment remains available as
  a future opt-in mode; it costs an extra chain transaction per payment.
- **`presidio_x402.treasury_binding` — fail-closed bundle export + offline
  verify, with a CLI.** `export` re-runs the *whole* decision-ref verification —
  signature included, which is why a trust store is a required argument rather
  than an optional one — and refuses to emit a bundle for an envelope that does
  not verify, a non-terminal `REFER` verdict, an out-of-bound caller identity
  string, out-of-domain settlement facts, or a join that would be signed by an
  identity other than the decision's own signer. `DENY` *is* exportable on
  purpose: a settlement that happened despite a DENY is the anomaly an auditor
  most needs to see. The bundle carries **no key material** — `trust_store_ref`
  names the signer and key id, and the verifier resolves both against its own
  pinned store, because a bundle-supplied public key would make verification
  trust-on-first-use and defeat the pin. The signing key is read from a file or
  `PRESIDIO_X402_EVIDENCE_KEY`, never from `argv`, which is world-readable in
  `ps` output. Exit 0 verified / 1 fail-closed with a distinct reason / 2 usage.
- **Client-side settlement-receipt capture (opt-in `settlement_writer=`).** The
  paid response's `PAYMENT-RESPONSE` / `X-PAYMENT-RESPONSE` /
  `X-PAYMENT-RECEIPT` echo is parsed into rail-agnostic settlement facts and
  correlated with that payment's `decision_ref`. Documented honestly: **the echo
  carries the transaction hash and the network, not a block number and not a log
  index**, so those come back `null`, the record is flagged `"complete": false`,
  and completing them from a chain or indexer lookup is an operator step. They
  are required rather than optional because without a log index there is no key
  on which a ledger can enforce one-settlement-one-leg. Capture is strictly
  observational — it runs after the paid response is in hand, performs no
  network I/O, and cannot change a payment outcome. The `decision_ref` is
  captured through a request-local closure, never client state, so concurrent
  requests through one client cannot correlate a receipt with each other's
  decision.
- **Caller-identity value bounds on the export and verify paths.** `agent_id`,
  `actor.payment_signer`, `pay_to`, `resource_origin` and `mpa.approval_refs`
  are caller-supplied strings, and a wallet address is pseudonymous personal
  data to a GDPR-minded auditor. They are bounded by length and charset (no
  control, format, surrogate, private-use or unassigned code point — a charset
  bound, not an ASCII allowlist, so an international agent id stays legal). The
  bound is re-applied on read, so a bundle from a laxer producer still fails.
  This replaces the overclaim that the record is PII-free: only the `controls{}`
  block is structurally PII-free.
- **Bundle summary fields are cross-checked against the envelopes.** The
  top-level `decision_ref`, `settlement_ref`, `settlement_key` and `verdict` are
  a mirror of what the envelopes prove; verification never reads them and
  re-derives everything. But a consumer enforcing "one settlement, one leg" reads
  `settlement_key`, so a mirror that can disagree with what it mirrors is a trap
  — swapping in a settlement-ref for another transaction leaves a stale key
  naming the old one. A disagreement is now a distinct fail-closed reason
  (`summary_mismatch`), not a warning.
- **Cross-language conformance vectors** under
  `tests/conformance/treasury-binding/`, with `PROVENANCE.json` and a
  deterministic generator. They are the *normative* contract between this
  repository's Python canonicaliser and the sibling Rust one — x402 is Python,
  the ledger is Rust, and nothing is imported across that boundary, so the
  contract is the bytes. Covers the axes that can actually diverge: non-ASCII
  escaping (emoji, combining marks, U+007F, C0 controls), non-ASCII key ordering
  (equal by construction — pinned so a toolchain change cannot break it
  silently), lone surrogates, non-string object keys, integers past `i64::MAX`,
  floats, and the depth boundary at 128/129 with the depth definition pinned
  alongside it. Plus the two family negatives as complete signed envelopes: both
  verify cryptographically and both must still be rejected.

### Changed
- **`mica.canonical_bytes` now fails closed across its whole input domain.** A
  string carrying an unpaired surrogate raised a bare `UnicodeEncodeError` from
  the UTF-8 encode step — an interpreter accident escaping a boundary whose
  callers catch `EvidenceError` — and now raises `EvidenceError`. Non-string
  object keys are also rejected: `json.dumps` sorts integer keys *numerically*
  and only then stringifies them (`1, 2, 10`), while every sibling canonicaliser
  sorts the strings (`"1", "10", "2"`), which is a silent cross-language hash
  divergence. Neither change affects any valid input, so no emitted bytes move;
  the float guard and the key guard now share one walk instead of two.
- `ScreeningPipeline.apply()` accepts an optional `on_decision_ref` callback
  (additive keyword) so a caller can correlate the emitted decision-ref with a
  settlement observed later, without the pipeline holding per-payment state that
  concurrent calls would race on.
- `PaymentProtocolBinding` gains an *optional*, duck-typed
  `settlement_receipt(headers)` method. The gateway probes for it with `getattr`
  and skips capture when absent, so third-party bindings keep working unchanged.

### Fixed
- **Replay-fingerprint collision on high-precision amounts.** `_canonical_amount`
  stripped trailing zeros with `Decimal.normalize()`, a *context* operation bounded
  by the default 28-significant-digit precision. Any amount longer than that was
  silently rounded, so distinct amounts differing only past the 28th significant
  digit canonicalised to the same string and produced the same replay fingerprint —
  e.g. `…5555555` and `…5555556` (31 digits) both became
  `5555555555555555555555555556000`. Across 5000 distinct 31-digit amounts, 4994
  collided. `amount` originates in the server's 402 response and is therefore
  attacker-influenced. Impact is fail-closed (a distinct payment could be rejected as
  a duplicate) rather than a bypass. Canonicalisation is now context-free and exact.
  **Amounts of 28 or fewer significant digits are unaffected — verified byte-identical
  across 20 000 randomised inputs, so existing fingerprints do not change.** Found by
  the Atheris `_canonical_amount` harness.

### Added
- **Coverage-guided fuzzing of the canonicalisation and digest layer (Atheris).**
  Four property harnesses under `fuzz/`, exercised in CI on every push and pull
  request, time-boxed per harness. They assert the byte-determinism contracts the
  evidence layer rests on rather than merely reaching for coverage:
  `canonical_bytes` (determinism, JSON round-trip, type-aware injectivity, NFC/NFD
  non-collapse, float fail-closed via `EvidenceError`), `compute_fingerprint` and
  `_canonical_amount` (replay-guard canonicalisation), `compute_decision_ref`, and
  `compute_action_ref`. Fuzzing dependencies live in a separate `fuzz` extra —
  `pip install -e ".[fuzz]"` — and are not pulled in by `dev`. Atheris 3.x ships no
  cp310 wheel, so the fuzz job pins Python 3.12; the 3.10–3.13 test matrix is
  unchanged. Ruff now also lints `fuzz/`.

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
