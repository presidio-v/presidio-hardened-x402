# PRESIDIO-REQ — presidio-hardened-x402

Requirements, feature deliberation, and versioning rationale for the x402 security middleware.

---

## v0.1.0 Requirements (MVP)

### Mandatory Security Extensions

1. **PII detection and redaction**: Presidio-based scanning of all x402 payment metadata
   fields (resource URL, resource description, payment reason) before payment submission.
   Supports `regex` mode (zero-setup, structural PII: emails, SSNs, credit cards, phone
   numbers) and `nlp` mode (full spaCy NER: PERSON, ORG, location, etc.).

2. **Spending policy enforcement**: Per-agent, per-endpoint, and per-time-window budget
   limits enforced before payment execution. Configurable via dict or TOML. Raises
   `PolicyViolationError` on breach.

3. **Replay/duplicate payment detection**: HMAC-SHA256 fingerprint of canonical payment
   fields (resource URL + payTo address + amount + currency + deadline). In-memory TTL
   store (default) and Redis-backed store (production). Raises `ReplayDetectedError` on
   duplicate.

4. **Structured audit logging**: JSON-L audit events emitted for every payment attempt
   (including blocked ones). Each entry includes: timestamp, event type, resource URL
   (post-redaction), amount, agent ID, outcome, and HMAC of previous entry for tamper
   evidence.

5. **Pluggable payment signing**: `PaymentSigner` protocol — callers provide their own
   signing implementation. No hard dependency on any specific wallet SDK.

6. **On-startup dependency audit**: Version checks for known-vulnerable dependencies;
   logs warnings for outdated `httpx`, `presidio-analyzer`, etc.

7. **Security event logging**: Structured log output for every security control activation
   (PII found, policy breach, replay detected).

### Scoping Decisions (Deferred to v0.2.0+)

- **Endpoint reputation scoring** (WS-4): Requires a labeled dataset of malicious 402
  endpoints that does not exist at v0.1.0 scale. Deferred to v0.2.0.
  *Rationale: Including an untrained reputation model would produce high false-positive
  rates and damage trust in the package.*

- **LangChain/CrewAI adapters**: Framework-specific glue; not required for the core
  security value proposition. Deferred to v0.2.0.
  *Rationale: The base HardenedX402Client is usable from any async context; adapters
  are a convenience layer.*

- **Multi-party authorization (MPA)**: Requires cryptographic engineering (threshold
  signatures or webhook approval workflows). Deferred to v0.3.0.
  *Rationale: MPA adds significant complexity; the policy engine's per-call limits
  address the most common enterprise governance need in v0.1.0.*

- **Helm chart / Docker sidecar**: Deployment tooling without core functionality.
  Deferred to v0.3.0.

- **EVM/SVM signing implementations**: The `PaymentSigner` protocol is provided;
  reference implementations using `eth-account` (EVM) and `solders` (SVM) are
  provided as usage examples in the README, not as package dependencies.
  *Rationale: Wallet SDK dependencies create supply chain risk; pluggable design is
  safer and more flexible.*

---

## v0.2.0 Requirements (Extended Validation)

### Corpus and experimental infrastructure

- **Synthetic corpus** (`tools/corpus/`): 2,000 labeled x402 metadata samples spanning
  7 use-case categories (AI inference, data access, medical/health, compute-as-a-service,
  media, financial, generic API). ~40% PII-positive. Ground-truth entity labels in JSONL.
  See `explore/feasibility.md` for full corpus design.

- **Precision/recall sweep** (`tools/experiments/run_sweep.py`): Grid search over
  `pii_mode` × `pii_entities` × `min_score` × `metadata_field`. Outputs CSV + Markdown
  results table. Primary metrics: Precision, Recall, F1.

- **Latency benchmark** (`tools/experiments/run_latency.py`): 1,000-call loopback
  benchmark. Reports p50/p95/p99 per mode. Validates 50ms p99 target for regex mode.

### Scoping decision: synthetic corpus first, live data for conference paper

The preprint is based exclusively on the synthetic corpus. This is intentional:
- Ground truth is known by construction → enables precision/recall measurement
- Fully reproducible and deterministic (fixed seed)
- No external data access required
- Live Base L2 data (Dune Analytics) deferred to v0.2.1 / conference paper

*Rationale: A synthetic-corpus-first approach is standard practice in security systems
papers when (a) ground truth is required for precision/recall measurement and (b) the
live data source requires non-trivial access setup. The claim we are making — "the
middleware correctly detects PII in x402-like metadata" — is testable on synthetic data.
The claim "PII is present in production x402 metadata" requires live data and is
explicitly deferred.*

### New code features

- Endpoint reputation scorer (`reputation.py`) with VirusTotal/SafeBrowsing adapters
  and heuristic signals (price drift, metadata entropy, domain age)
- LangChain adapter (`adapters/langchain.py`): `HardenedX402Tool` as a LangChain `BaseTool`
- CrewAI adapter (`adapters/crewai.py`): same pattern for CrewAI
- Compliance report generator (`compliance_report.py`): SOC2-friendly, HMAC-chained
  JSON-L with GDPR data-subject reference support

### Publication

- arXiv cs.CR preprint — **delivered**: [arXiv:2604.11430](https://arxiv.org/abs/2604.11430)
- Conference paper submission (USENIX Security 2027 or IEEE S&P 2027) after live
  data replication in v0.2.1

---

## v0.2.1 Requirements (Live Data Replication) — Delivered

### Dune Analytics query set (`dune/`)

Six Trino SQL queries characterising the deployed x402 ecosystem:

- `query0_facilitator_list.sql` — enumerate facilitator wallets by project and chain
- `query2_volume_by_chain_project.sql` — cross-chain transaction volume and date ranges
- `query2a_volume_base.sql` — Base L2 volume (chain-specific table; fast)
- `query2b_volume_polygon.sql` — Polygon volume (chain-specific table; fast)
- `query2c_volume_other_chains.sql` — remaining 9 chains via `evms.transactions`
- `query3_resolve_unknowns.sql` — resolve unrecognised wallet addresses to project names

### Ecosystem findings (as of Q1 2026)

- 20 projects, 96 facilitator wallets, 11 chains, ≥79 million transactions
- Three structural PII-embedding patterns identified in live endpoints (P1–P3)
- Controlled demonstration confirms recommended configuration intercepts all observed
  entity types with no configuration change

### Scoping decision: synthetic corpus for precision/recall; live data for structural validation

The precision/recall sweep (v0.2.0) uses only the synthetic corpus — ground truth is
required for F1 measurement and live data cannot provide it without multi-week labelling
effort. The live data study confirms that the entity types and structural patterns
modelled synthetically appear in deployed endpoints. The two datasets are not
independent; the live data result is confirmatory rather than a blind validation.

*Rationale: This is the standard design for security systems papers — validate the tool
on controlled data with known ground truth, then confirm the threat model on live data.*

### Publications

- **IEEE Security & Privacy magazine** — practitioner article (~5 pages) centred on the
  live ecosystem findings; submitted 2026-04-04 (SPSI Nov/Dec 2026 special issue:
  Autonomous AI Agents in Computer Security)
- **IEEE Transactions on Information Forensics and Security (TIFS)** — full transactions
  paper (~14 pages IEEEtran) including system design, corpus, 42-configuration sweep,
  and live data study; under review

---

## v0.3.0 Requirements (Mature Enterprise) — Delivered

### Multi-party authorization (`mpa.py`)

- **`MPAConfig`**: threshold (n-of-m), per-approver configs, min_amount_usd, timeout
- **`MPAApproverConfig`**: approver_id, mode (`webhook` | `crypto`), webhook_url, shared_secret
- **`MPAEngine.request_approval(details, amount_usd, provided_signatures)`**:
  - Crypto mode: verifies HMAC-SHA256 countersignatures against configured shared secrets
  - Webhook mode: parallel HTTP POSTs to approver endpoints; collects JSON `{"approved": bool}` responses
  - Payments below `min_amount_usd` are exempt from MPA (performance critical path)
  - Raises `MPADeniedError` (< threshold approvals) or `MPATimeoutError` (webhook timeout)
- **Gateway integration**: `HardenedX402Client(mpa_engine=...)` — MPA runs after replay guard,
  before signing. Crypto signatures passed via `mpa_signatures` kwarg.

### Policy-as-code JSON Schema (`x402-policy-schema.json`)

- JSON Schema Draft 2020-12 covering all `PolicyConfig` fields plus `mpa` section
- `x402_policy_schema.py`: `validate_policy(dict)` + `load_policy_file(path)` (TOML + JSON)
- `PolicyValidationError` with per-field error list for clear developer feedback
- Marked as IETF draft candidate in schema `$id`

### Prometheus metrics exporter (`metrics.py`)

- `MetricsCollector` with counters: `payments_total`, `pii_detections_total`,
  `policy_violations_total`, `replay_detections_total`, `mpa_events_total`
- Histogram: `payment_amount_usd` (10 buckets, $0.001–$50)
- Graceful no-op stub when `prometheus-client` not installed
- `HardenedX402Client(metrics_collector=...)` integration
- New optional extra: `pip install presidio-hardened-x402[prometheus]`

### Kubernetes sidecar

- `docker/Dockerfile`: multi-stage, non-root user (UID 1001), health check
- `docker/sidecar_app.py`: FastAPI app with `/health`, `/metrics`, `/version`
- Helm chart (`helm/`): `Chart.yaml`, `values.yaml`, deployment + service + ServiceMonitor
- Image tag: `ghcr.io/presidio-v/presidio-hardened-x402:0.3.0`

### SOC2 compliance reference architecture

- `docs/soc2-reference-architecture.md`: SOC 2 TSC mapping, three deployment patterns,
  audit log retention, GDPR obligations, secret management guidance, evidence collection table

### Anchor project within PRESIDIO SDLC — delivered

- `presidio-hardened-x402` serves as the canonical reference implementation for the
  PRESIDIO SDLC: the `sdlc/` documentation set (14 docs + 6 ADRs + JSON inventory)
  lives in the outer repo and is kept aligned with the codebase via the
  data-inventory drift test that blocks PR merge.

### New exceptions

- `MPADeniedError(approvals_received, threshold)` — n-of-m requirement not met
- `MPATimeoutError(approvals_received, threshold)` — webhook timeout

### New optional extras

- `[prometheus]`: `prometheus-client>=0.20.0`
- `[schema]`: `jsonschema>=4.21.0`

---

## v0.4.0 Requirements (Screening API Launch) — Delivered

**Re-scoped from the original "production hardening 2027" plan per
[ADR-0006](../sdlc/adr/0006-v040-scope-redefinition.md).** v0.4.0 now pairs the
library release with the hosted `screen.presidio-group.eu` screening service
that acts as its authoritative remote backend. The 2027-hardening umbrella is
redistributed across v0.5.0+; production-hardening items now land in v0.6.0
(see below).

### Hosted screening service

- **`screen.presidio-group.eu`** — FastAPI service behind nginx on an OVHcloud
  VPS (deploy 2026-04-20: SSH key-only, UFW, fail2ban, unattended-upgrades,
  Let's Encrypt ECDSA cert with certbot.timer auto-renewal). Free tier only:
  regex mode, 100 screenings/day/key, no audit token. Paid tiers gated on real
  usage data and deferred to v0.4.1+.
- Baseline load test (`run/load-tests/health-baseline.js`, 2026-04-20):
  100 req/s × 5 min on `GET /health` → 29,989 requests, 100.00% 2xx,
  p95 33 ms, p99 92 ms, 0 failures.

### Client-side integration

- **`screening_client.py`** — `ScreeningClient`: httpx-injectable client that
  posts metadata fields to the screening service and consumes the structured
  PII analysis response.
- **Gateway integration**: `HardenedX402Client(remote_screening=True, screening_api_key=...)`
  routes PII analysis to the hosted service instead of the in-process PIIFilter;
  falls back to local regex/NLP modes when the network is unhealthy.

### New library-side controls

- **Per-origin `pay_to` allowlist** (`gateway.py:495-512`): defence against
  DNS-poisoning attacks that substitute the recipient wallet in a 402 response.
  Configured via `HardenedX402Client(trusted_wallets={origin: {pay_to, ...}})`.
  Adversary-attack chain-06 mitigation.
- **Replay fingerprint case-canonicalisation** (F1, audit 2026-05-17):
  `compute_fingerprint` now lowercases `pay_to` and uppercases `currency`
  before HMAC, so a server cannot bypass replay detection by toggling case
  across retries.
- **`PRESIDIO_X402_CHAIN_KEY` startup ERROR log** (F2, audit 2026-05-17):
  matches the existing `PRESIDIO_X402_FINGERPRINT_KEY` pattern; silent
  fallback to a per-process key is no longer observable-free.
- **`X-PAYMENT` length cap** (F3, audit 2026-05-17): 64 KiB hard cap before
  `json.loads` to bound client-side DoS exposure from hostile 402 servers.

### Audit cycle closures rolled up into 0.4.0

- 2026-05-03: F-A (PII `scan_dict` covers `extra` dict), F-B (MPA webhook
  outbound HMAC).
- 2026-05-10: F-C (Bandit `--exit-zero` removed → MEDIUM+ findings now block
  CI), F-D (replay fingerprint JSON-array canonical form replaces pipe-joined
  string), F-E (replay-detected event promoted from WARNING to ERROR with
  structured `extra` for SIEM).
- 2026-05-17: F1, F2, F3 (listed above).

### Adversary-chain disposition

All 8 chains in `adversary-attack/` dispositioned per the closure table in the
parent repo's `adversary-attack/README.md`: CLOSED or MITIGATED as of the
v0.6.0 release-readiness pass. The original v0.4.0 state was 3 CLOSED (04 Unicode evasion,
05 exception exfiltration, 07 MPA SSRF), 3 MITIGATED-config (02 replay,
03 audit OOM, 06 wallet hijack — operator must set
`PRESIDIO_X402_FINGERPRINT_KEY` + `PRESIDIO_X402_CHAIN_KEY` and populate the
wallet allowlist at deploy), 2 PARTIAL (01 spaCy model not yet wheel-pinned,
08 tools/ sidecar Dockerfile not digest-pinned — residual scope deferred to
v0.6.0). v0.6.0 closes the Docker/model residuals with digest/hash pinning.
No CRITICAL/HIGH chain remains OPEN with zero in-tree control.

### Out of v0.4.0 (moved to later milestones per ADR-0006)

- Third-party external security audit → **DONE 2026-06-06**: external second-set-of-eyes
  review performed by Grok 4.3 (xAI) across the published `tools/` package and research
  tree (report in `presidio-third-party-audits/`). No Critical/High; advisory-only
  family-lens findings. Mitigates RSK-019. The commissioned human penetration
  test completed on 2026-06-21; both Medium findings were remediated and
  retested before the v0.6.0 release-readiness pass.
- Multi-tenant key scoping + remote audit sinks (S3 / Splunk / Datadog) → v0.6.0
- Email-hash per-install salt → v0.6.0 (closes RSK-002)
- `/v1/revoke` endpoint → v0.4.1
- Prometheus `/metrics` on the hosted service → v0.4.1
- SLSA L3 hardened build worker → v0.6.0
- Hard startup-gates for `PRESIDIO_X402_*_KEY` env vars → v0.6.0
- Policy hot-reload, OpenTelemetry span export, performance regression CI →
  v0.6.0

---

## v0.5.0 Requirements (OEM Embed Kit + Binding Layer) — Delivered

Re-slotted 2026-06-12 (session-3 T1+T2, founder-selected scope): OEM outreach in
Q3 needs the embed kit before the multi-tenant platform work, and the patent
posture wants the screening core demonstrably rail-agnostic (claims cover the
method, not the rail — the binding layer is the hedge against protocol
fragmentation: Stripe ACP/Tempo, AP2). The previous v0.5.0 scope moves to
v0.6.0 unchanged; the SLO payment broker moves to v0.7.0.

- Rail-agnostic screening core: `core.ScreeningPipeline` extracted verbatim from
  the gateway (audit events, metrics, exceptions, rollback semantics
  byte-identical; existing 326-test suite is the conformance proof) — Delivered
- Binding layer: `bindings/x402.X402Binding` owns the 402 status, `X-PAYMENT`
  header, scheme, and offer parsing (F-04/F1 hardening preserved);
  `PaymentProtocolBinding` protocol; `HardenedX402Client(binding=...)`; proven
  by an end-to-end fake-rail test (HTTP 419 + `X-FAKEPAY`, full pipeline
  guarantees intact) — Delivered
- Back-compat: every pre-0.5.0 import path works; grandfathered gateway aliases
  kept until v1.0.0 (SEMVER.md) — Delivered
- `PIIFilter.scan_fields(mapping)` for rails with different metadata fields — Delivered
- Partner conformance suite `python -m presidio_x402.conformance` (7 end-to-end
  checks, no network, exit 0/1), wired into CI — Delivered
- SEMVER.md: public-API definition, pre-1.0 semver profile, behavioural security
  invariants, partner pin guidance (`>=0.5,<0.6`) — Delivered
- Quickstarts: Coinbase CDP, LangChain, CrewAI (`docs/quickstarts/`) — Delivered
- SBOM (CycloneDX) job in CI — Delivered
- Includes the previously-unreleased MPA freshness binding (F-8) and sink-level
  log redaction (family audit R2) — see CHANGELOG 0.5.0

---

## v0.6.0 Requirements (Multi-Tenant + Audit Sink + SLSA L3) — Delivered

Converts the single-tenant v0.4.0 screening service into a production platform.
Largely the "production hardening" scope previously carried under v0.4.0, plus
the multi-tenant work required to take paid tiers live. (Re-slotted from v0.5.0
on 2026-06-12; content unchanged.)

Status: release-ready on branch `v0.6.0` as of 2026-06-21. Public issue #23
(third-party prompt/content injection into agent-bound envelopes) is explicitly
deferred and remains open outside the v0.6.0 release scope.

- [x] Multi-tenant key scoping with per-tenant Redis namespace
- [x] Remote audit sink interfaces: `S3AuditWriter`, `SplunkAuditWriter`,
  `DatadogAuditWriter` (enterprise tier)
- [x] Per-install salt for `email:<sha256>` audit prefix (closes RSK-002)
- [x] Commissioned human penetration test before paid tiers (closes RSK-019 residual;
  the 2026-06-06 AI-based external review already mitigated the "no second set of
  eyes" risk); both Medium retest items resolved
- [x] SLSA L3 hardened build worker + provenance attestation; digest-pinned base
  image for `tools/docker/` and pinned spaCy model wheel (closes chain-01 and
  chain-08 residuals)
- [x] Performance regression test suite: p99 < 50ms latency SLO enforced in CI
- [x] Policy hot-reload: update `PolicyConfig` at runtime without client restart
- [x] OpenTelemetry span export for every security control activation
- [x] Hard startup-gates: `PRESIDIO_X402_REQUIRE_FINGERPRINT_KEY=1` and
  `PRESIDIO_X402_REQUIRE_CHAIN_KEY=1` opt-ins that hard-fail import when the
  corresponding env var is unset

---

## v0.7.0 Requirements (SLO Payment Broker) — **library core delivered 2026-06-21**

This version fills a second white spot: **market-based SLO enforcement**. Current
autoscaling is reactive and rule-based. This milestone makes the agent an economic actor
that bids for the infrastructure quality it needs — paying only when it needs it — via
x402 micropayments.

### Integration target

`presidio-hardened-arch-translucency` provides the SLO observability signal (latency
percentiles, quality metrics) as **Ed25519-signed `evidence-ref@1` envelopes** (the same
substrate x402 verifies via `mica`). `presidio-hardened-x402` acts as the SLO payment
broker: it receives degradation events, **verifies the signed trigger fail-closed**, applies
`SLOPaymentPolicy`, and triggers x402 payments for capacity upgrades — all with the same
PII redaction and spending governance built in v0.1.0.

**Design upgrade — authorization, not metric.** The broker moves money, so a degradation
signal is treated as an *authorization* and must be a signed evidence-ref from a trusted
arch-translucency signer, verified before any payment. This makes spoofed/misconfigured
degradation a verification failure (no payment) rather than something a cooldown races to
contain. This is why v0.6.0 evidence Phase-A (the `mica` verifier) was a hard prerequisite.

### New components — Delivered

- [x] **`slo_broker.py`** — `SLOPaymentBroker`: wraps `HardenedX402Client`; on a verified
  `SLOTrigger` applies cooldown + tier escalation + per-event/daily caps; buys capacity via
  a pluggable `CapacityProvider` (default `X402CapacityProvider`); records
  `SLO_PAYMENT_TRIGGERED` / `SLO_PAYMENT_BLOCKED` audit events. Decision serialized
  (`asyncio.Lock`) so concurrent triggers can't both pass the cooldown.

- [x] **`slo_policy.py`** — `SLOPaymentPolicy(PolicyConfig)`: `latency_threshold_ms`,
  `max_per_slo_event_usd`, `cooldown_seconds`, `max_daily_slo_usd`, `tier_escalation_rules`.
  Being a `PolicyConfig` subclass, SLO spend also counts against the ordinary budgets (shared
  ledger); the SLO caps are an independent second layer.

- [x] **`arch_translucency_adapter.py`** — `ArchTranslucencyAdapter` + `SLOTrigger`:
  fail-closed gate that accepts a degradation signal only when (1) `sha256(content)` matches
  the ref's `content_hash`, (2) the signature verifies against a trusted signer
  (`mica.verify_ref`), and optionally (3) the signer is on an allow-list. Feed transport
  injectable; attested-content field names overridable via `field_map`.

- [x] **Extended PII filter**: opt-in provisioning entity types (`WORKLOAD_CLASS`,
  `DATA_CLASSIFICATION`, `QUERY_PATTERN`) — kept out of the default active set so existing PII
  behaviour is unchanged; selectable via `entities=` / `PROVISIONING_ENTITIES`. Redacts
  workload context before it reaches a third-party compute provider.

**Test coverage:** `test_slo_policy.py`, `test_arch_translucency_adapter.py`,
`test_slo_broker.py`, `test_pii_provisioning.py` (29 tests). Full suite 476 passed / 9 skipped.

### Scoping decisions for v0.7.0

- **Provider-side x402 support**: A compute provider exposing capacity tiers via x402 402
  responses may need to be prototyped for empirical evaluation. Coinbase-compatible
  facilitator reuse expected; no new blockchain integration required.

- **SLO signal types**: v0.7.0 covers latency-based triggers only (p99 threshold).
  Throughput and error-rate triggers deferred until after v0.7.0 to keep the empirical evaluation
  tractable.

- **Multi-provider bidding**: Deferred until after v0.7.0.
  *Rationale: Single-provider SLO payment is the minimal falsifiable experiment.
  Multi-provider auction adds significant complexity without changing the core claim.*

### New threat model entries

| ID | Threat | Primary mitigation | Defense-in-depth |
|----|--------|--------------------|------------------|
| **T-SLO-1** | SLO-triggered spending drain — adversarial or misconfigured infrastructure floods the agent with degraded signals to provoke runaway capacity payments | **Signed-trigger verification**: only a fail-closed-verified `evidence-ref` from a trusted arch-translucency signer can trigger a payment (`ArchTranslucencyAdapter` + `mica.verify_ref`) | `SLOPaymentPolicy` cooldown, `max_per_slo_event_usd`, `max_daily_slo_usd`, and step-up `tier_escalation_rules` |
| **T-SLO-2** | Workload-metadata leakage — provisioning requests carry query types, data classifications, and access patterns that must not reach third-party compute providers | Extended `PIIFilter` provisioning entities (`WORKLOAD_CLASS`, `DATA_CLASSIFICATION`, `QUERY_PATTERN`) redact workload context before transmission | Opt-in, so no false-positive regression on ordinary payment metadata |
| **T-SLO-3** | Vendor lock-in via payment coupling — agent becomes economically dependent on one capacity provider | Pluggable `CapacityProvider` registry in `SLOPaymentBroker` | — |

---

## Security Model

The threat model for presidio-hardened-x402 addresses the following adversaries:

1. **Malicious 402 server**: Embeds PII-harvesting fields in payment metadata to extract
   sensitive data from agents. *Mitigation: PIIFilter scrubs all metadata before commit.*

2. **Overcharging server**: Sets `maxAmountRequired` above agent's per-call limit to drain
   wallets. *Mitigation: PolicyEngine enforces per-call maximum.*

3. **Budget exhaustion attack**: Sends many small, legitimate-looking 402 responses to
   drain daily budget. *Mitigation: PolicyEngine enforces time-window aggregate limits.*

4. **Replay attack**: Captures a signed payment and replays it against the same endpoint.
   *Mitigation: ReplayGuard detects duplicate fingerprints before re-signing.*

5. **Duplicate billing**: Server re-submits payment request after partial fulfillment.
   *Mitigation: ReplayGuard deduplicates by canonical payment fields.*

---

## Design Principles

- **Drop-in**: `HardenedX402Client` is a direct behavioral replacement for any async HTTP
  client handling 402 responses. Minimal code changes to adopt.
- **Defense in depth**: Each control is independent; disabling one does not weaken others.
- **Zero-trust metadata**: All payment metadata is treated as untrusted until scanned.
- **Fail-safe**: Security control errors default to blocking the payment, not allowing it.
- **Observable**: Every security decision is audited; no silent suppression.

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
