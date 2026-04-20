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

- arXiv cs.CR preprint by 2026-11-01
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

### New exceptions

- `MPADeniedError(approvals_received, threshold)` — n-of-m requirement not met
- `MPATimeoutError(approvals_received, threshold)` — webhook timeout

### New optional extras

- `[prometheus]`: `prometheus-client>=0.20.0`
- `[schema]`: `jsonschema>=4.21.0`

---

## v0.4.0 Requirements (Production Hardening)

- Third-party security audit of all v0.1.0–v0.3.0 modules
- Performance regression test suite: p99 < 50ms latency SLO enforced in CI
- Policy hot-reload: update `PolicyConfig` at runtime without client restart
- OpenTelemetry span export for every security control activation
- Operator runbook (GitHub Pages)

---

## v0.5.0 Requirements (SLO Payment Broker)

This version fills a second white spot: **market-based SLO enforcement**. Current
autoscaling is reactive and rule-based. This milestone makes the agent an economic actor
that bids for the infrastructure quality it needs — paying only when it needs it — via
x402 micropayments.

### Integration target

`presidio-hardened-arch-translucency` provides the SLO observability signal (latency
percentiles, quality metrics). `presidio-hardened-x402` acts as the SLO payment broker:
it receives degradation events, applies `SLOPaymentPolicy`, and triggers x402 payments
for capacity upgrades — all with the same PII redaction and spending governance already
built in v0.1.0.

### New components

- **`slo_broker.py`** — `SLOPaymentBroker`: wraps `HardenedX402Client`; listens to SLO
  degradation events; applies cooldown and tier escalation logic; triggers capacity upgrade
  payments; records `SLO_PAYMENT_TRIGGERED` and `SLO_PAYMENT_BLOCKED` audit events.

- **`slo_policy.py`** — `SLOPaymentPolicy`: extends `PolicyConfig` with:
  - `latency_threshold_ms`: p99 latency above which a payment is triggered
  - `max_per_slo_event_usd`: per-event spending cap
  - `cooldown_seconds`: minimum gap between consecutive SLO payments (prevents drain)
  - `max_daily_slo_usd`: daily SLO spending cap (shares ledger with `PolicyEngine`)
  - `tier_escalation_rules`: step-up pricing for repeated degradation events

- **`arch_translucency_adapter.py`** — consumes `presidio-hardened-arch-translucency`
  metrics feed; translates degradation events into `SLOTrigger` objects consumed by
  `SLOPaymentBroker`.

- **Extended PII filter**: provisioning-specific entity types (`WORKLOAD_CLASS`,
  `DATA_CLASSIFICATION`, `QUERY_PATTERN`) added to the `PIIFilter` entity registry.
  Infrastructure provisioning requests carry sensitive workload context that must not
  reach third-party compute providers.

### Scoping decisions for v0.5.0

- **Provider-side x402 support**: A compute provider exposing capacity tiers via x402 402
  responses may need to be prototyped for empirical evaluation. Coinbase-compatible
  facilitator reuse expected; no new blockchain integration required.

- **SLO signal types**: v0.5.0 covers latency-based triggers only (p99 threshold).
  Throughput and error-rate triggers deferred to v0.6.0 to keep the empirical evaluation
  tractable.

- **Multi-provider bidding**: Deferred to v0.6.0.
  *Rationale: Single-provider SLO payment is the minimal falsifiable experiment.
  Multi-provider auction adds significant complexity without changing the core claim.*

### New threat model entries

| Threat | Mitigation |
|--------|-----------|
| SLO-triggered spending drain (adversarial or misconfigured degradation signals) | `SLOPaymentPolicy` cooldown + `max_daily_slo_usd` cap |
| Workload metadata leakage in provisioning requests | Extended PIIFilter covers provisioning-specific entity types |
| Vendor lock-in via payment coupling | Pluggable provider registry in `SLOPaymentBroker` |

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
