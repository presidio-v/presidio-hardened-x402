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

- Endpoint reputation scorer with VirusTotal/SafeBrowsing feed adapters
- Heuristic reputation signals: price drift, metadata entropy, domain age
- LangChain adapter (`adapters/langchain.py`)
- CrewAI adapter (`adapters/crewai.py`)
- Compliance report generator (`compliance_report.py`): SOC2-friendly, HMAC-chained
  JSON-L with GDPR data-subject reference support
- Empirical PII measurement corpus and arXiv preprint

---

## v0.3.0 Requirements (Mature Enterprise)

- Multi-party authorization engine (`mpa.py`): n-of-m approval, webhook + cryptographic
  countersignature modes
- Policy-as-code JSON Schema (`x402-policy-schema.json`): shareable policy format,
  IETF draft candidate
- Kubernetes sidecar: Helm chart, Docker image (GHCR), Prometheus metrics exporter
- SOC2 compliance reference architecture guide

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
