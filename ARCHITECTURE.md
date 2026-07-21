# Architecture

This document describes the high-level design of `presidio-hardened-x402`: its
components, how a payment flows through them, and the trust boundaries the
library is built to enforce. For the security requirements and threat model that
motivate this design, see [SECURITY.md](SECURITY.md) and
[PRESIDIO-REQ.md](PRESIDIO-REQ.md). For the stable public API surface, see
[SEMVER.md](SEMVER.md).

## What the library is

`presidio-hardened-x402` is **pre-execution security middleware** for the x402
agentic HTTP payment protocol. It sits between an AI agent (or any x402 client)
and the payment rail, and applies a chain of security controls to each payment
*before* the request is transmitted or committed on-chain. It is a Python
library, not a service; the optional hosted screening endpoint is a separate
deployment that the library can call but does not require.

## Component overview

The package (`src/presidio_x402/`) is organised as a set of single-responsibility
modules. Implementation and dependency order runs from primitives outward:
`exceptions` → `_types` → `pii_filter` → `policy_engine` → `replay_guard` →
`audit_log` → `gateway`.

| Module | Responsibility |
|---|---|
| `core.py` / `gateway.py` | `HardenedX402Client` — the entry point that composes the controls into one payment pipeline. |
| `pii_filter.py` | Presidio-based detection and redaction of personal data in payment metadata. `regex` engine is the zero-setup default; `nlp` (spaCy NER) is an opt-in structural superset. |
| `policy_engine.py` / `x402_policy_schema.py` / `slo_policy.py` | Spending-policy enforcement — per-agent, per-endpoint, per-time-window budget limits; policy-as-code JSON Schema. |
| `replay_guard.py` | HMAC-SHA256 fingerprinting of canonical payment fields with TTL deduplication. In-memory by default; Redis backend for cross-process durability. |
| `audit_log.py` / `audit_sinks.py` | HMAC-chained JSON-L audit trail; optional S3 / Splunk / Datadog sinks with bounded buffers and TLS enforcement. |
| `mpa.py` | Multi-party authorization — n-of-m approvals above a threshold, via webhook or HMAC countersignature modes. |
| `decision_ref.py` / `action_ref.py` / `capability.py` / `compliance_report.py` / `mica.py` | Proof-carrying evidence layer — signed, byte-deterministic, offline-verifiable records (`payment-decision@1`, `capability-grant@1`) and compliance reporting. |
| `arch_translucency_adapter.py` / `slo_broker.py` | SLO payment broker — pays only on a fail-closed-verified signed degradation trigger. |
| `screening_client.py` | Client for the optional hosted screening service (local regex still runs as a backstop). |
| `bindings/x402.py` | `PaymentProtocolBinding` — rail-agnostic core with an x402 binding layer, hedging against rail fragmentation. |
| `adapters/langchain.py`, `adapters/crewai.py` | Framework integrations. |
| `metrics.py` / `telemetry.py` / `log_redaction.py` | Prometheus metrics, OpenTelemetry spans, and import-time log-sink redaction of secrets. |
| `conformance/` | The partner conformance suite (`python -m presidio_x402.conformance`) that verifies the documented guarantees end-to-end. |

## Payment flow

A payment passes through the controls as a pipeline, and the pipeline
**fails closed** — any control that raises blocks the payment rather than letting
it through:

1. **Spending-policy enforcement** — the payment is checked against the
   configured budget limits first. Policy checks run *before* replay
   fingerprinting by design, so a policy-rejected payment never consumes a
   replay slot.
2. **Replay fingerprinting** — a canonical, HMAC-fingerprinted representation of
   the payment is checked against the TTL-bounded dedup store.
3. **PII detection and redaction** — personal data in the payment metadata is
   redacted (or the payment is blocked / warned, per `pii_action`) *before* it
   can leave the process toward the network or the chain.
4. **Multi-party authorization** (when configured) — high-value payments require
   n-of-m approvals before proceeding.
5. **Audit + evidence** — the attempt and its outcome are written to the
   HMAC-chained audit log, and (opt-in) a signed, offline-verifiable evidence
   record is emitted.

Metrics and telemetry are emitted at each control activation for observability.

## Trust boundaries

The design treats the following as the boundaries where untrusted data enters or
sensitive data leaves:

- **Agent / caller → library (untrusted input).** All payment metadata arriving
  from the calling agent is treated as untrusted and validated before use. This
  is the primary input-validation boundary.
- **Library → payment rail / blockchain (irreversible egress).** Once a payment
  is committed on-chain it cannot be recalled, so PII redaction and policy
  enforcement happen *before* this boundary is crossed — the whole point of the
  "pre-execution" design.
- **Library → hosted screening service and remote audit sinks (network egress).**
  All network communication enforces TLS with certificate verification; local
  regex screening still runs as a backstop so a remote failure fails safe.
- **Signing key custody (out of scope, by contract).** The `PaymentSigner`
  protocol is abstract — the library never holds wallet keys; the security of the
  signing implementation is the caller's responsibility. Evidence-signing keys
  are supplied by the deployment and never embedded in the library.

## Extension points

The library depends on protocols, not concrete vendor SDKs, so integrators can
substitute their own implementations:

- `PaymentSigner` — wallet/signing implementation (no bundled wallet dependency).
- `PaymentProtocolBinding` — the payment rail (x402 today; the core is
  rail-agnostic).
- `CapacityProvider` — pluggable capacity source for the SLO broker.
- Audit writers (`S3AuditWriter`, `SplunkAuditWriter`, `DatadogAuditWriter`, or a
  custom writer via `MultiAuditWriter`).
- Screening client — local, hosted, or custom.

## Language and safety properties

The library is pure Python (3.10+), which is memory-safe — there is no manual
memory management, so the memory-safety class of vulnerabilities does not apply.
Robustness of the canonicalisation and digest layer is checked with Atheris
fuzzing in CI, and the security-relevant control paths are covered by the test
suite (statement coverage is gated at ≥90% in CI).
