# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.7.x   | ✓ (latest release) |
| 0.6.x   | ✓ |
| 0.5.x   | ✓ |
| 0.4.x   | ✓ |
| 0.3.x   | security fixes only |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

## Security Controls

presidio-hardened-x402 provides the following security controls for x402 payments:

1. **PII redaction** — Presidio-based detection and redaction of personal data from payment
   metadata fields before blockchain commit
2. **Spending policy enforcement** — Per-agent, per-endpoint, and per-time-window budget
   limits enforced before payment execution
3. **Replay detection** — HMAC-SHA256 fingerprinting of canonical payment fields with TTL
   deduplication to prevent duplicate payments
4. **Audit logging** — HMAC-chained JSON-L audit trail for every payment attempt
5. **Multi-party authorization (MPA)** — n-of-m approval requirement for high-value payments,
   via webhook or HMAC-SHA256 cryptographic countersignature modes (v0.3.0+)
6. **Prometheus metrics** — Structured telemetry for all security control activations,
   enabling real-time alerting on policy violations, PII detections, and replay attempts (v0.3.0+)
7. **Enterprise audit sinks** — Optional S3, Splunk HEC, and Datadog audit writers
   with bounded buffers and TLS enforcement (v0.6.0+)
8. **Evidence verification** — Signed `evidence-ref@1` emission and trust-store-backed
   verification for compliance-supporting audit windows (v0.6.0+)

### Automatic vs. opt-in controls

To avoid over-claiming, the table below states exactly which controls are applied
automatically by `HardenedX402Client` on every payment flow and which require
explicit configuration by the integrator. Controls marked **opt-in** are *not*
active unless you enable them.

| Control | Mode | How to enable |
|---------|------|---------------|
| PII detection + redaction of payment metadata | **Automatic** | On by default (`pii_action="redact"`); `regex` engine, zero-setup |
| `pii_action="block"` / `"warn"` instead of redact | Opt-in | Pass `pii_action=` to the client |
| spaCy NER (`nlp`) PII engine | Opt-in | Install `presidio-hardened-x402[nlp]` + set the regex/nlp mode flag; `regex` is the default |
| Spending-policy enforcement | **Automatic when a policy is set** | Pass `policy={...}`; with no policy, no budget limits are enforced |
| Replay detection | **Automatic** (in-memory) | On by default; set `PRESIDIO_X402_FINGERPRINT_KEY` + the Redis backend for cross-process durability |
| Audit logging (HMAC-chained JSON-L) | **Automatic when an audit writer is set** | Provide an `audit_writer`; set `PRESIDIO_X402_CHAIN_KEY` for a stable chain key (else per-process key + ERROR log) |
| Multi-party authorization (MPA) | Opt-in | Construct and pass an `MPAEngine` |
| Hosted screening service | Opt-in | `remote_screening=True` + a `screening_client` (local regex still runs as backstop) |
| Prometheus metrics | Opt-in | Install `prometheus-client` and wire a `MetricsCollector` (graceful no-op when absent) |
| OpenTelemetry spans | Opt-in | Install `[otel]` and configure an exporter; disabled is a no-op |
| Remote audit sinks | Opt-in | Use `MultiAuditWriter` with `S3AuditWriter`, `SplunkAuditWriter`, or `DatadogAuditWriter` |
| Evidence signing / verification | Opt-in | Use `build_evidence()` / `verify_ref()` with a deployment trust store |
| SLO payment broker (v0.7.0) | Opt-in | `SLOPaymentBroker` pays only on a **verified** signed degradation trigger (`ArchTranslucencyAdapter` → `verify_ref`); cooldown + per-event/daily caps + escalation as defence-in-depth |

Header/secret redaction at the logging sink ships in v0.5.0 (family audit rec
R2): `install_log_redaction()` runs at package import and scrubs API keys,
bearer tokens, and 32-byte hex key/signature material from every
`presidio_x402` log record. Integrator code outside this logger namespace must
still follow the same discipline. From v0.5.0 the documented security
guarantees can be verified end-to-end in your environment with the partner
conformance suite: `python -m presidio_x402.conformance` (see SEMVER.md).

## Threat Model

See `PRESIDIO-REQ.md` for the full threat model and security design rationale.

### v0.3.0 additions

| Threat | Mitigation |
|--------|-----------|
| Large-value payment without human oversight | MPA engine requires n-of-m approvals above configurable USD threshold |
| Compromised single approver in MPA | Threshold design: n-of-m means one compromised approver does not unilaterally approve |
| MPA denial-of-service (timeout) | `MPATimeoutError` blocks payment on timeout; no implicit approval |
| Forged MPA webhook response | Crypto mode verifies HMAC-SHA256 countersignatures against shared secrets |
| Unobservable security control activations | Prometheus metrics expose every PII detection, policy block, replay, and MPA event |

### v0.7.0 additions (SLO payment broker)

| Threat | Mitigation |
|--------|-----------|
| T-SLO-1 — SLO-triggered spending drain (spoofed/misconfigured degradation signals) | Trigger is an *authorization, not a metric*: only a fail-closed-verified signed `evidence-ref` from a trusted arch-translucency signer can trigger a payment; cooldown + per-event/daily caps + step-up escalation are defence-in-depth |
| T-SLO-2 — Workload-metadata leakage to a compute provider | Opt-in provisioning PII entities (`WORKLOAD_CLASS`, `DATA_CLASSIFICATION`, `QUERY_PATTERN`) redact workload context before transmission |
| T-SLO-3 — Vendor lock-in via payment coupling | Pluggable `CapacityProvider` registry |

## Dependency Security

- Dependencies are pinned to minimum-safe versions
- `dependabot.yml` is configured for automated dependency updates
- CodeQL analysis is run on every push and pull request
- CI runs `pip-audit` against release extras (`evidence`, `redis`, `audit-s3`,
  `langchain`, `prometheus`, `otel`, `schema`) before merge
- Critical security updates are backported to the current supported version

## Known Limitations

- The `PaymentSigner` protocol is abstract; the security of the signing implementation
  is the caller's responsibility
- The `nlp` PII mode requires a spaCy NER model; the `regex` mode covers structural PII
  only (emails, SSNs, credit cards, phone numbers) and may miss free-text PII
- The in-memory replay guard does not persist across process restarts; use the Redis
  backend for production deployments requiring cross-process deduplication
- The CrewAI adapter remains importable, but the `crewai` extra is intentionally
  empty until CrewAI's `chromadb` dependency has a fixed release for CVE-2026-45829.
  Install CrewAI separately only after your own dependency audit and risk acceptance.

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.

## Manual Security Audit History

- [`SECURITY-AUDIT-2026-06-21-v0.7.0.md`](SECURITY-AUDIT-2026-06-21-v0.7.0.md) —
  v0.7.0 third-party functional/security audit remediation status.
