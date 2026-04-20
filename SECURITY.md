# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✓ (current) |
| 0.2.x   | ✓ |
| 0.1.x   | security fixes only |

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

## Dependency Security

- Dependencies are pinned to minimum-safe versions
- `dependabot.yml` is configured for automated dependency updates
- CodeQL analysis is run on every push and pull request
- Critical security updates are backported to the current supported version

## Known Limitations

- The `PaymentSigner` protocol is abstract; the security of the signing implementation
  is the caller's responsibility
- The `nlp` PII mode requires a spaCy NER model; the `regex` mode covers structural PII
  only (emails, SSNs, credit cards, phone numbers) and may miss free-text PII
- The in-memory replay guard does not persist across process restarts; use the Redis
  backend for production deployments requiring cross-process deduplication

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
