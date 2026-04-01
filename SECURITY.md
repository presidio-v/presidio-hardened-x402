# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✓ (current) |

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

## Threat Model

See `PRESIDIO-REQ.md` for the full threat model and security design rationale.

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
