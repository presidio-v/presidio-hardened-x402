# Security Assurance Case

This document is the assurance case for `presidio-hardened-x402`: an explicit
argument for why the library's security requirements are met. It has four parts,
as required by the OpenSSF Best Practices silver criterion `assurance_case`:

1. the threat model,
2. the trust boundaries,
3. the argument that secure design principles are applied, and
4. the argument that common implementation weaknesses are countered.

It is a summary that links to the authoritative detail in
[`PRESIDIO-REQ.md`](PRESIDIO-REQ.md) (full threat model and requirements),
[`SECURITY.md`](SECURITY.md) (controls, per-version threat tables, reporting),
and [`ARCHITECTURE.md`](ARCHITECTURE.md) (components, flow, boundaries).

## 1. Threat model

The library is **pre-execution security middleware** for the x402 agentic HTTP
payment protocol. The asset it protects is a payment request that an AI agent is
about to transmit and commit — an action that is **irreversible** once it reaches
the chain. The adversaries and threats it is designed against:

- **A compromised or buggy agent** that would transmit personal data in payment
  metadata → PII detection and redaction before egress.
- **An agent driven to overspend** (prompt injection, logic error, malicious
  instruction) → per-agent/endpoint/time-window spending-policy enforcement, and
  n-of-m multi-party authorization above a value threshold.
- **Duplicate / replayed payments** → HMAC-SHA256 canonical-field fingerprinting
  with TTL deduplication.
- **A spoofed or misconfigured runtime signal driving spend** (SLO broker) → the
  trigger is a fail-closed-verified signed evidence record, not a raw metric,
  plus cooldowns and per-event/daily caps.
- **Tampering with, or repudiation of, the audit trail** → HMAC-chained JSON-L
  audit log and signed, offline-verifiable evidence records.
- **Metadata leakage to a compute/payment counterparty** → opt-in provisioning
  PII entities redact workload context before transmission.

Per-version threat/mitigation tables are maintained in
[`SECURITY.md`](SECURITY.md#threat-model). The full deliberation and
requirements rationale are in [`PRESIDIO-REQ.md`](PRESIDIO-REQ.md).

Explicitly **out of scope** (documented, not silently assumed): wallet key
custody and the security of the `PaymentSigner` implementation (supplied by the
integrator), the security of the payment rail / blockchain itself, and free-text
PII beyond the configured detector's recall in `regex` mode.

## 2. Trust boundaries

The design treats these as the boundaries where untrusted data enters or
sensitive data leaves (see [`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries)):

- **Agent / caller → library** — all payment metadata from the calling agent is
  **untrusted input** and is validated before use. This is the primary
  input-validation boundary.
- **Library → payment rail / blockchain** — the irreversible-egress boundary.
  PII redaction and policy enforcement complete *before* anything crosses it.
- **Library → hosted screening service and remote audit sinks** — network-egress
  boundaries; all traffic is TLS with certificate verification, and local regex
  screening remains a backstop so a remote failure fails safe.
- **Signing-key custody** — outside the library by contract; the library holds no
  wallet keys, and evidence-signing keys are supplied by the deployment.

## 3. Secure design principles applied

- **Fail-safe defaults / secure by default** — the pipeline fails closed (any
  control that raises blocks the payment); PII redaction is on by default; new
  controls are opt-in and defaults are not weakened without explicit rationale.
- **Complete mediation** — every payment passes policy, replay, and PII controls
  before egress; the ordering (policy before replay fingerprinting) is a
  deliberate part of the contract.
- **Least privilege** — the library never holds wallet signing keys
  (`PaymentSigner` is abstract); evidence keys are deployment-supplied.
- **Defense in depth** — independent controls (policy, replay guard, PII filter,
  MPA, HMAC-chained audit, signed evidence) each cover a distinct threat; the SLO
  broker adds cooldowns and caps on top of signature verification.
- **Economy of mechanism** — cryptography uses vetted primitives (`hashlib`,
  `hmac`, `secrets`, `cryptography`: SHA-256, HMAC-SHA256, ed25519); no bespoke
  crypto.

These map to the secure-design argument in
[`ARCHITECTURE.md`](ARCHITECTURE.md#language-and-safety-properties) and the
controls table in [`SECURITY.md`](SECURITY.md#security-controls).

## 4. Common implementation weaknesses countered

The relevant weakness classes for a Python payment-security library, and how each
is countered:

| Weakness class | How it is countered |
|---|---|
| **Improper input validation / injection** (CWE-20, CWE-74) | All caller-supplied payment metadata is treated as untrusted; canonicalisation and digest functions are byte-stability contracts; `action_ref` rejects empty entity-type sets and NFC-normalizes before hashing. No SQL/shell/eval paths. |
| **Memory-safety errors** (CWE-119 family) | The library is pure Python (memory-safe); the canonicalisation/digest layer is additionally fuzzed with Atheris in CI. |
| **Cryptographic misuse** (CWE-327, CWE-916) | Standard-library / `cryptography` primitives only; HMAC comparison uses constant-time equality; no weak algorithms (no MD5/SHA-1/DES for security). |
| **Hard-coded / exposed secrets** (CWE-798, CWE-532) | No secrets in source; keys come from environment/config separate from code; `install_log_redaction()` scrubs keys, tokens, and hex key material from logs, and the missing-header warning omits request URLs. |
| **Insecure network communication / SSRF** (CWE-319, CWE-295) | TLS with certificate verification on all egress; verification cannot be disabled; remote failure fails safe to the local backstop. |
| **Replay** (CWE-294) | HMAC-fingerprinted canonical payment fields with TTL deduplication. |
| **Insufficient logging / audit tampering** (CWE-778, CWE-117) | HMAC-chained JSON-L audit trail; signed, offline-verifiable evidence records. |
| **Unsafe deserialization** (CWE-502) | Records are JSON; no `pickle`/`eval` of untrusted input. |
| **Vulnerable dependencies** (CWE-1104) | Dependency floors, Dependabot, and `pip-audit` in CI; CycloneDX SBOM per release. |

These weakness classes are also checked continuously by automated tooling:
**CodeQL**, **bandit** (ruff `S` rules), and **OpenSSF Scorecard** run on every
push and pull request, and an independent multi-round security review was
performed for v0.8.0 (see the audit history in
[`SECURITY.md`](SECURITY.md#manual-security-audit-history)).

## Conclusion

The threats above are each matched to a control; the controls sit at explicit
trust boundaries; the design follows fail-safe, least-privilege, complete-
mediation, defense-in-depth, and economy-of-mechanism principles; and the common
implementation weakness classes are countered by design and checked by automated
analysis and independent review. The library's stated security requirements are
therefore met, subject to the documented out-of-scope assumptions (wallet key
custody, the payment rail, and free-text PII recall in `regex` mode).
