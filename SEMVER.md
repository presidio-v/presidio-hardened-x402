# Stability & semver guarantees — presidio-hardened-x402

For OEM partners embedding this library. Effective from v0.5.0.

## What is the public API

Everything exported in `presidio_x402.__all__`, plus the documented constructor/method signatures of those names, plus the modules `presidio_x402.core`, `presidio_x402.bindings.x402`, and the `presidio_x402.conformance` runner. Underscore-prefixed names are internal — but the pre-v0.5.0 gateway aliases (`gateway._parse_402_header`, `gateway._HEADER_PAYMENT`, `gateway._SUPPORTED_SCHEME`, `gateway._amount_to_usd`) are grandfathered and kept until v1.0.0.

## Versioning rules (semver, pre-1.0 profile)

- **Patch (0.x.Y):** bug fixes, security fixes, dependency floor bumps. No API change, no behaviour change except the fixed defect. Safe to auto-upgrade; this is the channel security releases ship on.
- **Minor (0.X.0):** additive API (new exports, new optional parameters with defaults), new optional extras. Existing code keeps working — including audit event shapes, exception types, and the wire behaviour of the x402 binding. Deprecations are announced here (docstring + CHANGELOG) at least one minor before any change.
- **Major (1.0.0+):** the only place deprecated surface may be removed. None scheduled.

**Pin guidance for partners:** `presidio-hardened-x402>=0.8,<0.9` in production; run the conformance suite (below) in your CI on every upgrade.

## Behavioural guarantees (stronger than API stability)

These are security invariants, not just interfaces; weakening any of them is treated as a breaking change regardless of version component:

1. **Fail-closed:** malformed payment offers, PII in block mode, policy violations, and replays raise — they never degrade to a warning.
2. **Pre-signing screening:** all four controls (PII, policy, replay, MPA when configured) complete before the signer is invoked.
3. **Rollback on non-commit:** a payment that is never signed (signer failure, MPA denial/timeout) refunds the budget and frees the replay fingerprint.
4. **Sanitised audit path:** raw PII, signer exception chains, and oversized inputs never reach audit records or log sinks.
5. **Audit chain integrity:** JSON-L audit records are HMAC-chained; tampering is detectable via `ComplianceReport`.

## Verifying an installation

```bash
python -m presidio_x402.conformance
```

Runs the partner conformance suite (7 checks, no network) against the installed environment; exit code 0 means all guarantees above hold end-to-end. Run it in your CI next to your own integration tests.

## Schema/wire stability

- **x402 binding:** follows x402 spec v1 (`X-PAYMENT`, scheme `exact`). New schemes are additive (minor).
- **Audit records:** fields are additive-only within a minor line; `ComplianceReport` reads all prior 0.x record shapes.
- **Rail bindings:** `PaymentProtocolBinding` is a stable protocol from v0.5.0; custom bindings written against it will not break within 0.x.

## Security response

See [SECURITY.md](SECURITY.md). Security fixes ship as patch releases on the latest minor; the minimum-safe dependency floors (`_KNOWN_VULNERABLE`) are bumped in the same release.
