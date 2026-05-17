# Changelog

All notable changes to `presidio-hardened-x402` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
