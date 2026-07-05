# presidio-hardened-x402

[![PyPI version](https://img.shields.io/pypi/v/presidio-hardened-x402.svg)](https://pypi.org/project/presidio-hardened-x402/)
[![Python](https://img.shields.io/pypi/pyversions/presidio-hardened-x402.svg)](https://pypi.org/project/presidio-hardened-x402/)
[![GitHub release](https://img.shields.io/github/v/release/presidio-v/presidio-hardened-x402.svg)](https://github.com/presidio-v/presidio-hardened-x402/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/presidio-v/presidio-hardened-x402/actions/workflows/ci.yml/badge.svg)](https://github.com/presidio-v/presidio-hardened-x402/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/presidio-v/presidio-hardened-x402/badge)](https://securityscorecards.dev/viewer/?uri=github.com/presidio-v/presidio-hardened-x402)

> v0.9.0 — proof-carrying x402 evidence: attenuable `capability-grant@1` spending grants plus opt-in `payment-decision@1` decision refs with raw-offer digest binding, fail-closed offline verification, capability-chain provenance linkage, and PII-free emitted records.

Security middleware for the [x402 payment protocol](https://www.x402.org/).

Intercepts x402 payment requests **before transmission to servers and facilitators** to enforce:

- **PII redaction** — Presidio-based detection and redaction of personal data (emails, names, SSNs, credit cards, etc.) from payment metadata fields before they are sent to the payment server or facilitator API
- **Spending policy** — per-agent, per-endpoint, and per-time-window budget limits that block or throttle payments before execution
- **Replay detection** — HMAC-SHA256 fingerprinting of canonical payment fields to prevent duplicate and replayed payments; case-canonicalised on `pay_to` and `currency` *(v0.4.0)*
- **Audit logging** — HMAC-chained JSON-L audit trail for every payment attempt (including blocked ones)
- **Multi-party authorization** — n-of-m approval requirement for high-value payments, via webhook or HMAC-SHA256 cryptographic countersignature modes *(v0.3.0)*
- **Prometheus metrics** — structured telemetry for every security control activation *(v0.3.0)*
- **Remote screening** — opt-in `remote_screening=True` mode offloads PII analysis to the hosted [`screen.presidio-group.eu`](https://screen.presidio-group.eu) service via `ScreeningClient`; avoids the in-process spaCy dependency *(v0.4.0)*
- **Per-origin wallet allowlist** — per-origin `pay_to` allowlist blocks payments to attacker-controlled addresses when a DNS-poisoned 402 response substitutes the recipient (chain-06 mitigation) *(v0.4.0)*
- **Rail-agnostic core + binding layer** — the screening pipeline (`ScreeningPipeline`) is payment-protocol-independent; everything x402-specific lives in `bindings/x402`. Embed on a different rail by implementing `PaymentProtocolBinding` — the security guarantees travel with the core *(v0.5.0)*
- **OEM embed kit** — [semver/stability guarantees](SEMVER.md), partner-runnable conformance suite (`python -m presidio_x402.conformance`, 7 end-to-end checks, no network), and integration quickstarts for [Coinbase CDP](docs/quickstarts/coinbase-cdp.md), [LangChain](docs/quickstarts/langchain.md), and [CrewAI](docs/quickstarts/crewai.md) *(v0.5.0)*
- **Enterprise hardening** — per-tenant replay namespaces, remote audit sinks, signed evidence verification, OpenTelemetry spans, hot-reloadable policy, release provenance, and latency-SLO CI gates *(v0.6.0)*

Part of the [presidio-hardened-*](https://github.com/presidio-v) toolkit family.

---

## Installation

```bash
pip install presidio-hardened-x402
```

For full NLP-based PII detection (PERSON, ORG, location, etc.):

```bash
pip install "presidio-hardened-x402[nlp]"
python -m spacy download en_core_web_sm
```

For production replay guard with cross-process deduplication:

```bash
pip install "presidio-hardened-x402[redis]"
```

For Prometheus metrics export:

```bash
pip install "presidio-hardened-x402[prometheus]"
```

For policy-as-code schema validation:

```bash
pip install "presidio-hardened-x402[schema]"
```

---

## Quick Start

### Before (bare x402 — no security controls)

```python
import httpx

async def pay_and_fetch(url: str, signer) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        if resp.status_code == 402:
            payment_details = parse_402_header(resp.headers)
            # No PII check. No policy check. No replay check.
            payment_token = await signer.sign(payment_details)
            resp = await client.get(url, headers={"X-PAYMENT": payment_token})
        return resp
```

### After (presidio-hardened-x402)

```python
from presidio_x402 import HardenedX402Client

async def my_signer(details):
    # Your existing signing logic (eth-account, solders, CDP SDK, etc.)
    ...

client = HardenedX402Client(
    payment_signer=my_signer,
    policy={
        "max_per_call_usd": 0.10,
        "daily_limit_usd": 5.0,
        "per_endpoint": {"https://api.example.com": 1.0},
    },
    pii_action="redact",          # redact | block | warn
    pii_entities=["EMAIL_ADDRESS", "PERSON", "US_SSN", "CREDIT_CARD"],
    replay_ttl=300,               # seconds
)

response = await client.get("https://api.example.com/resource")
```

What happens transparently:

1. Client sends `GET /resource` → server returns `402` with payment details
2. **PIIFilter** scans resource URL, description, and reason fields; redacts any PII
3. **PolicyEngine** checks: amount ≤ per-call limit? daily spend within budget? endpoint limit OK?
4. **ReplayGuard** checks: have we paid this exact request within the TTL window?
5. **AuditLog** records the attempt (pass or block) as a tamper-evident JSON-L entry
6. If all checks pass, signer is called → payment header sent → resource returned

---

## Configuration

### Policy

```python
from presidio_x402 import HardenedX402Client, PolicyConfig

policy = PolicyConfig(
    max_per_call_usd=0.05,         # block if maxAmountRequired > this
    daily_limit_usd=2.00,          # block if 24h aggregate spend would exceed this
    per_endpoint={
        "https://premium-api.io": 0.50,  # per-endpoint daily limit
    },
    window_seconds=86400,          # time window for aggregate limits (default: 24h)
    agent_id="my-agent-v1",        # tag audit events with an agent identifier
)

client = HardenedX402Client(payment_signer=signer, policy=policy)
```

### PII Filter

```python
# regex mode (default, zero-setup): catches structured PII
client = HardenedX402Client(
    payment_signer=signer,
    pii_mode="regex",
    pii_entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD"],
    pii_action="redact",
)

# nlp mode: full spaCy NER (requires: pip install presidio-hardened-x402[nlp])
client = HardenedX402Client(
    payment_signer=signer,
    pii_mode="nlp",
    pii_entities=["EMAIL_ADDRESS", "PERSON", "LOCATION", "US_SSN"],
    pii_action="block",     # raise PIIBlockedError instead of redacting
)
```

### Replay Guard

```python
# In-memory (default, single-process)
client = HardenedX402Client(payment_signer=signer, replay_ttl=300)

# Redis-backed (production, cross-process)
client = HardenedX402Client(
    payment_signer=signer,
    replay_ttl=300,
    redis_url="redis://localhost:6379/0",
)
```

### Audit Log

```python
import sys
from presidio_x402 import HardenedX402Client
from presidio_x402.audit_log import StreamAuditWriter

client = HardenedX402Client(
    payment_signer=signer,
    audit_writer=StreamAuditWriter(sys.stdout),   # write JSON-L to stdout
)
```

---

## Multi-Party Authorization (v0.3.0)

For high-value payments that require human or system oversight before execution:

```python
from presidio_x402 import HardenedX402Client
from presidio_x402.mpa import MPAConfig, MPAApproverConfig, MPAEngine

mpa = MPAEngine(MPAConfig(
    threshold=2,               # require 2 of 3 approvals
    min_amount_usd=1.00,       # only for payments ≥ $1.00
    timeout_seconds=30,
    approvers=[
        MPAApproverConfig("alice", mode="webhook",
                          webhook_url="https://approvals.internal/alice"),
        MPAApproverConfig("bob",   mode="webhook",
                          webhook_url="https://approvals.internal/bob"),
        MPAApproverConfig("charlie", mode="webhook",
                          webhook_url="https://approvals.internal/charlie"),
    ],
))

client = HardenedX402Client(payment_signer=signer, mpa_engine=mpa)
```

Approval endpoints receive a POST with payment details and must return `{"approved": true}`.
For machine-to-machine approvals, use `mode="crypto"` with HMAC-SHA256 countersignatures
and pass them via `mpa_signatures={"approver_id": "hex_sig", ...}` in the request kwargs.

---

## Prometheus Metrics (v0.3.0)

```python
from presidio_x402 import HardenedX402Client
from presidio_x402.metrics import MetricsCollector

collector = MetricsCollector()
client = HardenedX402Client(payment_signer=signer, metrics_collector=collector)

# Expose /metrics endpoint (e.g., FastAPI)
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

Available metrics: `x402_payments_total`, `x402_payment_amount_usd` (histogram),
`x402_pii_detections_total`, `x402_policy_violations_total`,
`x402_replay_detections_total`, `x402_mpa_events_total`.

---

## Policy-as-Code (v0.3.0)

Define spending policy in a TOML or JSON file and validate it against the
[x402 policy JSON Schema](src/presidio_x402/x402-policy-schema.json):

```toml
# policy.toml
max_per_call_usd = 0.10
daily_limit_usd  = 5.00
agent_id         = "my-agent"

[per_endpoint]
"https://premium-api.io" = 0.50

[mpa]
threshold       = 2
min_amount_usd  = 1.00
timeout_seconds = 30

[[mpa.approvers]]
approver_id = "alice"
mode        = "webhook"
webhook_url = "https://approvals.internal/alice"
```

```python
from presidio_x402.x402_policy_schema import load_policy_file

policy = load_policy_file("policy.toml")
client = HardenedX402Client(payment_signer=signer, policy=policy)
```

---

## Remote Screening (v0.4.0)

Offload PII analysis to the hosted [`screen.presidio-group.eu`](https://screen.presidio-group.eu)
service. Useful when you want to keep the agent process small (no in-process spaCy
model) and centralise screening policy across many agents.

```python
from presidio_x402 import HardenedX402Client

client = HardenedX402Client(
    payment_signer=signer,
    remote_screening=True,
    screening_api_key="...",   # obtain by registering at screen.presidio-group.eu
)
```

The free tier serves the regex-mode screening backend at 100 screenings/day per key.
Falls back to local regex / NLP modes if the network is unhealthy, so the client never
hard-fails on a screening-service outage.

### Per-origin wallet allowlist (v0.4.0)

Defence against DNS-poisoning attacks that substitute the recipient wallet in a 402
response. Configure the trusted `pay_to` addresses per resource origin:

```python
client = HardenedX402Client(
    payment_signer=signer,
    trusted_wallets={
        "https://api.example.com": {"0xAbC...123"},
    },
)
```

Payments to a `pay_to` not in the allowlist for the response's origin are blocked
before signing.

---

## Kubernetes Deployment (v0.3.0)

Deploy as a sidecar using the bundled Helm chart:

```bash
helm install x402 ./helm \
  --set x402.agentId=my-agent \
  --set x402.maxPerCallUsd=0.10 \
  --set x402.dailyLimitUsd=5.00 \
  --set serviceMonitor.enabled=true
```

See [`docs/soc2-reference-architecture.md`](docs/soc2-reference-architecture.md) for
SOC 2 TSC mapping, GDPR obligations, and deployment patterns.

---

## SLO Payment Broker (v0.7.0)

Market-based SLO enforcement: when infrastructure degrades, the agent autonomously pays for
a capacity upgrade via x402 micropayments instead of relying on pre-provisioned autoscaling.
The broker acts only on a **verified** degradation signal — a signed
`evidence-ref@1` from a trusted `presidio-hardened-arch-translucency` signer — so a spoofed or
misconfigured signal cannot trigger a payment (authorization, not metric).

```python
from presidio_x402 import (
    HardenedX402Client, SLOPaymentBroker, SLOPaymentPolicy,
    X402CapacityProvider, ArchTranslucencyAdapter,
)

# arch-translucency's signed degradation feed → verified trigger (fail-closed).
adapter = ArchTranslucencyAdapter(
    {"presidio-hardened-arch-translucency": {"alg": "ed25519", "public_key": ARCH_PUB}},
    expected_signers=["presidio-hardened-arch-translucency"],
)
client = HardenedX402Client(payment_signer=signer)
broker = SLOPaymentBroker(
    client=client,
    slo_policy=SLOPaymentPolicy(
        cooldown_seconds=300,            # anti-drain
        max_per_slo_event_usd=0.50,
        max_daily_slo_usd=10.00,
        tier_escalation_rules=(1.0, 2.0, 4.0),  # step-up pricing for repeated degradation
    ),
    provider=X402CapacityProvider("compute", "https://compute.example/v1/capacity", client),
    base_event_usd=0.10,
)

for trigger in adapter.build_triggers(signed_envelope):  # verified or skipped
    await broker.handle_trigger(trigger)   # → paid / blocked / skipped, with audit event
```

The signing key lives in a separate bridge sidecar (arch-translucency stays key-less); x402
holds only the public key. The wire contract is pinned by the `evidence-ref@1`
golden-vector tests shared with arch-translucency.

---

## Decision-ref emission (`payment-decision@1`)

A **decision-ref** is a signed, portable record of one payment decision that a third
party verifies **offline** — without re-running the gateway. It binds the per-control
gate verdicts (`pii → trusted_wallet → policy → replay → mpa`), the hashed inputs, and
the effective policy hash into the family `evidence-ref@1` envelope, with a thin,
recomputable `decision_ref` correlation id. Emission is **opt-in and off by default**;
when no emitter is configured, behaviour is byte-identical to prior releases and no
decision-ref code runs. There is no network I/O on the emit path.

```python
from presidio_x402 import HardenedX402Client, DecisionRefEmitter, verify_decision_ref
from presidio_x402.decision_ref import FileDecisionRefWriter

# Signer independence is claim-critical: a policy/approval identity distinct from the
# payment wallet — a self-signed record fails closed on verify (signer_equals_runtime).
emitter = DecisionRefEmitter(
    signing_key=POLICY_PRIVATE_KEY_HEX,          # Ed25519 (or an HMAC secret)
    signer="presidio-hardened-x402-policy",
    writer=FileDecisionRefWriter("/var/log/x402-decisions.jsonl"),
)
client = HardenedX402Client(payment_signer=signer, decision_ref_emitter=emitter)
# ... one signed payment-decision@1 record is emitted per paid payment.

# Verify offline against a pinned trust store (fail-closed, distinct reasons):
result = verify_decision_ref(envelope, {"presidio-hardened-x402-policy":
    {"alg": "ed25519", "public_key": POLICY_PUBLIC_KEY_HEX}})
assert result.ok and result.verdict == "ALLOW"
```

The verifier checks signature, hash integrity, that the recorded verdict **re-derives**
from the recorded controls (`verdict == f(controls)` — the line between *attested* and
*admissible*), that the signer is not the actor's own controller (self-approval fails
closed), and — when the spending policy came from a capability chain
(`capability-grant@1`) — parent linkage to the chain's terminal `grant_hash`.
A minimal offline CLI is provided:

```bash
python -m presidio_x402.decision_ref envelope.jsonl trust-store.json
```

**Honest bound.** A decision-ref proves what the library concluded under a *declared*
predicate, tamper-evidently and recomputably. It does **not** prove the process was
uncompromised or that the declared controls are the real controls (no TEE claim). Wire
format and `decision_ref` derivation are pinned by the conformance fixture under
`tests/conformance/decision-ref/` and the design note
`plan/presidio-evidence-decision-ref-design.md`.

### Provisioning Metadata Redaction

Capacity-upgrade requests can reveal workload type, data classification, or access pattern.
Those heuristics are intentionally opt-in so ordinary payment metadata keeps the v0.6
false-positive profile.

```python
from presidio_x402 import PIIFilter, PROVISIONING_ENTITIES

filt = PIIFilter(
    entities=list(PROVISIONING_ENTITIES),
    redaction_template="<{entity_type}>",
)

clean, entities = filt.scan_and_redact(
    "ml training workload over CONFIDENTIAL data: SELECT email FROM customers"
)
# clean:
# "<WORKLOAD_CLASS> workload over <DATA_CLASSIFICATION> data: <QUERY_PATTERN>"
```

---

## Exceptions

| Exception | Raised when |
|-----------|-------------|
| `PIIBlockedError` | PII detected in metadata and `pii_action="block"` |
| `PolicyViolationError` | Payment amount or aggregate spend exceeds configured limit |
| `ReplayDetectedError` | Payment fingerprint matches a recent transaction |
| `X402PaymentError` | Upstream payment signing or network error |
| `MPADeniedError` | Multi-party authorization required but not enough approvals received |
| `MPATimeoutError` | Multi-party authorization webhook approval timed out |

All exceptions are importable from `presidio_x402`.

---

## Research Artifacts

| Artifact | Location | Description |
|---|---|---|
| Synthetic corpus | [`vstantch/x402-pii-corpus`](https://huggingface.co/datasets/vstantch/x402-pii-corpus) on Hugging Face · `corpus/` | 2,000 labelled x402 metadata triples; generator (`generate.py`, `seed=42`) + metadata (`corpus_meta.json`); raw JSONL reproducible from seed |
| Precision/recall sweep | `experiments/` | 42-configuration grid search (`run_sweep.py`); latency benchmark (`run_latency.py`) |
| Dune Analytics queries | `dune/` | 6 Trino SQL queries used to characterise the live x402 ecosystem (20 projects, 96 wallets, 11 chains, ≥79M transactions); see `dune/README.md` |

---

## Roadmap

| Version | Milestone |
|---------|-----------|
| v0.1.0 | PII redaction + spending policy + replay detection |
| v0.2.0 | Synthetic corpus + 42-configuration precision/recall sweep, LangChain/CrewAI adapters, compliance report · [arXiv:2604.11430](https://arxiv.org/abs/2604.11430) |
| v0.2.1 | Live ecosystem characterisation via Dune Analytics (20 projects, 96 wallets, 11 chains, ≥79M transactions); IEEE S&P magazine article submitted; IEEE TIFS paper under review · Corpus: [`v0.2.1/dataport/`](v0.2.1/dataport/), [Hugging Face](https://huggingface.co/datasets/vstantch/x402-pii-corpus), [IEEE DataPort (doi:10.21227/kpsz-nq73)](https://doi.org/10.21227/kpsz-nq73) |
| v0.3.0 | **Multi-party authorization** (`mpa.py`: n-of-m, webhook + crypto modes) · **Policy-as-code** JSON Schema (IETF draft candidate) · **Prometheus metrics** exporter · Kubernetes Helm chart + Docker image · SOC2 reference architecture |
| v0.4.0 | **Screening API launch** — hosted [`screen.presidio-group.eu`](https://screen.presidio-group.eu) free tier (regex mode, 100 req/day) · `ScreeningClient` + `remote_screening=True` mode · per-origin `pay_to` allowlist (chain-06 mitigation) · audit-cycle hardening (F-A/B 2026-05-03, F-C/D/E 2026-05-10, F1/F2/F3 2026-05-17); see [`CHANGELOG.md`](CHANGELOG.md) |
| v0.5.0 | **OEM embed kit** — rail-agnostic `ScreeningPipeline` core + `bindings/x402` layer (`PaymentProtocolBinding` protocol, hedge against rail fragmentation: ACP/Tempo, AP2) · [SEMVER.md](SEMVER.md) stability guarantees · partner conformance suite (`python -m presidio_x402.conformance`) · CDP/LangChain/CrewAI quickstarts · SBOM in CI · freshness-bound MPA countersignatures (F-8) |
| v0.6.0 | **Production hardening + evidence substrate** — multi-tenant replay namespaces · enterprise audit sinks (S3 / Splunk / Datadog) · signed `evidence-ref@1` verification · SLSA/OIDC release provenance · digest-pinned Docker base + hash-pinned spaCy model · latency SLO and all-matrix coverage CI gates · OTel spans · policy hot-reload · startup key gates · human-pentest retest closure |
| v0.7.0 | **SLO payment broker (library)** — x402 micropayments as runtime infrastructure bids: `SLOPaymentBroker` + `SLOPaymentPolicy` + evidence-anchored `ArchTranslucencyAdapter` + provisioning PII entities; cross-repo validated against `presidio-hardened-arch-translucency`. cs.DC preprint + empirical eval tracked separately |
| v0.8.0 | PII completeness + supply-chain hardening (library) — `nlp` mode is now a structural superset of `regex` (no structured-identifier misses) · composed-envelope `screen_ref` leg · `action_ref` byte-determinism (NFC + non-empty entity sets) · URL-redacted log hygiene · OpenSSF Scorecard workflow/badge + SLSA Build L3 provenance · independent multi-round security audit cleared |
| **v0.9.0** | **Proof-carrying x402 evidence** — `capability-grant@1` attenuable spending grants + opt-in `payment-decision@1` decision refs with raw-offer digest binding, fail-closed offline verification, capability-chain provenance linkage, and PII-free emitted records — **latest release** |
| Future | Deferred #23 prompt-injection / agent-bound response scanning threat-model work |

See [PRESIDIO-REQ.md](PRESIDIO-REQ.md) for full deliberation and rationale.

---

## License

MIT

---

## SDLC

This repository is developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
