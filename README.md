# presidio-hardened-x402

Security middleware for the [x402 payment protocol](https://www.x402.org/).

Intercepts x402 payment requests **before transmission to servers and facilitators** to enforce:

- **PII redaction** — Presidio-based detection and redaction of personal data (emails, names, SSNs, credit cards, etc.) from payment metadata fields before they are sent to the payment server or facilitator API
- **Spending policy** — per-agent, per-endpoint, and per-time-window budget limits that block or throttle payments before execution
- **Replay detection** — HMAC-SHA256 fingerprinting of canonical payment fields to prevent duplicate and replayed payments
- **Audit logging** — HMAC-chained JSON-L audit trail for every payment attempt (including blocked ones)
- **Multi-party authorization** — n-of-m approval requirement for high-value payments, via webhook or HMAC-SHA256 cryptographic countersignature modes *(v0.3.0)*
- **Prometheus metrics** — structured telemetry for every security control activation *(v0.3.0)*

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
| Synthetic corpus | `corpus/` | 2,000 labelled x402 metadata triples; generator (`generate.py`, `seed=42`) + metadata (`corpus_meta.json`); raw JSONL reproducible from seed |
| Precision/recall sweep | `experiments/` | 42-configuration grid search (`run_sweep.py`); latency benchmark (`run_latency.py`) |
| Dune Analytics queries | `dune/` | 6 Trino SQL queries used to characterise the live x402 ecosystem (20 projects, 96 wallets, 11 chains, ≥79M transactions); see `dune/README.md` |

---

## Roadmap

| Version | Milestone |
|---------|-----------|
| v0.1.0 | PII redaction + spending policy + replay detection |
| v0.2.0 | Synthetic corpus + 42-configuration precision/recall sweep, LangChain/CrewAI adapters, compliance report · [arXiv preprint (pending)](https://arxiv.org/abs/2504.xxxxx) |
| v0.2.1 | Live ecosystem characterisation via Dune Analytics (20 projects, 96 wallets, 11 chains, ≥79M transactions); IEEE S&P magazine article submitted; IEEE TIFS paper under review |
| **v0.3.0** | **Multi-party authorization** (`mpa.py`: n-of-m, webhook + crypto modes) · **Policy-as-code** JSON Schema (IETF draft candidate) · **Prometheus metrics** exporter · Kubernetes Helm chart + Docker image · SOC2 reference architecture — **current** |
| v0.4.0 | Production hardening: security audit, OpenTelemetry spans, policy hot-reload, operator runbook |
| v0.5.0 | **SLO payment broker** — x402 micropayments as runtime infrastructure bids; `presidio-hardened-arch-translucency` integration |

See [PRESIDIO-REQ.md](PRESIDIO-REQ.md) for full deliberation and rationale.

---

## License

MIT
