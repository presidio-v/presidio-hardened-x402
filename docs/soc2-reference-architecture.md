# SOC 2 + x402 Compliance Reference Architecture

**presidio-hardened-x402 v0.3.0**

This guide maps the four security controls provided by `presidio-hardened-x402`
to SOC 2 Trust Services Criteria (TSC) and GDPR obligations, and describes
deployment patterns for environments subject to these requirements.

---

## Controls → Compliance Mapping

| Control | Module | SOC 2 TSC | GDPR Article |
|---------|--------|-----------|--------------|
| PII redaction before payment | `pii_filter.py` | CC6.1, CC6.7, P3.1, P4.1 | Art. 5(1)(c) data minimisation; Art. 25 privacy by design |
| Spending policy enforcement | `policy_engine.py` | CC5.2, CC6.3, A1.1 | — |
| Replay / duplicate detection | `replay_guard.py` | CC7.2, CC7.4 | — |
| Tamper-evident audit log | `audit_log.py` | CC4.1, CC7.2, CC7.3 | Art. 30 records of processing; Art. 5(2) accountability |
| Multi-party authorization | `mpa.py` | CC6.3, CC6.6, CC9.1 | Art. 32 security of processing |
| Prometheus metrics export | `metrics.py` | A1.2, CC7.2 | — |

---

## Architecture Patterns

### Pattern 1 — Library embedded in agent (simplest)

```
┌───────────────────────────────────┐
│  Autonomous Agent Process         │
│                                   │
│  ┌─────────────────────────────┐  │
│  │   HardenedX402Client        │  │
│  │   ├── PIIFilter             │  │
│  │   ├── PolicyEngine          │  │
│  │   ├── ReplayGuard           │  │
│  │   ├── MPAEngine (optional)  │  │
│  │   └── AuditLog → file/stdout│  │
│  └─────────────────────────────┘  │
└───────────────────────────────────┘
```

**Audit trail**: JSON-L written to a file or stdout, captured by the container
log driver. Recommended: ship logs to a SIEM (Splunk, Datadog, CloudWatch).

**SOC 2 consideration**: HMAC-chained entries provide intra-process tamper
evidence. Cross-session chain continuity requires persisting the chain key
(see `audit_log.py` module docstring).

---

### Pattern 2 — Kubernetes sidecar (recommended for production)

```
┌──────────────────────────────────────────────────────┐
│  Pod                                                  │
│                                                       │
│  ┌─────────────────┐   localhost   ┌───────────────┐ │
│  │  Agent container│ ──────────── ▶│ x402-sidecar  │ │
│  │  (your code)    │               │ :8080         │ │
│  └─────────────────┘               │  /health      │ │
│                                    │  /metrics     │ │
│                                    └───────┬───────┘ │
└────────────────────────────────────────────┼─────────┘
                                             │ Prometheus scrape
                                      ┌──────▼──────┐
                                      │ Prometheus  │
                                      │ + Grafana   │
                                      └─────────────┘
```

Deploy with the bundled Helm chart:

```bash
helm install x402-sidecar ./helm \
  --set x402.agentId=my-agent \
  --set x402.maxPerCallUsd=0.10 \
  --set x402.dailyLimitUsd=5.00 \
  --set serviceMonitor.enabled=true
```

---

### Pattern 3 — MPA for high-value payments

For payments above a defined threshold (e.g., $1.00 USD), require two
of three human or system approvers before the payment is executed:

```
Agent
  │
  ├─ amount < $1.00 ──▶ auto-approved (policy + replay checks only)
  │
  └─ amount ≥ $1.00 ──▶ MPAEngine
                          ├─ POST https://approvals.internal/alice
                          ├─ POST https://approvals.internal/bob  
                          └─ POST https://approvals.internal/charlie
                                     ↓ (2 of 3 approve)
                                HardenedX402Client signs + submits
```

```python
from presidio_x402 import HardenedX402Client
from presidio_x402.mpa import MPAConfig, MPAApproverConfig, MPAEngine

mpa = MPAEngine(MPAConfig(
    threshold=2,
    min_amount_usd=1.00,
    timeout_seconds=30,
    approvers=[
        MPAApproverConfig("alice", mode="webhook",
                          webhook_url="https://approvals.internal/alice"),
        MPAApproverConfig("bob", mode="webhook",
                          webhook_url="https://approvals.internal/bob"),
        MPAApproverConfig("charlie", mode="webhook",
                          webhook_url="https://approvals.internal/charlie"),
    ],
))

client = HardenedX402Client(payment_signer=signer, mpa_engine=mpa)
```

**SOC 2 TSC CC6.3**: Separation of duties enforced via MPA threshold.
**SOC 2 TSC CC9.1**: High-value transactions require explicit authorization.

---

## Audit Log Retention

For SOC 2 Type II, retain audit logs for **at least 12 months**, with 3 months
immediately accessible. Recommended setup:

| Environment | Writer | Destination |
|-------------|--------|-------------|
| Development | `StreamAuditWriter(sys.stdout)` | Container stdout |
| Staging | `FileAuditWriter("/var/log/x402-audit.jsonl")` | Volume mount |
| Production | `FileAuditWriter` + log shipper | S3 / GCS / SIEM |

HMAC chain key persistence (required for cross-session tamper evidence):

```python
import os
import secrets

# Load or generate chain key from a restricted file
chain_key_path = "/run/secrets/x402_chain_key"
if os.path.exists(chain_key_path):
    with open(chain_key_path, "rb") as f:
        chain_key = f.read()
else:
    chain_key = secrets.token_bytes(32)
    with open(chain_key_path, "wb") as f:
        f.write(chain_key)
```

---

## GDPR Obligations

### Article 5(1)(c) — Data minimisation

`PIIFilter` in `"block"` mode prevents any PII from being transmitted in
payment metadata. In `"redact"` mode, PII is replaced with entity-type tokens
(e.g., `<EMAIL_ADDRESS>`) before transmission to the payment server or
blockchain facilitator.

**Recommended configuration for GDPR:**

```python
client = HardenedX402Client(
    payment_signer=signer,
    pii_mode="nlp",     # full NER for maximum coverage
    pii_action="block", # never transmit PII, even as metadata
)
```

### Article 30 — Records of processing

The `ComplianceReport` module (`compliance_report.py`) generates SOC2/GDPR-friendly
reports from JSON-L audit logs:

```python
from presidio_x402 import ComplianceReport

report = ComplianceReport.from_jsonl("/var/log/x402-audit.jsonl")
report.generate(output_path="compliance-report-2026-Q2.json")
```

---

## Secret Management

- **Payment signing keys**: Never pass key material to `HardenedX402Client` directly.
  Implement `PaymentSigner` to call a secrets manager (HashiCorp Vault, AWS KMS,
  GCP Cloud KMS) or hardware wallet (Ledger, Trezor via HID).

- **MPA shared secrets** (crypto mode): Inject via Kubernetes Secrets or an
  init container that fetches from Vault. Do not embed in `values.yaml`.

- **Redis connection string**: Use a Kubernetes Secret and reference via
  `secretKeyRef`, not a plain environment variable.

---

## Recommended SOC 2 Evidence Collection

| Evidence | Source | Frequency |
|----------|--------|-----------|
| Payment audit log (JSON-L) | `AuditLog` → SIEM | Continuous |
| Policy configuration snapshots | GitOps / `values.yaml` | Per deploy |
| PII detection summary report | `ComplianceReport` | Monthly |
| Prometheus metrics | Grafana dashboard screenshot | Quarterly |
| Dependency audit results | `pip-audit` CI step | Per build |
| MPA approval records | Approver webhook logs | Continuous |
