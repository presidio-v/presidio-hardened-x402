# Quickstart: Coinbase CDP wallet + presidio-hardened-x402

Embed the screening pipeline in front of a CDP-managed wallet so every x402 micropayment is PII-screened, policy-limited, replay-protected, and audited **before** the CDP signer is invoked.

## Install

```bash
pip install "presidio-hardened-x402>=0.5,<0.6" cdp-sdk
```

## Wire the CDP signer

The library never touches your keys — it calls your `PaymentSigner` with already-screened `PaymentDetails`. Adapt the token construction to the x402 facilitator you use; the screening behaviour is identical regardless.

```python
from presidio_x402 import HardenedX402Client, FileAuditWriter
from presidio_x402._types import PaymentDetails, PaymentResponse

# --- your CDP wallet setup (see CDP docs for auth) ---
from cdp import CdpClient  # CDP SDK

cdp = CdpClient()  # reads CDP_API_KEY_ID / CDP_API_KEY_SECRET / CDP_WALLET_SECRET
account = await cdp.evm.get_or_create_account(name="agent-payments")

async def cdp_signer(details: PaymentDetails) -> PaymentResponse:
    """Sign the (already screened/redacted) payment with the CDP account.

    `details` has passed all four controls: PII is redacted, the spend is
    within policy, the fingerprint is fresh. Build the x402 payment token
    for your facilitator here (EIP-712 typed-data signature).
    """
    signature = await account.sign_typed_data(
        # typed-data payload per your x402 facilitator's scheme, built from:
        # details.pay_to, details.amount, details.currency,
        # details.network, details.deadline_seconds
        ...
    )
    return PaymentResponse(token=signature, details=details)

client = HardenedX402Client(
    payment_signer=cdp_signer,
    policy={"max_per_call_usd": 0.10, "daily_limit_usd": 5.0},
    pii_action="redact",
    trusted_wallets={"https://api.example.com": {"0xKnownVendorWallet..."}},
    audit_writer=FileAuditWriter("audit/payments.jsonl"),
    agent_id="agent-payments",
)

response = await client.get("https://api.example.com/paid-resource")
```

## What the embed gives you

The 402 → screen → sign → retry loop is fully handled. A payment that fails any control raises (`PIIBlockedError`, `PolicyViolationError`, `ReplayDetectedError`, `X402PaymentError`) before `cdp_signer` runs — fail-closed, with the attempt in the audit log. A CDP outage mid-signing rolls back the budget and replay slot automatically.

## Production checklist

- Set `PRESIDIO_X402_CHAIN_KEY` and `PRESIDIO_X402_FINGERPRINT_KEY` (32-byte hex) — required for cross-restart audit-chain integrity and cross-replica replay detection.
- Pin `>=0.5,<0.6` and run `python -m presidio_x402.conformance` in your CI (see [SEMVER.md](../../SEMVER.md)).
- Use `trusted_wallets` for every origin you pay regularly — it defeats pay-to substitution by a compromised server.
