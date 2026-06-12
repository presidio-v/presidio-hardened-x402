# Quickstart: LangChain agent + presidio-hardened-x402

Give a LangChain agent the ability to pay for x402-gated resources with the full screening pipeline (PII redaction, spending limits, replay protection, audit) applied to every payment the agent decides to make.

## Install

```bash
pip install "presidio-hardened-x402[langchain]>=0.5,<0.6"
```

The extra enforces `langchain-core>=1.3.3` (CVE-2026-44843 floor — see `_KNOWN_VULNERABLE` in the package).

## Use

```python
from presidio_x402.adapters.langchain import HardenedX402Tool
from presidio_x402 import FileAuditWriter

tool = HardenedX402Tool(
    payment_signer=my_signer,           # your PaymentSigner (see CDP quickstart)
    policy={"max_per_call_usd": 0.05, "daily_limit_usd": 2.0},
    pii_action="redact",
    audit_writer=FileAuditWriter("audit/agent-payments.jsonl"),
    agent_id="langchain-researcher",
)

# Any async LangChain agent executor:
agent = create_react_agent(model, tools=[tool])
result = await agent.ainvoke({"messages": [("user", "Fetch the paid dataset and summarise it")]})

# Or call the tool directly:
text = await tool.arun("https://api.example.com/paid-resource")
```

The tool is async-only (`arun`); the sync `run` path raises by design — payments should never block an event loop thread where timeouts and cancellation are invisible.

## Why this matters for agents specifically

The agent chooses *what* to pay for at runtime; you keep control of *how much, to whom, and with what data*. The agent cannot exceed `daily_limit_usd`, repeat a payment (fingerprint TTL), leak user PII through payment metadata it composes, or pay an unexpected wallet when `trusted_wallets` is set. Every attempt — allowed or blocked — lands in the HMAC-chained audit log keyed by `agent_id`.

## Production checklist

Same as the [CDP quickstart](coinbase-cdp.md): chain/fingerprint env keys, version pin, conformance suite in CI.
