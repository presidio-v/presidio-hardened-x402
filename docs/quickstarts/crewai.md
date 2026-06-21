# Quickstart: CrewAI crew + presidio-hardened-x402

Let CrewAI agents purchase x402-gated resources under centrally enforced spending, PII, and replay controls — one shared budget and audit trail per crew, or one per agent.

## Install

```bash
pip install "presidio-hardened-x402>=0.5,<0.6"
# Install CrewAI separately only after your own dependency audit/risk acceptance.
pip install "crewai>=1.14.7"
```

The `presidio-hardened-x402[crewai]` extra is intentionally empty while CrewAI's
current dependency graph pulls `chromadb==1.1.1` with CVE-2026-45829 and no fixed
version reported by `pip-audit`.

## Use

```python
from presidio_x402.adapters.crewai import HardenedX402CrewTool
from presidio_x402 import FileAuditWriter
from crewai import Agent, Crew, Task

pay_tool = HardenedX402CrewTool(
    payment_signer=my_signer,           # your PaymentSigner (see CDP quickstart)
    policy={
        "max_per_call_usd": 0.05,
        "daily_limit_usd": 2.0,
        "per_endpoint": {"https://api.example.com": 1.0},
    },
    pii_action="block",                 # crews compose metadata from task context —
                                        # block rather than redact if it may carry user data
    audit_writer=FileAuditWriter("audit/crew-payments.jsonl"),
    agent_id="research-crew",
)

researcher = Agent(
    role="Researcher",
    goal="Gather paid market data within budget",
    tools=[pay_tool],
)

crew = Crew(agents=[researcher], tasks=[Task(description="...", agent=researcher)])
result = await crew.kickoff_async()
```

## Budget topology choices

- **One tool instance shared across agents** → one budget, one replay scope, one audit stream for the whole crew (the example above).
- **One instance per agent** (distinct `agent_id`) → per-agent budgets and attributable audit trails; replay protection stays per-instance unless you set `PRESIDIO_X402_FINGERPRINT_KEY` and `redis_url` for cross-process scope.

## Production checklist

Same as the [CDP quickstart](coinbase-cdp.md): chain/fingerprint env keys, version pin `>=0.5,<0.6`, `python -m presidio_x402.conformance` in CI.
