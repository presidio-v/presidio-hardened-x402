"""CrewAI adapter for presidio-hardened-x402.

Provides a drop-in :class:`HardenedX402CrewTool` that wraps
:class:`~presidio_x402.gateway.HardenedX402Client` as a CrewAI
``BaseTool``, enabling CrewAI agents to make x402 payments with
full PII redaction, spending policy enforcement, and replay detection.

Requires ``crewai>=0.28.0``.

Usage::

    from presidio_x402.adapters.crewai import HardenedX402CrewTool

    tool = HardenedX402CrewTool(
        payment_signer=my_signer,
        policy={"max_per_call_usd": 0.05, "daily_limit_usd": 2.0},
        agent_id="crew-agent-1",
    )

    # Use in any CrewAI agent:
    agent = Agent(role="researcher", tools=[tool], ...)
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from ..gateway import HardenedX402Client

if TYPE_CHECKING:
    from .._types import AuditWriter, PaymentSigner

try:  # pragma: no cover
    from crewai.tools import BaseTool as CrewBaseTool
    from pydantic import BaseModel
    from pydantic import Field as PydanticField

    class _X402Input(BaseModel):
        url: str = PydanticField(description="The resource URL to fetch via x402 payment")
        method: str = PydanticField(default="GET", description="HTTP method (GET or POST)")

    class HardenedX402CrewTool(CrewBaseTool):
        """CrewAI tool that fetches x402-gated resources with Presidio security controls.

        Wraps HardenedX402Client so CrewAI agents can call x402-protected APIs
        while automatically enforcing PII redaction, spending limits, and replay detection.

        Note: CrewAI tools are synchronous by default. This tool runs the async
        client in the running event loop (if available) or creates a temporary one.
        """

        name: str = "hardened_x402_fetch"
        description: str = (
            "Fetch a resource that requires an x402 micropayment. "
            "Handles payment signing with PII protection and spending policy enforcement. "
            "Input: the resource URL."
        )
        args_schema: type[BaseModel] = _X402Input

        _client: HardenedX402Client

        class Config:
            arbitrary_types_allowed = True

        def __init__(
            self,
            payment_signer: PaymentSigner | Any,
            *,
            policy: dict | None = None,
            pii_mode: str = "regex",
            pii_entities: list[str] | None = None,
            pii_action: str = "redact",
            replay_ttl: int = 300,
            redis_url: str | None = None,
            audit_writer: AuditWriter | None = None,
            agent_id: str | None = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(**kwargs)
            object.__setattr__(
                self,
                "_client",
                HardenedX402Client(
                    payment_signer=payment_signer,
                    policy=policy,
                    pii_mode=pii_mode,
                    pii_entities=pii_entities,
                    pii_action=pii_action,
                    replay_ttl=replay_ttl,
                    redis_url=redis_url,
                    audit_writer=audit_writer,
                    agent_id=agent_id,
                ),
            )

        def _run(self, url: str, method: str = "GET") -> str:
            """Fetch *url* via x402 payment (synchronous wrapper for async client)."""
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            coro = self._client._request(method.upper(), url)
            if loop and loop.is_running():
                # Running inside an event loop (e.g., Jupyter, async CrewAI runner)
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(asyncio.run, coro)
                    response = future.result()
            else:
                response = asyncio.run(coro)
            return response.text

except ImportError:
    class HardenedX402CrewTool:  # type: ignore[no-redef]
        """Stub raised when crewai is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "CrewAI adapter requires: pip install crewai>=0.28.0"
            )
