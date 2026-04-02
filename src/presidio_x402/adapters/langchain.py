"""LangChain adapter for presidio-hardened-x402.

Provides a drop-in :class:`HardenedX402Tool` that wraps
:class:`~presidio_x402.gateway.HardenedX402Client` as a LangChain
``BaseTool``, enabling LangChain agents to make x402 payments with
full PII redaction, spending policy enforcement, and replay detection.

Requires ``langchain-core>=0.1.0``.

Usage::

    from presidio_x402.adapters.langchain import HardenedX402Tool

    tool = HardenedX402Tool(
        payment_signer=my_signer,
        policy={"max_per_call_usd": 0.05, "daily_limit_usd": 2.0},
    )

    # Use in any LangChain agent:
    agent = initialize_agent(tools=[tool], ...)

    # Or call directly:
    result = await tool.arun("https://api.example.com/data")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..gateway import HardenedX402Client

if TYPE_CHECKING:
    from .._types import AuditWriter, PaymentSigner

try:  # pragma: no cover
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel
    from pydantic import Field as PydanticField

    class _X402Input(BaseModel):
        url: str = PydanticField(description="The resource URL to fetch via x402 payment")
        method: str = PydanticField(default="GET", description="HTTP method")

    class HardenedX402Tool(BaseTool):
        """LangChain tool that fetches x402-gated resources with Presidio security controls.

        All payment metadata is scanned for PII before signing; spending policy
        and replay detection are enforced on every call.
        """

        name: str = "hardened_x402_fetch"
        description: str = (
            "Fetch a resource that requires an x402 micropayment. "
            "Automatically handles payment signing, PII protection, and spending limits. "
            "Input: the resource URL to fetch."
        )
        args_schema: type[BaseModel] = _X402Input

        # HardenedX402Client config — set at construction time
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
            raise NotImplementedError(
                "HardenedX402Tool is async-only. Use arun() or an async agent executor."
            )

        async def _arun(self, url: str, method: str = "GET") -> str:
            """Fetch *url* via x402 payment with all security controls applied."""
            response = await self._client._request(method.upper(), url)
            return response.text

        async def aclose(self) -> None:
            """Close the underlying httpx client."""
            await self._client._http.aclose()

except ImportError:
    class HardenedX402Tool:  # type: ignore[no-redef]
        """Stub raised when langchain-core is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "LangChain adapter requires: pip install langchain-core>=0.1.0"
            )
