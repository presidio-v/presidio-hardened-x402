# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Conformance checks — see package docstring. No network; httpx.MockTransport only."""

from __future__ import annotations

import asyncio
import json
import tempfile
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from collections.abc import Callable

CHECKS: list[tuple[str, Callable[[], None]]] = []


class ConformanceFailureError(AssertionError):
    """Raised when a partner conformance invariant fails."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceFailureError(message)


def check(name: str) -> Callable[[Callable[[], None]], Callable[[], None]]:
    def register(fn: Callable[[], None]) -> Callable[[], None]:
        CHECKS.append((name, fn))
        return fn

    return register


# ---------------------------------------------------------------------------
# Helpers (no network: a scripted httpx.MockTransport plays the 402 server)
# ---------------------------------------------------------------------------

_OFFER = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "0.01",
                "resource": "https://conformance.invalid/v1/data",
                "description": "conformance probe for pii@example.com",
                "payTo": "0x00000000000000000000000000000000c0ffee00",
                "requiredDeadlineSeconds": 300,
            }
        ]
    }
)


def _scripted_transport(responses: list[httpx.Response]) -> httpx.MockTransport:
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        if not queue:
            raise AssertionError("conformance transport exhausted")
        return queue.pop(0)

    return httpx.MockTransport(handler)


def _client(responses: list[httpx.Response], **kwargs):
    from presidio_x402 import HardenedX402Client
    from presidio_x402._types import PaymentDetails, PaymentResponse

    async def signer(details: PaymentDetails) -> PaymentResponse:
        return PaymentResponse(token="conformance-token", details=details)  # noqa: S106

    kwargs.setdefault("payment_signer", signer)
    httpx_client = httpx.AsyncClient(transport=_scripted_transport(responses))
    return HardenedX402Client(httpx_client=httpx_client, **kwargs)


def _run(coro):
    return asyncio.run(coro)


def _402(offer: str = _OFFER) -> httpx.Response:
    return httpx.Response(402, headers={"X-PAYMENT": offer})


def _ok() -> httpx.Response:
    return httpx.Response(200, text="paid")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@check("public API surface importable")
def check_api_surface() -> None:
    import presidio_x402

    missing = [name for name in presidio_x402.__all__ if not hasattr(presidio_x402, name)]
    _require(not missing, f"__all__ names missing from package: {missing}")


@check("PII redacted before signer sees payment details")
def check_pii_redaction() -> None:
    from presidio_x402._types import PaymentDetails, PaymentResponse

    seen: list[str] = []

    async def capturing_signer(details: PaymentDetails) -> PaymentResponse:
        seen.append(details.description)
        return PaymentResponse(token="t", details=details)  # noqa: S106

    async def flow() -> None:
        client = _client([_402(), _ok()], payment_signer=capturing_signer)
        async with client:
            await client.get("https://conformance.invalid/v1/data")

    _run(flow())
    _require(bool(seen), "signer was never invoked")
    _require("pii@example.com" not in seen[0], "raw PII reached the signer")


@check("pii_action=block fails closed on PII")
def check_pii_block() -> None:
    from presidio_x402.exceptions import PIIBlockedError

    async def flow() -> None:
        client = _client([_402()], pii_action="block")
        async with client:
            try:
                await client.get("https://conformance.invalid/v1/data")
            except PIIBlockedError:
                return
            raise AssertionError("PII did not block the payment")

    _run(flow())


@check("spending policy blocks over-limit payment before signing")
def check_policy_block() -> None:
    from presidio_x402.exceptions import PolicyViolationError

    async def flow() -> None:
        client = _client([_402()], policy={"max_per_call_usd": 0.001})
        async with client:
            try:
                await client.get("https://conformance.invalid/v1/data")
            except PolicyViolationError:
                return
            raise AssertionError("policy did not block the payment")

    _run(flow())


@check("replay blocked; signer failure rolls back budget + fingerprint")
def check_replay_and_rollback() -> None:
    from presidio_x402._types import PaymentDetails, PaymentResponse
    from presidio_x402.exceptions import ReplayDetectedError, X402PaymentError

    async def replay_flow() -> None:
        client = _client([_402(), _ok(), _402()])
        async with client:
            await client.get("https://conformance.invalid/v1/data")
            try:
                await client.get("https://conformance.invalid/v1/data")
            except ReplayDetectedError:
                return
            raise AssertionError("identical payment was not detected as replay")

    _run(replay_flow())

    fail_once = {"n": 0}

    async def flaky_signer(details: PaymentDetails) -> PaymentResponse:
        fail_once["n"] += 1
        if fail_once["n"] == 1:
            raise RuntimeError("signer outage")
        return PaymentResponse(token="t", details=details)  # noqa: S106

    async def rollback_flow() -> None:
        client = _client(
            [_402(), _402(), _ok()],
            payment_signer=flaky_signer,
            policy={"daily_limit_usd": 0.01},
        )
        async with client:
            try:
                await client.get("https://conformance.invalid/v1/data")
            except X402PaymentError:
                pass
            else:
                raise AssertionError("signer failure did not surface as payment error")
            # Budget and fingerprint must be free again — the retry succeeds.
            await client.get("https://conformance.invalid/v1/data")

    _run(rollback_flow())


@check("audit log written; HMAC chain verifies; tampering detected")
def check_audit_chain() -> None:
    from presidio_x402 import ComplianceReport, FileAuditWriter

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"

        async def flow() -> None:
            client = _client([_402(), _ok()], audit_writer=FileAuditWriter(str(path)))
            async with client:
                await client.get("https://conformance.invalid/v1/data")

        _run(flow())
        _require(path.exists() and path.stat().st_size > 0, "no audit records written")
        report = ComplianceReport.from_jsonl(path)
        _require(
            report.chain_ok,
            f"audit chain failed on untampered log: {report.chain_warnings}",
        )

        # Tamper with the first record — the chain must flag it.
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["amount_usd"] = 99999.0
        lines[0] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tampered = ComplianceReport.from_jsonl(path)
        _require(not tampered.chain_ok, "tampered audit log passed chain verification")


@check("x402 binding parses spec offers and rejects malformed offers fail-closed")
def check_binding() -> None:
    from presidio_x402 import X402Binding
    from presidio_x402.exceptions import X402PaymentError

    binding = X402Binding()
    details = binding.parse_payment_required(_OFFER)
    _require(
        details.amount == "0.01" and details.network == "base-sepolia",
        "valid x402 offer parsed to unexpected payment details",
    )
    for bad in ("not json", "[]", '{"accepts": []}', '{"accepts": ["exact"]}'):
        try:
            binding.parse_payment_required(bad)
        except X402PaymentError:
            continue
        raise AssertionError(f"malformed offer accepted: {bad!r}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all() -> int:
    """Run every conformance check. Returns the number of failures."""
    import presidio_x402

    print(f"presidio-hardened-x402 conformance suite — library {presidio_x402.__version__}")
    failures = 0
    for name, fn in CHECKS:
        try:
            fn()
        except Exception:
            failures += 1
            print(f"FAIL  {name}")
            traceback.print_exc()
        else:
            print(f"PASS  {name}")
    print(f"\n{len(CHECKS) - failures}/{len(CHECKS)} checks passed")
    return failures


def main() -> int:
    return 1 if run_all() else 0
