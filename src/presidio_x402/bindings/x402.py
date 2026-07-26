# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""x402 protocol binding — HTTP 402 + ``X-PAYMENT`` header (x402 spec v1).

This module owns every x402-specific assumption that used to live in the
gateway: the payment header name, the supported scheme, and the parsing of the
402 payment-offer JSON into the rail-agnostic
:class:`~presidio_x402._types.PaymentDetails`. The screening core never sees
any of these details (v0.5.0 binding-layer refactor; session-3 T2).

Parsing hardening notes (F-04 2026-06-03, F1 2026-06-07) are preserved verbatim
from the pre-refactor gateway implementation — the bytes and error behaviour
are unchanged.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import logging
from datetime import datetime, timezone

from .._types import PaymentDetails, SettlementReceipt
from ..exceptions import X402PaymentError

logger = logging.getLogger("presidio_x402.bindings.x402")

# Header name per x402 spec.
HEADER_PAYMENT = "X-PAYMENT"

#: Headers a resource server may echo the settlement outcome back on, most
#: current first: ``PAYMENT-RESPONSE`` is the Coinbase x402 v2 spelling,
#: ``X-PAYMENT-RESPONSE`` the v1 one, and ``X-PAYMENT-RECEIPT`` the name this
#: library's own flow documentation has used since v0.1.0. All three carry the
#: same payload shape, so all three are accepted on the read path (Postel on the
#: receipt channel only — the *offer* channel stays strict).
SETTLEMENT_RECEIPT_HEADERS = ("PAYMENT-RESPONSE", "X-PAYMENT-RESPONSE", "X-PAYMENT-RECEIPT")

#: Max byte length of a settlement-receipt header before decoding. Same rationale
#: as :data:`PAYMENT_HEADER_MAX_BYTES`, an order of magnitude tighter: the
#: settle response is four short fields.
SETTLEMENT_RECEIPT_MAX_BYTES = 8_192

#: x402 rail network names → CAIP-2 chain ids. Deliberately small and explicit:
#: an unmapped network yields ``chain=None`` (the raw name is still recorded) so
#: the operator supplies the chain id rather than the library guessing one. A
#: wrong chain id would silently correlate a decision to a transaction on another
#: chain, which is worse than no chain id at all. Values already in CAIP-2 form
#: (x402 v2 uses them natively) pass through unchanged.
_CAIP2_BY_NETWORK = {
    "base": "eip155:8453",
    "base-mainnet": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "ethereum": "eip155:1",
    "ethereum-mainnet": "eip155:1",
    "ethereum-sepolia": "eip155:11155111",
    "sepolia": "eip155:11155111",
    "polygon": "eip155:137",
    "polygon-mainnet": "eip155:137",
    "polygon-amoy": "eip155:80002",
    "avalanche": "eip155:43114",
    "avalanche-fuji": "eip155:43113",
    "iotex": "eip155:4689",
}

# Supported x402 scheme (since v0.1.0).
SUPPORTED_SCHEME = "exact"

# Max byte length of the raw X-PAYMENT header before JSON parsing. A malicious
# 402 server could otherwise force the client to allocate arbitrary memory in
# json.loads before any security control fires. 64 KiB is multiple orders of
# magnitude above any legitimate x402 accepts payload.
PAYMENT_HEADER_MAX_BYTES = 65_536


def parse_402_header(header_value: str) -> PaymentDetails:
    """Parse the ``X-PAYMENT`` header from a 402 response.

    Expected JSON structure (x402 spec v1)::

        {
          "accepts": [{
            "scheme": "exact",
            "network": "base-mainnet",
            "maxAmountRequired": "0.01",
            "resource": "https://...",
            "description": "...",
            "mimeType": "application/json",
            "payTo": "0x...",
            "requiredDeadlineSeconds": 300,
            "extra": {}
          }]
        }
    """
    if len(header_value.encode("utf-8")) > PAYMENT_HEADER_MAX_BYTES:
        raise X402PaymentError(
            f"X-PAYMENT header exceeds maximum length of {PAYMENT_HEADER_MAX_BYTES} bytes"
        )
    try:
        data = json.loads(header_value)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        # Also catch RecursionError: deeply nested JSON (small byte payload, under
        # the size cap above) makes json.loads recurse to the interpreter limit;
        # without this it would propagate uncaught and bypass the sanitised audit
        # path (F-04, 2026-06-03). Never embed the raw JSON (which may carry
        # wallet/PII fragments) in the message; the parse-error cause itself
        # carries only position info, so it is kept on __cause__ for debugging.
        raise X402PaymentError("Invalid X-PAYMENT header JSON") from exc

    # The top level must be a JSON object. A valid-but-non-object payload (a
    # bare array/number/string, e.g. a moderately nested list that parses before
    # the recursion limit) would otherwise reach data.get() and raise an uncaught
    # AttributeError outside the sanitised audit path (F-04, 2026-06-03).
    if not isinstance(data, dict):
        raise X402PaymentError("Invalid X-PAYMENT header JSON")

    accepts = data.get("accepts", [])
    if not accepts:
        raise X402PaymentError("X-PAYMENT header contains no 'accepts' entries")

    # Pick the first supported scheme. Each accepts[] entry must be a JSON object;
    # a hostile server can send a primitive (e.g. {"accepts": ["exact"]} or [42]),
    # and entry.get() on a non-dict would raise an uncaught AttributeError outside
    # the sanitised audit path (F1, 2026-06-07). Skip non-dict entries.
    chosen = None
    for entry in accepts:
        if isinstance(entry, dict) and entry.get("scheme") == SUPPORTED_SCHEME:
            chosen = entry
            break
    if chosen is None:
        schemes = [e.get("scheme") for e in accepts if isinstance(e, dict)]
        raise X402PaymentError(
            f"No supported payment scheme found. Server offered: {schemes}; "
            f"client supports: [{SUPPORTED_SCHEME!r}]"
        )

    try:
        return PaymentDetails(
            resource_url=chosen["resource"],
            pay_to=chosen["payTo"],
            amount=chosen["maxAmountRequired"],
            currency=chosen.get("currency", "USDC"),
            network=chosen["network"],
            deadline_seconds=int(chosen.get("requiredDeadlineSeconds", 300)),
            description=chosen.get("description", ""),
            reason=chosen.get("reason", ""),
            extra=chosen.get("extra", {}),
        )
    except KeyError:
        raise X402PaymentError("Missing required field in X-PAYMENT entry") from None


def caip2_for_network(network: str) -> str | None:
    """Map an x402 network identifier to a CAIP-2 chain id, or ``None``.

    Pass-through for values already in CAIP-2 form (``namespace:reference``,
    per CAIP-2's own grammar), table lookup for the rail's short names, and
    ``None`` for anything else — never a guess. ``None`` is a well-formed
    outcome: the caller records the raw network string and the operator
    supplies the chain id.
    """
    if not isinstance(network, str) or not network:
        return None
    candidate = network.strip()
    namespace, sep, reference = candidate.partition(":")
    if sep and _is_caip2(namespace, reference):
        return candidate
    return _CAIP2_BY_NETWORK.get(candidate.lower())


def _is_caip2(namespace: str, reference: str) -> bool:
    """CAIP-2 grammar: ``[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}``."""
    return (
        3 <= len(namespace) <= 8
        and all(c.isdigit() or c.islower() or c == "-" for c in namespace)
        and namespace.isascii()
        and 1 <= len(reference) <= 32
        and reference.isascii()
        and all(c.isalnum() or c in "-_" for c in reference)
    )


def _coerce_index(value: object) -> int | None:
    """A non-negative block height / log index, or ``None``.

    ``bool`` is excluded explicitly (it is an ``int`` subclass, and ``True`` is
    not a block number). A float is refused rather than truncated.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def parse_settlement_receipt(raw: str | bytes) -> SettlementReceipt | None:
    """Parse an x402 settlement echo into rail-agnostic facts, or ``None``.

    The payload is the facilitator's settle response, base64-encoded (the x402
    convention) or bare JSON::

        {"success": true, "transaction": "0x…", "network": "base-sepolia", "payer": "0x…"}

    **Never raises and never affects the payment.** The paid response has already
    been received by the time this runs; a hostile or broken server must not be
    able to turn a successful payment into an exception, so every failure path
    returns ``None``. ``block_number``/``log_index`` are read only if the server
    volunteered them (most do not) — see :class:`~presidio_x402._types.SettlementReceipt`.
    """
    try:
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    except UnicodeEncodeError:
        return None
    if not raw_bytes or len(raw_bytes) > SETTLEMENT_RECEIPT_MAX_BYTES:
        return None

    data = _decode_receipt_payload(raw_bytes)
    if data is None:
        return None

    network = data.get("network")
    network = network.strip() if isinstance(network, str) else ""
    tx_hash = data.get("transaction")
    if not isinstance(tx_hash, str) or not tx_hash:
        tx_hash = data.get("txHash") if isinstance(data.get("txHash"), str) else None
    payer = data.get("payer") if isinstance(data.get("payer"), str) else None
    block_number = _coerce_index(data.get("blockNumber", data.get("block_number")))
    log_index = _coerce_index(data.get("logIndex", data.get("log_index")))

    if not network and not tx_hash:
        # Nothing correlatable was echoed — treat as "no receipt" rather than
        # manufacturing an empty one.
        return None

    return SettlementReceipt(
        network=network,
        chain=caip2_for_network(network),
        tx_hash=tx_hash or None,
        block_number=block_number,
        log_index=log_index,
        payer=payer,
        success=data.get("success") is True,
        observed_at=datetime.now(tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        receipt_hash="sha256:" + hashlib.sha256(raw_bytes).hexdigest(),
    )


def _decode_receipt_payload(raw_bytes: bytes) -> dict | None:
    """Base64-then-JSON, falling back to bare JSON. ``None`` on anything else."""
    candidates: list[bytes] = []
    with contextlib.suppress(binascii.Error, ValueError):
        candidates.append(base64.b64decode(raw_bytes, validate=True))
    candidates.append(raw_bytes)
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError, RecursionError, UnicodeDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


class X402Binding:
    """The reference :class:`~presidio_x402._types.PaymentProtocolBinding`.

    Encapsulates how the x402 rail signals a payment requirement (HTTP 402 +
    ``X-PAYMENT`` header) and how the signed token is transmitted (the same
    header on the retried request).
    """

    name = "x402"
    payment_required_status = 402
    header_name = HEADER_PAYMENT

    def payment_offer(self, status_code: int, headers: dict[str, str]) -> str | None:
        """Return the raw payment-offer payload, or ``None`` if this response
        does not require payment (or the offer is missing/malformed at the
        transport level)."""
        if status_code != self.payment_required_status:
            return None
        # Header lookup is case-insensitive at the httpx layer; callers pass
        # the already-normalised mapping. A 402 without the header is treated
        # as "no offer" — the gateway returns the response unmodified.
        return headers.get(self.header_name)

    def parse_payment_required(self, offer: str) -> PaymentDetails:
        """Parse the rail's payment offer into rail-agnostic details.

        Raises :class:`~presidio_x402.exceptions.X402PaymentError` on any
        malformed offer (fail-closed; hardened per F-04/F1).
        """
        return parse_402_header(offer)

    def token_headers(self, token: str) -> dict[str, str]:
        """Headers carrying the signed payment token on the retried request."""
        return {self.header_name: token}

    def settlement_receipt(self, headers: object) -> SettlementReceipt | None:
        """Settlement facts echoed on the paid response, or ``None``.

        Optional protocol extension (v0.10.0): the gateway probes for this method
        with ``getattr`` and skips capture when a binding does not implement it.
        Reads transport bytes via ``headers.raw`` when the client retained them,
        so :attr:`~presidio_x402._types.SettlementReceipt.receipt_hash` binds the
        parsed facts to the bytes actually received rather than to a re-encoding.
        """
        get = getattr(headers, "get", None)
        if get is None:
            return None
        for name in SETTLEMENT_RECEIPT_HEADERS:
            raw = _raw_header_value(headers, name)
            if raw is None:
                value = get(name)
                if not isinstance(value, str) or not value:
                    continue
                raw = value
            receipt = parse_settlement_receipt(raw)
            if receipt is not None:
                return receipt
            logger.debug("settlement receipt header %s present but unparseable", name)
        return None


def _raw_header_value(headers: object, name: str) -> bytes | None:
    """One header's transport bytes, when the HTTP client retained them."""
    raw_pairs = getattr(headers, "raw", None)
    if not raw_pairs:
        return None
    target = name.lower().encode("ascii")
    for raw_name, raw_value in raw_pairs:
        if bytes(raw_name).lower() == target:
            return bytes(raw_value)
    return None
