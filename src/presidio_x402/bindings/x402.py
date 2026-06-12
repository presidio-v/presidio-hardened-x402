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

import json

from .._types import PaymentDetails
from ..exceptions import X402PaymentError

# Header name per x402 spec.
HEADER_PAYMENT = "X-PAYMENT"

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
