"""Payment-rail bindings for the presidio-hardened screening core.

The screening core (:mod:`presidio_x402.core`) is **rail-agnostic**: PII
filtering, spending policy, replay detection, multi-party authorization, and
audit logging operate on :class:`~presidio_x402._types.PaymentDetails` and know
nothing about how a rail signals "payment required" or how a signed token is
transmitted. Everything protocol-specific lives in a binding:

- how a payment requirement is detected on an HTTP response,
- how the rail's payment-offer payload parses into ``PaymentDetails``,
- which header (or other channel) carries the signed payment token.

``bindings.x402`` is the reference binding (HTTP 402 + ``X-PAYMENT`` header).
A new rail (e.g. a future ACP/AP2-style protocol) is supported by adding a
sibling module implementing :class:`~presidio_x402._types.PaymentProtocolBinding`
— the screening core and its security guarantees are reused unchanged.
"""

from __future__ import annotations

from .x402 import X402Binding

__all__ = ["X402Binding"]
