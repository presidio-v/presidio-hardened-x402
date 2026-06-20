"""Content-addressed ``action_ref`` derivation (action-ref-v1).

``action_ref`` is a deterministic, content-addressed identifier for an agent
action: ``SHA-256`` over the RFC 8785 (JCS) canonicalisation of a four-field
preimage (``agent_id``, ``action_type``, ``scope``, ``timestamp``). Any party
holding those four fields can recompute it independently — no trust in the
emitting system required.

This module implements the joint action-ref-v1 derivation that
``presidio-hardened-x402`` co-authored on x402-foundation/x402 issue #2332. It
is the interoperability primitive only; it does **not** submit trails to any
external service. A Mycelium/ARGENTUM "provider" integration (an optional
``AuditWriter`` that POSTs trails) is intentionally out of scope here.

Spec: argentum-core ``docs/spec/action-ref.md`` (stable ref ``action-ref-v1.0``).

.. note:: Safe band

   The :func:`json.dumps` canonicalisation below is RFC 8785-compatible for the
   input shapes this primitive targets: ASCII field values and conformant
   ``YYYY-MM-DDTHH:MM:SS.mmmZ`` timestamps. For non-ASCII or surrogate-pair
   field values, use an RFC 8785 library to guarantee byte-level portability.

Usage::

    from datetime import datetime, timezone
    from presidio_x402.action_ref import compute_action_ref, format_action_ref_timestamp

    ts = format_action_ref_timestamp(datetime.now(tz=timezone.utc))
    ref = compute_action_ref(
        agent_id="did:aps:zProviderAgent001",
        action_type="payment.send",
        scope="",
        timestamp=ts,
    )
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

# RFC 3339 UTC, exactly 3 fractional (millisecond) digits, mandatory trailing
# ``Z``. The spec closes JCS-determinism at the format level: one valid byte
# sequence per instant (no ``+00:00``, no trailing-zero suppression).
_CONFORMANT_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def format_action_ref_timestamp(dt: datetime) -> str:
    """Format *dt* as a conformant ``action_ref`` timestamp string.

    Returns RFC 3339 UTC with exactly three millisecond digits and a trailing
    ``Z`` (``"2026-06-20T14:00:00.123Z"``) — the normative emission form.

    *dt* must be timezone-aware; it is converted to UTC before formatting. A
    naive datetime raises :class:`ValueError` rather than silently assuming a
    timezone (which would yield an unverifiable, wrong digest).
    """
    if dt.tzinfo is None:
        raise ValueError(
            "format_action_ref_timestamp requires a timezone-aware datetime; got a naive value"
        )
    dt = dt.astimezone(timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def compute_action_ref(
    agent_id: str,
    action_type: str,
    scope: str,
    timestamp: str,
) -> str:
    """Compute the ``action_ref`` for a four-field preimage.

    Parameters
    ----------
    agent_id:
        Stable identifier of the **terminal executing agent** at issuance time.
    action_type:
        Semantic label for the action (``"payment.send"``, ``"code.execute"``…).
    scope:
        Terminal agent's requested-intent scope. Pass ``""`` if not applicable;
        never ``None`` and never a hash of an intent object.
    timestamp:
        Conformant RFC 3339 UTC string (``YYYY-MM-DDTHH:MM:SS.mmmZ``). Use
        :func:`format_action_ref_timestamp` to produce one. A non-conformant
        timestamp raises :class:`ValueError` so an unverifiable receipt is never
        emitted.

    Returns
    -------
    str
        64 lowercase hex characters (SHA-256 of the JCS canonical preimage).
    """
    if not _CONFORMANT_TS_RE.match(timestamp):
        raise ValueError(
            "timestamp must be RFC 3339 UTC with exactly 3 millisecond digits "
            f"and a trailing 'Z' (YYYY-MM-DDTHH:MM:SS.mmmZ); got {timestamp!r}"
        )
    payload = {
        "agent_id": agent_id,
        "action_type": action_type,
        "scope": scope,
        "timestamp": timestamp,
    }
    # JCS (RFC 8785): lexicographic key order, no inter-token whitespace, UTF-8.
    # Mirrors the family canonical-bytes pattern (see ``mica.py``).
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
