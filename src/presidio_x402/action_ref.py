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

.. note:: Canonicalisation

   The :func:`json.dumps` canonicalisation below is RFC 8785-compatible: string
   fields are NFC-normalised before hashing (so NFD-form Unicode yields the same
   digest a normalising verifier computes), and timestamps are pinned to the
   conformant ``YYYY-MM-DDTHH:MM:SS.mmmZ`` form. NFC is a no-op for the ASCII
   inputs this primitive targets (DIDs, ``payment.send``, ASCII scopes).

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
import unicodedata
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

# screen_ref scope grammar: ``presidio:x402.screen:<verdict>[:<entities>]``.
# A ``screen_ref`` is an ``action_ref`` over a PII-screening *verdict* — the
# pre-signing decision the gateway records before a payment leaves. It is the
# sibling pointer offered alongside ``v_gate`` / ``mycelium_trail_id`` in the
# composed envelope on x402-foundation/x402#2332.
_SCREEN_SCOPE_PREFIX = "presidio:x402.screen"
_SCREEN_ACTION_TYPE = "pii_screen"

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
    # NFC-normalise the string fields so a caller passing NFD-form Unicode yields the
    # same digest as an RFC 8785 verifier (which normalises to NFC). No-op for ASCII
    # inputs (DIDs, ``payment.send``, ASCII scopes), so existing digests are unchanged.
    payload = {
        "agent_id": unicodedata.normalize("NFC", agent_id),
        "action_type": unicodedata.normalize("NFC", action_type),
        "scope": unicodedata.normalize("NFC", scope),
        "timestamp": timestamp,
    }
    # JCS (RFC 8785): lexicographic key order, no inter-token whitespace, UTF-8.
    # Mirrors the family canonical-bytes pattern (see ``mica.py``).
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def format_screen_scope(verdict: str, entities: Iterable[str] = ()) -> str:
    """Build the canonical ``screen_ref`` scope segment for a PII verdict.

    Returns ``presidio:x402.screen:<verdict>`` with, when *entities* is
    non-empty, a trailing ``:<entities>`` segment of the **lexicographically
    sorted, de-duplicated, comma-joined, space-free** entity types — the
    normative rule from argentum-core ``docs/spec/action-ref.md`` §Scope
    conventions (commit ``16dbc92``).

    The sort is applied *here*, at the formatting boundary, precisely because
    a screen's ``pii_entities_found`` comes out in **detection order**, which is
    not guaranteed alphabetical. Canonicalising at emission is what stops two
    honest implementations from diverging when one reports ``US_SSN`` before
    ``EMAIL_ADDRESS``. A clean verdict (no PII) carries no entity segment::

        format_screen_scope("PII_REDACTED", ["US_SSN", "EMAIL_ADDRESS"])
        # -> "presidio:x402.screen:PII_REDACTED:EMAIL_ADDRESS,US_SSN"
        format_screen_scope("clean-allow")
        # -> "presidio:x402.screen:clean-allow"

    Parameters
    ----------
    verdict:
        Screening verdict label (``"PII_REDACTED"``, ``"PII_BLOCKED"``,
        ``"clean-allow"``…). Must be non-empty and contain neither ``:`` nor
        ``,`` (either would forge or split a scope segment).
    entities:
        Entity types found by the screen. Order and multiplicity are
        irrelevant — they are sorted and de-duplicated. Pass nothing for a
        clean verdict. No entity may contain ``,`` or ``:``.
    """
    if not verdict:
        raise ValueError("screen verdict must be a non-empty string")
    if ":" in verdict or "," in verdict:
        raise ValueError(f"screen verdict must not contain ':' or ',' separators; got {verdict!r}")
    canonical_entities = sorted(set(entities))
    for entity in canonical_entities:
        if not entity:
            raise ValueError("entity type must be a non-empty string")
        if "," in entity or ":" in entity:
            raise ValueError(f"entity type must not contain ',' or ':' separators; got {entity!r}")
    scope = f"{_SCREEN_SCOPE_PREFIX}:{verdict}"
    if canonical_entities:
        scope += ":" + ",".join(canonical_entities)
    return scope


def compute_screen_ref(
    agent_id: str,
    verdict: str,
    entities: Iterable[str],
    timestamp: str,
) -> str:
    """Compute the ``screen_ref`` for a PII-screening verdict.

    A ``screen_ref`` is an :func:`compute_action_ref` over the fixed
    ``action_type`` ``"pii_screen"`` and the canonical screen scope
    (:func:`format_screen_scope`). It is the content-addressed pointer to the
    screening *decision* — recorded before signing — that rides as a sibling of
    ``v_gate`` and ``mycelium_trail_id`` in the composed envelope.

    Parameters mirror :func:`compute_action_ref`; *verdict* and *entities* are
    canonicalised into the scope, *timestamp* is the conformant
    ``YYYY-MM-DDTHH:MM:SS.mmmZ`` string of the screening decision.
    """
    scope = format_screen_scope(verdict, entities)
    return compute_action_ref(agent_id, _SCREEN_ACTION_TYPE, scope, timestamp)
