# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Adapter: arch-translucency degradation signals → verified SLO triggers (v0.7.0).

The :class:`~presidio_x402.slo_broker.SLOPaymentBroker` *moves money* on degradation
events, so a trigger must be an **authorization, not a metric**. ``presidio-hardened-
arch-translucency`` already emits Ed25519-signed evidence in the cross-repo
``presidio-hardened/evidence-ref@1`` wire format (the same substrate x402 verifies in
:mod:`presidio_x402.mica`). This adapter accepts a degradation signal only when:

1. the attested content's SHA-256 matches the ref's ``content_hash`` (content ↔ hash), and
2. the ref's detached signature verifies against a **trusted arch-translucency signer**
   in the trust store (hash+signer ↔ signature), and
3. (optionally) the signer is on an allow-list of expected arch-translucency signers.

All three are fail-closed: any failure yields **no** :class:`SLOTrigger`, so the broker
never pays on a forged, tampered, or untrusted signal. Verification mechanics are
contract-stable; only the *field names* read out of the attested content
(``slo``/``value``/``threshold``/``window``) are coupled to arch-translucency's payload
shape and are overridable via ``field_map``.

Feed transport is injectable: construct :class:`SLOTrigger` objects from envelopes you
pull however arch-translucency exposes them (HTTP poll, push, file tail). This keeps x402
decoupled from arch-translucency's internal API surface.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .mica import load_trust_store, parse_document, sha256_hex, verify_ref

logger = logging.getLogger("presidio_x402.arch_translucency_adapter")

# Default arch-translucency signer id (override via expected_signers if different).
DEFAULT_ARCH_SIGNER = "presidio-hardened-arch-translucency"

# Attested-content field names. Overridable to match arch-translucency's payload.
_DEFAULT_FIELD_MAP = {
    "slo": "slo",
    "value": "value",
    "threshold": "threshold",
    "window": "window",
    "observed_at": "observed_at",
}


@dataclass(frozen=True)
class SLOTrigger:
    """A *verified* SLO degradation event. Only the adapter constructs these, and
    only after fail-closed signature + content-hash checks, so possessing one is
    proof the broker may act on it."""

    slo: str
    value: int
    threshold: int
    window: str
    signer: str
    content_hash: str
    observed_at: str

    @property
    def degraded(self) -> bool:
        """True when the observed metric breaches the SLO's own threshold."""
        return self.value > self.threshold


class SLOTriggerError(ValueError):
    """Raised by strict parsing when an envelope cannot be turned into a trigger."""


class ArchTranslucencyAdapter:
    """Verifies arch-translucency evidence envelopes into :class:`SLOTrigger` objects.

    Parameters
    ----------
    trust:
        Trust store (mapping or JSON text) of arch-translucency signers, in the
        ``trust-store@1`` shape consumed by :func:`presidio_x402.mica.load_trust_store`.
    expected_signers:
        Optional allow-list; when set, a ref whose signer is not listed is rejected
        even if its signature would verify under some other entry.
    field_map:
        Override attested-content field names if arch-translucency labels them
        differently from the defaults (``slo``/``value``/``threshold``/``window``).
    """

    def __init__(
        self,
        trust: Mapping[str, object] | str,
        *,
        expected_signers: Iterable[str] | None = None,
        field_map: Mapping[str, str] | None = None,
    ) -> None:
        self._trust = load_trust_store(trust)
        self._expected = set(expected_signers) if expected_signers is not None else None
        self._fields = {**_DEFAULT_FIELD_MAP, **(dict(field_map) if field_map else {})}
        self.rejected = 0

    def build_triggers(self, envelope: Mapping[str, object]) -> list[SLOTrigger]:
        """Verify one evidence envelope and return its trigger(s) (fail-closed).

        Bad/forged/untrusted items are skipped and counted in ``self.rejected``;
        the method never raises on a verification failure (so a malicious feed item
        produces no trigger rather than an exception that could mask others). Use
        :meth:`build_trigger_strict` when you want a raise.
        """
        try:
            refs = parse_document(envelope)
        except Exception:
            logger.warning("arch-translucency envelope failed structural parse; skipping")
            self.rejected += 1
            return []

        content = envelope.get("attested_content")
        if not isinstance(content, Mapping):
            logger.warning("envelope missing attested_content mapping; skipping")
            self.rejected += len(refs) or 1
            return []

        # Content ↔ hash: recompute and pin before trusting any field of it.
        try:
            content_digest = sha256_hex(content)
        except Exception:
            logger.warning("attested_content not canonicalizable; skipping")
            self.rejected += len(refs) or 1
            return []

        triggers: list[SLOTrigger] = []
        for ref in refs:
            if ref.content_hash != content_digest:
                logger.warning("content_hash mismatch (content tampered); rejecting ref")
                self.rejected += 1
                continue
            if self._expected is not None and ref.signer not in self._expected:
                logger.warning("signer %r not in expected arch signers; rejecting", ref.signer)
                self.rejected += 1
                continue
            if not verify_ref(ref, self._trust):
                logger.warning("signature did not verify for signer %r; rejecting", ref.signer)
                self.rejected += 1
                continue
            trigger = self._content_to_trigger(content, ref.signer, ref.content_hash)
            if trigger is None:
                self.rejected += 1
                continue
            triggers.append(trigger)
        return triggers

    def build_trigger_strict(self, envelope: Mapping[str, object]) -> SLOTrigger:
        """Like :meth:`build_triggers` but raises :class:`SLOTriggerError` on any
        failure and requires exactly one trigger. Handy for request/response feeds."""
        triggers = self.build_triggers(envelope)
        if len(triggers) != 1:
            raise SLOTriggerError(
                f"expected exactly one verified trigger, got {len(triggers)} "
                "(unverified, tampered, untrusted, or multi-ref envelope)"
            )
        return triggers[0]

    def _content_to_trigger(
        self, content: Mapping[str, object], signer: str, content_hash: str
    ) -> SLOTrigger | None:
        f = self._fields
        try:
            slo = str(content[f["slo"]])
            value = int(content[f["value"]])
            threshold = int(content[f["threshold"]])
            window = str(content[f["window"]])
        except (KeyError, TypeError, ValueError):
            logger.warning("attested_content missing/invalid SLO fields; rejecting")
            return None
        observed_at = str(content.get(f["observed_at"], ""))
        return SLOTrigger(
            slo=slo,
            value=value,
            threshold=threshold,
            window=window,
            signer=signer,
            content_hash=content_hash,
            observed_at=observed_at,
        )
