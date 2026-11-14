# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Gate-certificate parents: name the gate decision a payment was authorised under.

The operator loads one or more ikigov-assess ``gate-certificate@1`` files and a
trust store once, at startup, with :func:`load_gate_parents`, and passes the
result to :class:`~presidio_x402.gateway.HardenedX402Client` (or
:class:`~presidio_x402.core.ScreeningPipeline`) as ``gate_parents``. Each
certificate is verified with ikigov-assess's own ``verify_certificate``
(schema, issuer signature, predicate identity, validity bound, embedded
evidence-refs, recomputed decision), and the decision must be ``OPEN``: a
PARTIAL or BLOCKED gate did not admit anything, however well it verifies. Any
refusal raises :class:`GateCertificateError`, so the client is never built: a
set-but-broken gate is a deployment defect.

The identity that goes into ``parents`` is the ADR-0006 identity, ikigov's
``certificate_content_hash`` (SHA-256 over the canonical bytes the issuer
signs), as a bare hash, the same form presidio-hardened-x402-mcp writes. It
comes from operator configuration only, never from a payment offer, so a
resource server cannot inject lineage into a signed record.

A client is long-lived and a certificate carries ``not_after``. The earliest
bound is kept, and :meth:`GateParents.current` returns no parents once it has
passed: the record is still emitted (emission never changes a payment outcome)
but no longer claims an expired gate.

The verifier comes from the optional ``[gate]`` extra; nothing here imports it
until :func:`load_gate_parents` is called.

This module is a port of ``presidio_x402_mcp.gate`` (x402-mcp #89), kept
behaviourally identical so both packages name a gate the same way.
"""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

#: Upper bound on a certificate or trust-store file. A certificate embeds one
#: evidence-ref per gate item; 1 MiB is far above any real one.
MAX_FILE_BYTES = 1024 * 1024

_REQUIRED_DECISION = "OPEN"
_EXTRA_HINT = (
    "gate-certificate parents need the [gate] extra: pip install 'presidio-hardened-x402[gate]'"
)


class GateCertificateError(ValueError):
    """A gate certificate or its trust store was refused (fail-closed)."""


@dataclass(frozen=True)
class GateParents:
    """Verified gate identities and the earliest ``not_after`` among them."""

    identities: tuple[str, ...]
    not_after: datetime | None

    def current(self, now: datetime) -> list[str]:
        """The identities while every certificate is in force, else ``[]``.

        In force through ``not_after`` itself, as ikigov's verifier counts it.
        """
        if self.not_after is not None and now > self.not_after:
            return []
        return list(self.identities)


def _read_bounded(path: Path, what: str) -> str:
    try:
        info = path.stat()
    except OSError as exc:
        raise GateCertificateError(f"cannot read {what} {path}: {exc.strerror}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise GateCertificateError(f"{what} {path} is not a regular file")
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise GateCertificateError(f"cannot read {what} {path}: {exc.strerror}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise GateCertificateError(f"{what} {path} exceeds {MAX_FILE_BYTES} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateCertificateError(f"{what} {path} is not UTF-8") from exc


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-finite number {name}")


def _load_json(path: Path, what: str) -> object:
    text = _read_bounded(path, what)
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise GateCertificateError(f"{what} {path} is not valid JSON") from exc


def _ikigov():  # noqa: ANN202
    try:
        from presidio_ikigov_assess import certificate, evidence  # noqa: PLC0415
    except ImportError as exc:
        raise GateCertificateError(_EXTRA_HINT) from exc
    return certificate, evidence


def load_gate_parents(
    certificate_paths: Sequence[Path],
    trust_path: Path,
    *,
    now: datetime | None = None,
) -> GateParents:
    """Verify each certificate against the trust store; return their identities.

    Order follows *certificate_paths*, each identity once. The first refusal
    raises :class:`GateCertificateError`. ``now`` (timezone-aware) overrides
    the wall clock for the expiry check.
    """
    if not certificate_paths:
        raise GateCertificateError("no gate certificate given")
    cert_mod, evidence_mod = _ikigov()
    trust_text = _read_bounded(trust_path, "gate trust store")
    try:
        trust = evidence_mod.load_trust_store(trust_text)
    except (evidence_mod.EvidenceError, ImportError) as exc:
        raise GateCertificateError(f"gate trust store {trust_path}: {exc}") from exc

    identities: list[str] = []
    bounds: list[datetime] = []
    for path in certificate_paths:
        document = _load_json(path, "gate certificate")
        try:
            result = cert_mod.verify_certificate(document, trust, now=now)
            identity = cert_mod.certificate_content_hash(document)
        except (cert_mod.CertificateError, evidence_mod.EvidenceError) as exc:
            raise GateCertificateError(f"gate certificate {path}: {exc}") from exc
        if not result.ok:
            raise GateCertificateError(f"gate certificate {path} does not verify: {result.reason}")
        if result.decision_recomputed != _REQUIRED_DECISION:
            raise GateCertificateError(
                f"gate certificate {path} records decision {result.decision_recomputed}, "
                f"not {_REQUIRED_DECISION}; only an open gate authorises payments"
            )
        if result.not_after:
            bound = cert_mod.parse_timestamp(result.not_after)
            if bound is None:  # verify_certificate already rejects this; stay closed
                raise GateCertificateError(f"gate certificate {path} has a malformed not_after")
            bounds.append(bound.astimezone(UTC))
        if identity not in identities:
            identities.append(identity)
    return GateParents(tuple(identities), min(bounds) if bounds else None)


__all__ = [
    "MAX_FILE_BYTES",
    "GateCertificateError",
    "GateParents",
    "load_gate_parents",
]
