"""MiCA/EU evidence module — signed compliance-supporting evidence (session-3 T3).

Maps what the screening middleware **actually does** (audit-chained payment
records, integrity protection, security-event logging, PII redaction) to the EU
obligations its *deployer* may need to demonstrate, and emits that mapping as
Ed25519-signed evidence records in the cross-repo
``presidio-hardened/evidence-ref@1`` wire format (the same format produced by
presidio-hardened-ai and verified by presidio-hardened-ikigov-assess).

Honest-claims doctrine (research memo: ``docs/mica-obligations.md``):

- Every obligation cited is addressed to the **deployer** (CASP, PPAET,
  financial entity, data controller) — never to this library. An evidence
  record attests only what the middleware observed/did on traffic routed
  through it; it is *supporting* material for the deployer's demonstration,
  not a compliance claim.
- The obligation map is **data**, not code: each entry carries its legal basis,
  per-claim verification status, a confidence grade, and the conditions under
  which it may be emitted. Entries below ``default_emit=True`` are the
  conservative core; conditional entries require explicit deployment flags.
- **TFR guardrail:** Regulation (EU) 2023/1113 *requires* originator/beneficiary
  personal data to accompany CASP-handled transfers (Arts. 14(1)–(2), 14(8)).
  PII redaction therefore must never be presented as TFR-supporting. The only
  TFR-adjacent attestation this module emits is a *layer-separation* statement:
  redaction was applied to x402 payment metadata, which is not the CASP
  travel-rule messaging channel (Art. 14(4)).
- AMLR (EU) 2024/1624 (applies 2027-07-10) mappings are deliberately absent:
  article-level content was not primary-source-verified at authoring time.

Wire format (must byte-match the family golden vector): detached signature =
``alg(canonical_json({"content_hash": ..., "signer": ...}))`` where
``canonical_json`` is ``json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`` and ``content_hash`` is SHA-256 over the canonical
encoding of the attested content. Ed25519 needs the ``[evidence]`` extra
(``pip install presidio-hardened-x402[evidence]``); HMAC-SHA256 works with the
standard library.
"""

from __future__ import annotations

import hashlib
import hmac as hmaclib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .exceptions import X402Error

if TYPE_CHECKING:
    from .compliance_report import ComplianceReport

EVIDENCE_SCHEMA_ID = "presidio-hardened/evidence-ref@1"
DEFAULT_SIGNER = "presidio-hardened-x402"

SIGNING_ALGORITHMS = ("ed25519", "hmac-sha256")


class EvidenceError(X402Error):
    """Raised on invalid evidence configuration or signing failure (fail-closed)."""


# ---------------------------------------------------------------------------
# Canonical encoding + signing (family wire format)
# ---------------------------------------------------------------------------


def canonical_bytes(payload: object) -> bytes:
    """Deterministic canonical JSON — must byte-match every family producer."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(payload: object) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise EvidenceError(
            "Ed25519 evidence signing needs the optional extra: "
            "pip install 'presidio-hardened-x402[evidence]'"
        ) from exc
    return ed25519


def sign_evidence(
    content_hash: str,
    signer: str,
    *,
    algorithm: str = "ed25519",
    key: str = "",
) -> str:
    """Detached signature over ``canonical({content_hash, signer})`` (hex).

    ``key`` is the Ed25519 private key as 64 lowercase hex chars, or the HMAC
    secret (UTF-8) for ``hmac-sha256``. Fail-closed: unknown algorithm or
    missing/malformed key raises :class:`EvidenceError`.
    """
    if not key:
        raise EvidenceError("evidence signing requires a key (fail-closed; no unsigned output)")
    message = canonical_bytes({"content_hash": content_hash, "signer": signer})
    if algorithm == "ed25519":
        ed25519 = _require_crypto()
        try:
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key))
        except ValueError as exc:
            raise EvidenceError("Ed25519 private key must be 64 lowercase hex chars") from exc
        return sk.sign(message).hex()
    if algorithm == "hmac-sha256":
        return hmaclib.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()
    raise EvidenceError(f"unknown signing algorithm {algorithm!r} (use ed25519 | hmac-sha256)")


# ---------------------------------------------------------------------------
# Obligation map — DATA, founder-reviewable. Verification statuses refer to the
# 2026-06-12 research memo (docs/mica-obligations.md); do not edit attestation
# wording without re-checking the cited source.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Obligation:
    item_id: str
    regulation: str
    article: str
    attests: str
    confidence: str  # "high" | "medium-high" | "medium" | "low-medium" | "low"
    verification: str  # "VERIFIED-PRIMARY" | "VERIFIED-SECONDARY"
    default_emit: bool
    requires: tuple[str, ...] = field(default_factory=tuple)
    """Deployment flags that must all be set for this item to be emitted."""

    notes: str = ""


OBLIGATION_MAP: tuple[Obligation, ...] = (
    Obligation(
        item_id="MICA-68-9-RECORDS",
        regulation="Regulation (EU) 2023/1114 (MiCA)",
        article="Art. 68(9); Delegated Regulation (EU) 2025/1140",
        attests=(
            "A tamper-evident, individually identifiable record of each payment "
            "order/attempt processed through the middleware exists (timestamp, "
            "decision, outcome), suitable as a component of a CASP's Art. 68(9) "
            "record set for flows routed through the middleware."
        ),
        confidence="medium-high",
        verification="VERIFIED-PRIMARY",
        default_emit=True,
        notes=(
            "Component claim only — record-content sufficiency against RTS (EU) "
            "2025/1140 field requirements is the deployer's assessment."
        ),
    ),
    Obligation(
        item_id="MICA-68-8-INTEGRITY",
        regulation="Regulation (EU) 2023/1114 (MiCA) / Regulation (EU) 2022/2554 (DORA)",
        article="MiCA Art. 68(8) 2nd subpara; DORA Art. 9(2)",
        attests=(
            "Audit log authenticity and integrity are cryptographically protected "
            "(HMAC-chained records; tampering is detectable on verification)."
        ),
        confidence="medium",
        verification="VERIFIED-PRIMARY",
        default_emit=True,
    ),
    Obligation(
        item_id="DORA-17-2-SECURITY-EVENTS",
        regulation="Regulation (EU) 2022/2554 (DORA)",
        article="Art. 17(2), 17(3)(b)",
        attests=(
            "Anomalous payment events (replay/duplicate detections, policy blocks, "
            "PII blocks) were detected, logged and categorised, and are available "
            "as inputs to the deployer's ICT incident-management process."
        ),
        confidence="medium",
        verification="VERIFIED-SECONDARY",
        default_emit=True,
    ),
    Obligation(
        item_id="GDPR-5-1C-MINIMISATION",
        regulation="Regulation (EU) 2016/679 (GDPR)",
        article="Art. 5(1)(c) with Art. 5(2) accountability",
        attests=(
            "Payment metadata was scanned pre-signature; fields matching PII "
            "patterns were redacted before transmission — demonstration material "
            "for the controller's data-minimisation accountability."
        ),
        confidence="medium",
        verification="VERIFIED-SECONDARY",
        default_emit=True,
        notes="Emitted only when redaction events are present in the audit window.",
    ),
    Obligation(
        item_id="TFR-14-4-LAYER-SEPARATION",
        regulation="Regulation (EU) 2023/1113 (TFR)",
        article="Art. 14(4) (constraint context: Arts. 14(1)-(2), 14(8))",
        attests=(
            "PII redaction was applied exclusively to x402 payment metadata, which "
            "is not the CASP-to-CASP travel-rule messaging channel (TFR Art. 14(4): "
            "required information need not be included in the transfer itself). "
            "This record makes no claim that redaction supports TFR compliance; "
            "TFR-mandated originator/beneficiary data flows are the deployer's "
            "responsibility on their own channel."
        ),
        confidence="high",
        verification="VERIFIED-PRIMARY",
        default_emit=True,
        notes="Negative/clarifying attestation — exists to prevent overclaiming.",
    ),
    Obligation(
        item_id="MICA-92-1-PPAET-INPUT",
        regulation="Regulation (EU) 2023/1114 (MiCA)",
        article="Art. 92(1) (scope: Art. 86(1)); Delegated Regulation (EU) 2025/885",
        attests=(
            "Orders flagged as duplicates/replays were blocked and recorded with "
            "timestamps, providing input data the deployer (a person professionally "
            "arranging or executing transactions) may use within its market-abuse "
            "detection arrangements and STOR substantiation."
        ),
        confidence="low-medium",
        verification="VERIFIED-PRIMARY",
        default_emit=False,
        requires=("ppaet", "admitted_to_trading"),
        notes="Replay detection is not market-abuse detection; input claim only.",
    ),
    Obligation(
        item_id="DORA-9-4-ACCESS-CONTROL",
        regulation="Regulation (EU) 2022/2554 (DORA)",
        article="Art. 9(4)(c)-(d)",
        attests=(
            "High-value payments required and received n-of-m approvals from "
            "distinct authorised parties before signing (freshness-bound "
            "countersignatures), as a technical access-control measure."
        ),
        confidence="low-medium",
        verification="VERIFIED-PRIMARY",
        default_emit=False,
        requires=("mpa_enabled",),
    ),
)


# ---------------------------------------------------------------------------
# Evidence emission
# ---------------------------------------------------------------------------

_REDACTION_EVENTS = frozenset({"PII_REDACTED", "PII_BLOCKED"})
_SECURITY_EVENTS = frozenset({"REPLAY_BLOCKED", "POLICY_BLOCKED", "PII_BLOCKED", "MPA_BLOCKED"})


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _audit_summary(report: ComplianceReport) -> dict[str, object]:
    """Deterministic, PII-free summary of the audit window — the attested content."""
    counts: dict[str, int] = {}
    timestamps: list[str] = []
    for ev in report.events:
        counts[ev.event_type] = counts.get(ev.event_type, 0) + 1
        timestamps.append(ev.timestamp.isoformat() if ev.timestamp else "")
    return {
        "event_counts": dict(sorted(counts.items())),
        "n_events": len(report.events),
        "chain_ok": bool(report.chain_ok),
        "window_first": min(timestamps) if timestamps else "",
        "window_last": max(timestamps) if timestamps else "",
    }


def applicable_obligations(
    report: ComplianceReport,
    *,
    deployment_flags: frozenset[str] = frozenset(),
    include: list[str] | None = None,
) -> list[Obligation]:
    """Select obligation items honestly supported by this audit window.

    Default-emit items are included when their evidentiary precondition holds in
    the data (e.g. GDPR minimisation only if redaction events exist). Conditional
    items additionally need every flag in ``requires`` present in
    ``deployment_flags`` — deployment facts the middleware cannot observe and the
    deployer must assert. ``include`` restricts to an explicit subset of ids.
    """
    counts: dict[str, int] = {}
    for ev in report.events:
        counts[ev.event_type] = counts.get(ev.event_type, 0) + 1

    if not counts:
        # An empty window supports no attestation at all — even the record-keeping
        # claim would be vacuous ("records of nothing exist").
        return []

    selected: list[Obligation] = []
    for ob in OBLIGATION_MAP:
        if include is not None and ob.item_id not in include:
            continue
        if ob.requires and not all(flag in deployment_flags for flag in ob.requires):
            if include is not None:
                raise EvidenceError(
                    f"obligation {ob.item_id} requires deployment flags "
                    f"{sorted(ob.requires)} (fail-closed: not emitted without them)"
                )
            continue
        if not ob.requires and not ob.default_emit and include is None:
            continue
        # Data preconditions: never attest to behaviour the window doesn't show.
        if ob.item_id in ("GDPR-5-1C-MINIMISATION", "TFR-14-4-LAYER-SEPARATION") and not any(
            counts.get(e) for e in _REDACTION_EVENTS
        ):
            continue
        if ob.item_id == "DORA-17-2-SECURITY-EVENTS" and not any(
            counts.get(e) for e in _SECURITY_EVENTS
        ):
            continue
        if ob.item_id == "MICA-92-1-PPAET-INPUT" and not counts.get("REPLAY_BLOCKED"):
            continue
        if ob.item_id == "DORA-9-4-ACCESS-CONTROL" and not (
            counts.get("MPA_BLOCKED") or "mpa_enabled" in deployment_flags
        ):
            continue
        selected.append(ob)
    return selected


def build_evidence(
    report: ComplianceReport,
    *,
    signing_key: str,
    algorithm: str = "ed25519",
    signer: str = DEFAULT_SIGNER,
    source_version: str | None = None,
    use_case: str = "x402-payment-screening",
    deployment_flags: frozenset[str] | set[str] = frozenset(),
    include: list[str] | None = None,
    ledger_ref: str | None = None,
) -> dict[str, object]:
    """Build a signed ``presidio-hardened/evidence-ref@1`` envelope.

    One evidence ref per applicable obligation. All refs in one envelope share
    the same attested content (the PII-free audit-window summary) and therefore
    the same ``content_hash``; what differs is the obligation (``item_id``) the
    deployer cites it under. The full obligation text travels alongside in
    ``obligations`` so a human reviewer sees exactly what is — and is not —
    being claimed.

    Fail-closed: refuses to sign when the audit chain does not verify, when no
    key is supplied, or when an explicitly requested obligation lacks its
    deployment flags.
    """
    from . import __version__

    if not report.chain_ok:
        raise EvidenceError(
            "audit chain failed verification — refusing to sign evidence over a "
            f"non-verifying window (fail-closed): {report.chain_warnings}"
        )

    flags = frozenset(deployment_flags)
    obligations = applicable_obligations(report, deployment_flags=flags, include=include)
    if not obligations:
        raise EvidenceError("no obligation is honestly supported by this audit window")

    content = _audit_summary(report)
    content_hash = sha256_hex(content)
    signature = sign_evidence(content_hash, signer, algorithm=algorithm, key=signing_key)
    version = source_version or __version__
    claimed_at = _utcnow_iso()
    ref_ledger = ledger_ref or f"x402-audit:chain/{content['n_events']}"

    refs = [
        {
            "item_id": ob.item_id,
            "source": signer,
            "source_version": version,
            "ledger_ref": ref_ledger,
            "content_hash": content_hash,
            "signer": signer,
            "signature": signature,
            "claimed_at": claimed_at,
        }
        for ob in obligations
    ]
    return {
        "schema": EVIDENCE_SCHEMA_ID,
        "use_case": use_case,
        "source": signer,
        "source_version": version,
        "generated_at": claimed_at,
        "evidence": refs,
        # Non-contract companion data (ignored by evidence-ref@1 verifiers):
        "attested_content": content,
        "signing_algorithm": algorithm,
        "obligations": [
            {
                "item_id": ob.item_id,
                "regulation": ob.regulation,
                "article": ob.article,
                "attests": ob.attests,
                "confidence": ob.confidence,
                "verification": ob.verification,
                "notes": ob.notes,
            }
            for ob in obligations
        ],
        "disclaimer": (
            "Supporting evidence only. Obligations cited are addressed to the "
            "deploying entity; this record attests solely to middleware-observed "
            "behaviour on traffic routed through it and makes no compliance claim."
        ),
    }
