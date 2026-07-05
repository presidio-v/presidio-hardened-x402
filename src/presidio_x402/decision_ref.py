"""Decision-ref emission — per-payment proof-carrying decision records.

A **decision-ref** is a signed, portable record of one gateway payment decision:
the inputs (as hashes), the predicate identity (the effective policy config
content hash, and — when the policy came from a capability chain — the chain's
terminal ``grant_hash`` as a provenance parent), the per-control verdicts, the
recomputable top-level conclusion, and a detached signature. A third party
verifies it **offline** against a pinned trust store, without re-running the
gateway (Pillar II of the Computational Jurisprudence program; Stantchev, arXiv
2026).

This module implements the binding design note
``plan/presidio-evidence-decision-ref-design.md`` (Phase-A scope):

- Attested content schema: ``presidio-hardened-x402/payment-decision@1`` — the
  per-payment artifact whose ``controls{}`` block carries the individual
  ``pii → trusted_wallet → policy → replay → mpa`` gate verdicts (the design note
  names this schema, so it is used verbatim rather than the generic
  ``decision-ref@1`` family default). One artifact per payment is the record the
  brief's "one record per gate decision plus a per-payment envelope linking them"
  asks for: the per-control verdicts are the gate decisions, the artifact is the
  envelope that binds them, and ``f(controls)`` re-derives the top-level verdict.
- ``artifact_hash = sha256(canonical_bytes(payment_decision_content))`` = the
  ``content_hash`` of the single evidence ref in the envelope.
- ``decision_ref = sha256(canonical_bytes({artifact_hash, artifact_type,
  policy_version, verdict}))`` — the thin, self-describing-preimage correlation id
  (sibling to ``action_ref``), whose preimage fields travel in the envelope.
- Envelope: the family ``presidio-hardened/evidence-ref@1`` wire format produced
  and verified by :mod:`presidio_x402.mica` (canonical JSON, SHA-256 content
  hash, detached Ed25519/HMAC).

Wire format follows the family Layer-0 rules mirrored in :mod:`presidio_x402.mica`
(``canonical_bytes``: sorted keys, ``(",", ":")`` separators, UTF-8,
``ensure_ascii=False``, floats rejected). Amounts are strings or integer atomic
units — never floats.

**Privacy rule (PII-freedom by construction).** The attested content contains only
hashes, an origin, and entity-type *labels*. Raw ``resource_url``, ``description``,
``reason``, ``pay_to`` beyond a hashed offer, request bodies, model prompts, and
output payloads never enter the record — consistent with how
:mod:`presidio_x402.audit_log` redacts. The only screening output that appears is
the entity-type finding set (e.g. ``["EMAIL_ADDRESS"]``) and a hash; the screened
*strings* never do.

**Honesty bound.** A decision-ref proves what the library concluded under a
*declared* predicate (the recorded control verdicts + policy hash), recomputably
and tamper-evidently. It does **not** prove the process was not compromised, that
the declared controls are the real controls (that is an attestation layer, not
this one), or anything TEE-like. Signing makes it tamper-evident; recomputation
(``verdict == f(controls)``) makes it admissible.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .mica import (
    EVIDENCE_SCHEMA_ID,
    EvidenceError,
    load_trust_store,
    sha256_hex,
    sign_evidence,
    verify_ed25519,
    verify_hmac,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .capability import VerifiedGrantChain

PAYMENT_DECISION_SCHEMA_ID = "presidio-hardened-x402/payment-decision@1"
DEFAULT_POLICY_VERSION = "presidio-x402.policy.v1"
DEFAULT_DECISION_SIGNER = "presidio-hardened-x402-policy"

#: The four fields of the thin decision_ref preimage (self-describing).
DECISION_REF_PREIMAGE_FIELDS = ("artifact_hash", "artifact_type", "policy_version", "verdict")

#: The precedence order of the five controls (first-failure-wins). Byte-identical
#: to the shipped gateway order in :mod:`presidio_x402.core`.
CONTROL_PRECEDENCE = ("pii", "trusted_wallet", "policy", "replay", "mpa")

#: Control verdicts that force a terminal DENY, per control key.
_HARD_FAIL = {
    "pii": frozenset({"PII_BLOCKED"}),
    "trusted_wallet": frozenset({"UNTRUSTED"}),
    "policy": frozenset({"VIOLATION"}),
    "replay": frozenset({"DUPLICATE"}),
    "mpa": frozenset({"DENIED"}),
}
#: MPA verdicts that force REFER (a quorum that has not answered is recoverable).
_MPA_REFER = frozenset({"PENDING", "TIMEOUT"})

#: Permitted verdict enums per control (design note "Decision function f").
_ALLOWED_VERDICTS = {
    "pii": frozenset({"PII_NONE", "PII_WARNED", "PII_REDACTED", "PII_BLOCKED"}),
    "trusted_wallet": frozenset({"TRUSTED", "UNTRUSTED"}),
    "policy": frozenset({"ALLOW", "VIOLATION"}),
    "replay": frozenset({"FRESH", "DUPLICATE"}),
    "mpa": frozenset({"NOT_REQUIRED", "APPROVED", "PENDING", "TIMEOUT", "DENIED"}),
}
_HASH_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class DecisionRefError(EvidenceError):
    """Raised on any decision-ref rejection (fail-closed, distinct reasons).

    Subclasses :class:`~presidio_x402.mica.EvidenceError` so a caller already
    catching the family evidence error also catches decision-ref failures. The
    message carries the distinct rejection reason (bad schema, hash mismatch,
    verdict not recomputable, self-approval, broken parent linkage, …).
    """


# ---------------------------------------------------------------------------
# The recomputable verdict function f — a pure precedence-combinator over the
# five recorded control verdicts. Never re-executes a control; the verifier
# re-applies it offline to controls{} and checks it equals the recorded verdict.
# ---------------------------------------------------------------------------


def f_controls(controls: Mapping[str, object]) -> str:
    """Recompute the top-level verdict from the recorded control verdicts.

    Pure precedence-combinator, first-failure-wins over
    ``pii → trusted_wallet → policy → replay → mpa`` (:data:`CONTROL_PRECEDENCE`):
    any hard-fail verdict ⇒ ``DENY``; else an unanswered MPA quorum
    (``PENDING``/``TIMEOUT``) ⇒ ``REFER``; else ``ALLOW``. Touches no spaCy,
    Redis, MPA webhook, or network — that is what lets it be CI-graded offline.
    """
    verdicts = _validated_control_verdicts(controls)
    for key in CONTROL_PRECEDENCE:
        verdict = verdicts[key]
        if verdict in _HARD_FAIL[key]:
            return "DENY"
        if key == "mpa" and verdict in _MPA_REFER:
            return "REFER"
    return "ALLOW"


def _validate_hash_ref(value: object, field_name: str, *, required: bool) -> None:
    if value is None and not required:
        return
    if not (isinstance(value, str) and _HASH_REF_RE.fullmatch(value)):
        raise DecisionRefError(f"control field {field_name} must be a sha256:<64hex> hash")


def _validated_control_verdicts(controls: Mapping[str, object]) -> dict[str, str]:
    """Validate the signed controls block and return its verdicts.

    Missing, unknown, or enum-invalid controls fail closed. The verifier must not
    treat an omitted hard-fail control as implicit ALLOW.
    """
    actual = set(controls)
    expected = set(CONTROL_PRECEDENCE)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise DecisionRefError(
            f"controls block must contain exactly {list(CONTROL_PRECEDENCE)}; "
            f"missing={missing}, extra={extra}"
        )

    entries: dict[str, Mapping[str, object]] = {}
    verdicts: dict[str, str] = {}
    for key in CONTROL_PRECEDENCE:
        entry = controls.get(key)
        if not isinstance(entry, Mapping):
            raise DecisionRefError(f"control {key!r} must be an object")
        entries[key] = entry
        verdict = entry.get("verdict")
        if not (isinstance(verdict, str) and verdict in _ALLOWED_VERDICTS[key]):
            raise DecisionRefError(
                f"control {key!r} has verdict {verdict!r} not in "
                f"{sorted(_ALLOWED_VERDICTS[key])} (fail-closed)"
            )
        verdicts[key] = verdict

    pii = entries["pii"]
    entities = pii.get("entities")
    mutated = pii.get("mutated")
    if not (
        isinstance(entities, list)
        and all(isinstance(e, str) and 0 < len(e) <= 128 for e in entities)
        and isinstance(mutated, bool)
    ):
        raise DecisionRefError("control 'pii' must carry entities[] and mutated boolean")

    policy = entries["policy"]
    _validate_hash_ref(
        policy.get("policy_snapshot_hash"), "policy.policy_snapshot_hash", required=True
    )
    _validate_hash_ref(policy.get("limit_hash"), "policy.limit_hash", required=False)

    replay = entries["replay"]
    _validate_hash_ref(replay.get("fingerprint_hash"), "replay.fingerprint_hash", required=False)

    mpa = entries["mpa"]
    required = mpa.get("required")
    if not isinstance(required, bool):
        raise DecisionRefError("control 'mpa' must carry required boolean")
    threshold = mpa.get("threshold")
    if threshold is not None and not (isinstance(threshold, str) and threshold):
        raise DecisionRefError("control 'mpa.threshold' must be a non-empty string when present")
    approval_refs = mpa.get("approval_refs")
    if approval_refs is not None and not (
        isinstance(approval_refs, list)
        and all(isinstance(ref, str) and 0 < len(ref) <= 512 for ref in approval_refs)
    ):
        raise DecisionRefError("control 'mpa.approval_refs' must be a string list when present")

    return verdicts


# ---------------------------------------------------------------------------
# Control-result collector — the PII-free inputs the pipeline populates.
# Every field is either a hash, an enum label, or an entity-type list. No raw
# metadata string can be assigned here (there is no field for one).
# ---------------------------------------------------------------------------


def _sha256_prefixed(payload: object) -> str:
    """``sha256:<64hex>`` over the canonical bytes of *payload* (design shape)."""
    return "sha256:" + sha256_hex(payload)


def _hash_str(text: str) -> str:
    """``sha256:<64hex>`` of a single string — the ONLY way a raw string ever
    contributes to the record, and only as a one-way digest (never the string)."""
    return _sha256_prefixed(text)


@dataclass
class ControlResults:
    """The five per-control gate verdicts + hashed inputs, gathered before signing.

    The gateway/pipeline populates this from the control results it already
    computes; :func:`build_payment_decision_content` renders it into the attested
    ``payment-decision@1`` content. **PII-freedom is structural**: the only string
    fields are enum verdict labels, entity-type labels, and pre-computed hashes —
    there is no field that accepts a raw ``resource_url``/``description``/
    ``reason``/request-body, so a raw metadata string cannot leak into a record
    even by a caller mistake.
    """

    # PII gate
    pii_verdict: str = "PII_NONE"
    pii_entities: tuple[str, ...] = ()
    pii_mutated: bool = False

    # Trusted-wallet gate
    trusted_wallet_verdict: str = "TRUSTED"

    # Policy gate
    policy_verdict: str = "ALLOW"
    policy_snapshot_hash: str = ""  # sha256: of the effective PolicyConfig
    policy_limit_hash: str | None = None

    # Replay gate
    replay_verdict: str = "FRESH"
    replay_fingerprint_hash: str | None = None  # sha256: of the fingerprint, never the fingerprint

    # MPA gate
    mpa_verdict: str = "NOT_REQUIRED"
    mpa_required: bool = False
    mpa_threshold: str | None = None
    mpa_approval_refs: tuple[str, ...] = ()

    def _validate(self) -> None:
        pairs = (
            ("pii", self.pii_verdict),
            ("trusted_wallet", self.trusted_wallet_verdict),
            ("policy", self.policy_verdict),
            ("replay", self.replay_verdict),
            ("mpa", self.mpa_verdict),
        )
        for key, verdict in pairs:
            if verdict not in _ALLOWED_VERDICTS[key]:
                raise DecisionRefError(
                    f"control {key!r} has verdict {verdict!r} not in "
                    f"{sorted(_ALLOWED_VERDICTS[key])} (fail-closed)"
                )

    def to_controls(self) -> dict[str, object]:
        """Render the ``controls{}`` block of the attested content (validated)."""
        self._validate()
        policy: dict[str, object] = {
            "verdict": self.policy_verdict,
            "policy_snapshot_hash": self.policy_snapshot_hash,
        }
        if self.policy_limit_hash is not None:
            policy["limit_hash"] = self.policy_limit_hash
        replay: dict[str, object] = {"verdict": self.replay_verdict}
        if self.replay_fingerprint_hash is not None:
            replay["fingerprint_hash"] = self.replay_fingerprint_hash
        mpa: dict[str, object] = {
            "verdict": self.mpa_verdict,
            "required": bool(self.mpa_required),
        }
        if self.mpa_threshold is not None:
            mpa["threshold"] = self.mpa_threshold
        if self.mpa_approval_refs:
            mpa["approval_refs"] = list(self.mpa_approval_refs)
        return {
            "pii": {
                "verdict": self.pii_verdict,
                # Sorted + de-duplicated so two honest emitters that detect the
                # same entities in different order produce byte-identical content.
                "entities": sorted(set(self.pii_entities)),
                "mutated": bool(self.pii_mutated),
            },
            "trusted_wallet": {"verdict": self.trusted_wallet_verdict},
            "policy": policy,
            "replay": replay,
            "mpa": mpa,
        }


# ---------------------------------------------------------------------------
# Hash helpers over the control inputs (redacted where PII-bearing).
# ---------------------------------------------------------------------------


def policy_snapshot_hash(config: object) -> str:
    """Content hash of the *effective* policy config (the predicate identity).

    Hashes a canonical, float-free projection of the ``PolicyConfig`` (the
    effective policy after inheritance — the input ``f`` must re-derive against,
    per the design note's resolved open question). Amounts are stringified so no
    float enters the canonical bytes.
    """
    snap = _policy_config_snapshot(config)
    return _sha256_prefixed(snap)


def policy_limit_hash(config: object) -> str:
    """Content hash of just the limit surface of the policy (per the design's
    ``limit_hash``). A stable pointer to the numeric caps in force."""
    snap = _policy_config_snapshot(config)
    limits = {
        "max_per_call_usd": snap["max_per_call_usd"],
        "daily_limit_usd": snap["daily_limit_usd"],
        "per_endpoint": snap["per_endpoint"],
        "window_seconds": snap["window_seconds"],
    }
    return _sha256_prefixed(limits)


def _policy_config_snapshot(config: object) -> dict[str, object]:
    """Float-free canonical projection of a ``PolicyConfig`` (or dict)."""

    def _amt(v: object) -> str | None:
        return None if v is None else str(v)

    get = (
        (lambda k, d=None: config.get(k, d))
        if isinstance(config, Mapping)
        else (lambda k, d=None: getattr(config, k, d))
    )
    per_endpoint_raw = get("per_endpoint", {}) or {}
    per_endpoint = {k: _amt(v) for k, v in sorted(per_endpoint_raw.items())}
    return {
        "max_per_call_usd": _amt(get("max_per_call_usd")),
        "daily_limit_usd": _amt(get("daily_limit_usd")),
        "per_endpoint": per_endpoint,
        "window_seconds": get("window_seconds", 86_400),
    }


def fingerprint_hash(fingerprint: str) -> str:
    """``sha256:`` of a replay fingerprint — the fingerprint itself never enters
    the record (it is derived from the original, pre-redaction URL)."""
    return _hash_str(fingerprint)


def offer_hash(raw_offer: bytes | str) -> str:
    """``sha256:`` of the raw 402 payment offer bytes, exactly as received.

    The offer may carry PII, so only its byte digest enters the record — never
    the offer text. Callers should pass the transport's raw header/body bytes.
    ``str`` input is encoded as UTF-8 only for tests and legacy helpers.
    """
    raw = raw_offer.encode("utf-8") if isinstance(raw_offer, str) else bytes(raw_offer)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def details_hash(*, pay_to: str, amount: str, currency: str, network: str) -> str:
    """``sha256:`` over the **post-redaction** payment details (the design note's
    resolved rule: the proposal hash is taken over post-redaction details)."""
    return _sha256_prefixed(
        {"pay_to": pay_to, "amount": amount, "currency": currency, "network": network}
    )


def _utcnow_ms_z() -> str:
    """RFC3339 UTC with millisecond precision and trailing ``Z``."""
    dt = datetime.now(tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Attested content + thin decision_ref derivation.
# ---------------------------------------------------------------------------


def build_payment_decision_content(
    *,
    agent_id: str,
    payment_signer: str,
    network: str,
    binding: str,
    offer_hash: str | None = None,
    offer_hash_absent: str | None = None,
    details_hash: str,
    pay_to: str,
    amount: str,
    currency: str,
    resource_origin: str,
    controls: ControlResults,
    issued_at: str | None = None,
    policy_version: str = DEFAULT_POLICY_VERSION,
    parents: Sequence[str] | None = None,
    prior_decision_refs: Sequence[str] | None = None,
) -> dict[str, object]:
    """Build the ``presidio-hardened-x402/payment-decision@1`` attested content.

    The top-level ``verdict`` is set to ``f(controls)`` so the artifact is
    recomputable by construction — a verifier re-applies :func:`f_controls` to the
    ``controls{}`` block and gets the same value. All monetary values are strings;
    no float enters the content (``canonical_bytes`` rejects floats regardless).
    """
    controls_block = controls.to_controls()
    verdict = f_controls(controls_block)
    payment: dict[str, object] = {
        "details_hash": details_hash,
        "pay_to": pay_to,
        "amount": amount,
        "currency": currency,
        "resource_origin": resource_origin,
    }
    if offer_hash is not None:
        payment["offer_hash"] = offer_hash
    else:
        payment["offer_hash_absent"] = offer_hash_absent or "not-retained"

    return {
        "schema": PAYMENT_DECISION_SCHEMA_ID,
        "issued_at": issued_at or _utcnow_ms_z(),
        "agent_id": agent_id,
        "actor": {
            "payment_signer": payment_signer,
            "binding": binding,
            "network": network,
        },
        "payment": payment,
        "controls": controls_block,
        "verdict": verdict,
        "policy_version": policy_version,
        "provenance": {
            "parents": list(parents or []),
            "prior_decision_refs": list(prior_decision_refs or []),
        },
    }


def artifact_hash(content: Mapping[str, object]) -> str:
    """``sha256`` (64 lowercase hex) over the canonical bytes of the content —
    the artifact hash and the ``content_hash`` of the evidence ref."""
    return sha256_hex(content)


def compute_decision_ref(
    *,
    artifact_hash: str,
    policy_version: str,
    verdict: str,
    artifact_type: str = PAYMENT_DECISION_SCHEMA_ID,
) -> str:
    """The thin, self-describing ``decision_ref`` id.

    ``sha256(canonical_bytes({artifact_hash, artifact_type, policy_version,
    verdict}))`` — a stable correlation key whose four preimage fields travel in
    the envelope so any holder recomputes it independently.
    """
    return sha256_hex(
        decision_ref_preimage(
            artifact_hash=artifact_hash,
            policy_version=policy_version,
            verdict=verdict,
            artifact_type=artifact_type,
        )
    )


def decision_ref_preimage(
    *,
    artifact_hash: str,
    policy_version: str,
    verdict: str,
    artifact_type: str = PAYMENT_DECISION_SCHEMA_ID,
) -> dict[str, str]:
    """The four-field self-describing preimage of the ``decision_ref``."""
    return {
        "artifact_hash": artifact_hash,
        "artifact_type": artifact_type,
        "policy_version": policy_version,
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# Capability-chain provenance linkage (parents array).
# ---------------------------------------------------------------------------


def capability_parents(chain: VerifiedGrantChain | None) -> list[str]:
    """Provenance parents contributed by a capability chain (may be empty).

    When the policy in force was projected from a verified capability chain, the
    chain's **terminal ``grant_hash``** is the parent that binds this decision to
    the authority it was decided under (provenance-parents convention). ``None``
    (config-sourced policy) contributes no parent.
    """
    if chain is None:
        return []
    return [f"capability-grant:{chain.grants[-1].grant_hash}"]


def build_decision_evidence(
    content: Mapping[str, object],
    *,
    signing_key: str,
    algorithm: str = "ed25519",
    signer: str = DEFAULT_DECISION_SIGNER,
    key_id: str | None = None,
    source_version: str | None = None,
    parents: Sequence[str] | None = None,
    prior_decision_refs: Sequence[str] | None = None,
) -> dict[str, object]:
    """Build a signed ``presidio-hardened/evidence-ref@1`` envelope over *content*.

    The single evidence ref's ``content_hash`` is the artifact hash; the detached
    signature is over ``canonical({content_hash, signer})`` (the family primitive,
    :func:`mica.sign_evidence`) so it is byte-compatible with the family verifier.
    Fail-closed: no key ⇒ no envelope.

    ``parents`` links provenance parents — the capability grant hash when the
    policy came from a chain (:func:`capability_parents`) — and
    ``prior_decision_refs`` links earlier decision-refs of the *same* payment
    (e.g. a REFER that later resolved). Both are copied into the signed
    ``payment_decision.provenance`` block before hashing; the envelope-level
    ``provenance`` block is a convenience mirror for consumers.

    **No network I/O.** This function only computes hashes and a signature.
    """
    signed_content = dict(content)
    content_provenance = signed_content.get("provenance")
    parent_list = (
        list(parents)
        if parents is not None
        else list(content_provenance.get("parents", []))
        if isinstance(content_provenance, Mapping)
        else []
    )
    prior_list = (
        list(prior_decision_refs)
        if prior_decision_refs is not None
        else list(content_provenance.get("prior_decision_refs", []))
        if isinstance(content_provenance, Mapping)
        else []
    )
    if not all(isinstance(p, str) and p for p in parent_list) or not all(
        isinstance(p, str) and p for p in prior_list
    ):
        raise DecisionRefError("provenance parents/prior_decision_refs must be non-empty strings")
    signed_content["provenance"] = {
        "parents": parent_list,
        "prior_decision_refs": prior_list,
    }

    if signed_content.get("schema") != PAYMENT_DECISION_SCHEMA_ID:
        raise DecisionRefError(
            f"attested content schema must be {PAYMENT_DECISION_SCHEMA_ID!r}; "
            f"got {signed_content.get('schema')!r}"
        )
    # Recompute the verdict fail-closed at emission: never sign a non-recomputable
    # artifact (the line between attested and admissible — autogen#7353).
    controls = signed_content.get("controls")
    if not isinstance(controls, Mapping):
        raise DecisionRefError("attested content missing a controls{} block")
    recomputed = f_controls(controls)
    if signed_content.get("verdict") != recomputed:
        raise DecisionRefError(
            f"refusing to sign a non-recomputable decision: recorded verdict "
            f"{signed_content.get('verdict')!r} != f(controls) {recomputed!r} (fail-closed)"
        )

    a_hash = artifact_hash(signed_content)
    signature = sign_evidence(a_hash, signer, algorithm=algorithm, key=signing_key)
    version = source_version or _library_version()
    claimed_at = _utcnow_ms_z()
    policy_version = str(signed_content.get("policy_version", DEFAULT_POLICY_VERSION))
    verdict = str(signed_content.get("verdict"))
    d_ref = compute_decision_ref(
        artifact_hash=a_hash, policy_version=policy_version, verdict=verdict
    )

    ref = {
        "item_id": d_ref,
        "source": signer,
        "source_version": version,
        "ledger_ref": f"x402-decision:{d_ref}",
        "content_hash": a_hash,
        "signer": signer,
        "signature": signature,
        "claimed_at": claimed_at,
    }
    envelope: dict[str, object] = {
        "schema": EVIDENCE_SCHEMA_ID,
        "use_case": "x402-payment-decision",
        "source": signer,
        "source_version": version,
        "generated_at": claimed_at,
        "attested_content": {"schema": PAYMENT_DECISION_SCHEMA_ID},
        "evidence": [ref],
        # Companion data (ignored by generic evidence-ref@1 verifiers; consumed by
        # verify_decision_ref below):
        "signing_algorithm": algorithm,
        "payment_decision": signed_content,
        "artifact_hash": a_hash,
        "decision_ref": d_ref,
        "decision_ref_preimage_fields": list(DECISION_REF_PREIMAGE_FIELDS),
        "decision_ref_preimage": decision_ref_preimage(
            artifact_hash=a_hash, policy_version=policy_version, verdict=verdict
        ),
        "provenance": {"parents": parent_list, "prior_decision_refs": prior_list},
        "disclaimer": (
            "Proof-carrying record of one x402 payment decision under a declared "
            "predicate: it is tamper-evident (signed) and admissible (verdict = "
            "f(controls) recomputes). It does NOT prove the process was uncompromised "
            "or that the declared controls are the real controls (no TEE claim)."
        ),
    }
    if key_id is not None:
        ref["key_id"] = key_id
        envelope["key_id"] = key_id
    return envelope


def _library_version() -> str:
    from . import __version__

    return __version__


# ---------------------------------------------------------------------------
# Verifier (read path) — fully offline, fail-closed, distinct reasons.
# ---------------------------------------------------------------------------

#: Distinct fail-closed reason codes (one per verification layer).
REASON_MALFORMED = "malformed"
REASON_HASH_MISMATCH = "hash_mismatch"
REASON_DECISION_REF_MISMATCH = "decision_ref_mismatch"
REASON_VERDICT_NOT_RECOMPUTABLE = "verdict_not_recomputable"
REASON_SIGNER_EQUALS_RUNTIME = "signer_equals_runtime"
REASON_UNKNOWN_SIGNER = "unknown_signer"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_PARENT_LINKAGE = "parent_linkage"


@dataclass(frozen=True)
class DecisionRefVerification:
    """The outcome of verifying one decision-ref envelope (never raises to caller).

    ``ok`` is the fail-closed conjunction of every layer. When ``ok`` is false,
    ``reason`` carries exactly one distinct reason code (the first layer that
    failed, in verification order) so a caller can branch on *why*.
    """

    ok: bool
    reason: str | None = None
    decision_ref: str | None = None
    verdict: str | None = None
    recomputed_verdict: str | None = None
    checked: tuple[str, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:  # let `if result:` mean "verified"
        return self.ok


def _fail(reason: str, **kw: object) -> DecisionRefVerification:
    return DecisionRefVerification(ok=False, reason=reason, **kw)  # type: ignore[arg-type]


def verify_decision_ref(
    envelope: Mapping[str, object],
    trust_store: str | Mapping[str, object],
    *,
    require_parents: Sequence[str] | None = None,
    actor_controllers: Sequence[str] | None = None,
) -> DecisionRefVerification:
    """Verify one decision-ref envelope offline, fail-closed, distinct reasons.

    Layers, in order (first failure wins, each its own reason code):

    1. **structure** — envelope shape, exactly one evidence ref, present
       ``payment_decision`` companion (``malformed``).
    2. **hash integrity** — ``content_hash`` == ``sha256(canonical(content))``
       (``hash_mismatch``); the thin ``decision_ref`` recomputes from its declared
       preimage and equals the recorded id (``decision_ref_mismatch``).
    3. **recompute** — recorded ``verdict`` == ``f(controls)``
       (``verdict_not_recomputable``): the line between attested and admissible.
    4. **admission** — the signer must not resolve to the actor's own controller
       (self-approval fails closed — ``signer_equals_runtime``). Pass
       ``actor_controllers`` to name the wallets/runtimes that count as the actor;
       the actor's ``payment_signer`` is always included.
    5. **signature** — the detached signature verifies against a key for ``signer``
       in the trust store (``unknown_signer`` / ``bad_signature``).
    6. **parent linkage** — if ``require_parents`` is given, every required parent
       must appear in the recorded ``provenance.parents`` (``parent_linkage``).

    Never raises to the caller — a malformed input returns
    ``ok=False`` with a reason. This guarantees verification itself cannot fail open.
    """
    checked: list[str] = []

    # 1. Structure.
    if not isinstance(envelope, Mapping):
        return _fail(REASON_MALFORMED)
    evidence = envelope.get("evidence")
    content = envelope.get("payment_decision")
    if (
        not isinstance(evidence, list)
        or len(evidence) != 1
        or not isinstance(evidence[0], Mapping)
        or not isinstance(content, Mapping)
    ):
        return _fail(REASON_MALFORMED)
    ref = evidence[0]
    content_hash = ref.get("content_hash")
    signer = ref.get("signer")
    signature = ref.get("signature")
    if not (
        isinstance(content_hash, str) and isinstance(signer, str) and isinstance(signature, str)
    ):
        return _fail(REASON_MALFORMED)
    if content.get("schema") != PAYMENT_DECISION_SCHEMA_ID:
        return _fail(REASON_MALFORMED)
    checked.append("structure")

    # 2. Hash integrity.
    try:
        recomputed_hash = sha256_hex(content)
    except EvidenceError:
        return _fail(REASON_MALFORMED, checked=tuple(checked))
    if recomputed_hash != content_hash:
        return _fail(REASON_HASH_MISMATCH, checked=tuple(checked))
    policy_version = str(content.get("policy_version", DEFAULT_POLICY_VERSION))
    verdict = content.get("verdict")
    if not isinstance(verdict, str):
        return _fail(REASON_MALFORMED, checked=tuple(checked))
    recomputed_ref = compute_decision_ref(
        artifact_hash=recomputed_hash, policy_version=policy_version, verdict=verdict
    )
    recorded_ref = envelope.get("decision_ref")
    if recorded_ref is not None and recorded_ref != recomputed_ref:
        return _fail(
            REASON_DECISION_REF_MISMATCH, decision_ref=recomputed_ref, checked=tuple(checked)
        )
    checked.append("hash")

    # 3. Recompute (attested -> admissible).
    controls = content.get("controls")
    if not isinstance(controls, Mapping):
        return _fail(REASON_MALFORMED, decision_ref=recomputed_ref, checked=tuple(checked))
    try:
        recomputed_verdict = f_controls(controls)
    except DecisionRefError:
        return _fail(REASON_MALFORMED, decision_ref=recomputed_ref, checked=tuple(checked))
    if recomputed_verdict != verdict:
        return _fail(
            REASON_VERDICT_NOT_RECOMPUTABLE,
            decision_ref=recomputed_ref,
            verdict=verdict,
            recomputed_verdict=recomputed_verdict,
            checked=tuple(checked),
        )
    checked.append("recompute")

    # 4. Admission (signer must not be the actor's own controller).
    controllers = set(actor_controllers or ())
    actor = content.get("actor")
    if isinstance(actor, Mapping) and isinstance(actor.get("payment_signer"), str):
        controllers.add(actor["payment_signer"])
    key_id = ref.get("key_id") if isinstance(ref.get("key_id"), str) else None
    if signer in controllers or (key_id is not None and key_id in controllers):
        return _fail(
            REASON_SIGNER_EQUALS_RUNTIME,
            decision_ref=recomputed_ref,
            verdict=verdict,
            recomputed_verdict=recomputed_verdict,
            checked=tuple(checked),
        )
    checked.append("admission")

    # 5. Signature.
    try:
        trust = load_trust_store(trust_store)
    except EvidenceError:
        return _fail(REASON_MALFORMED, decision_ref=recomputed_ref, checked=tuple(checked))
    entry = trust.get(signer)
    if entry is None:
        return _fail(REASON_UNKNOWN_SIGNER, decision_ref=recomputed_ref, checked=tuple(checked))
    alg = entry.get("alg")
    keys = entry.get("keys")
    verify = verify_ed25519 if alg == "ed25519" else verify_hmac
    if not (
        isinstance(keys, list)
        and any(isinstance(k, str) and verify(content_hash, signer, signature, k) for k in keys)
    ):
        return _fail(REASON_BAD_SIGNATURE, decision_ref=recomputed_ref, checked=tuple(checked))
    checked.append("signature")

    # 6. Parent linkage.
    if require_parents:
        provenance = content.get("provenance")
        recorded_parents = provenance.get("parents") if isinstance(provenance, Mapping) else None
        recorded_set = set(recorded_parents) if isinstance(recorded_parents, list) else set()
        if not set(require_parents).issubset(recorded_set):
            return _fail(
                REASON_PARENT_LINKAGE,
                decision_ref=recomputed_ref,
                verdict=verdict,
                recomputed_verdict=recomputed_verdict,
                checked=tuple(checked),
            )
    checked.append("parents")

    return DecisionRefVerification(
        ok=True,
        reason=None,
        decision_ref=recomputed_ref,
        verdict=verdict,
        recomputed_verdict=recomputed_verdict,
        checked=tuple(checked),
    )


# ---------------------------------------------------------------------------
# Pluggable emitter — the opt-in seam wired into the pipeline (default OFF).
# Mirrors the AuditWriter pattern: a small object the gateway is handed; when
# absent, no decision-ref code runs and behaviour is byte-identical.
# ---------------------------------------------------------------------------


class DecisionRefWriter:
    """Sink protocol for emitted decision-ref envelopes (structural).

    Any object with a ``write(envelope: dict) -> None`` method qualifies. Two
    built-ins are provided below. A writer MUST NOT perform network I/O on the
    emit path (the design note forbids it); file writers follow the audit-log
    file conventions.
    """

    def write(self, envelope: Mapping[str, object]) -> None:  # pragma: no cover - protocol
        raise NotImplementedError


class NullDecisionRefWriter(DecisionRefWriter):
    """Discards envelopes. The explicit off-switch used in tests."""

    def write(self, envelope: Mapping[str, object]) -> None:
        return


class FileDecisionRefWriter(DecisionRefWriter):
    """Appends one JSON envelope per line to a file (JSON-L), fsync by default.

    Mirrors :class:`~presidio_x402.audit_log.FileAuditWriter`: per-write fsync so
    the record survives a kernel-level process death, a lock for thread-safety,
    UTF-8, ``ensure_ascii`` off for byte-parity with the family canonical form.
    """

    def __init__(self, path: str, *, fsync: bool = True) -> None:
        import threading

        self._path = path
        self._fsync = fsync
        self._lock = threading.Lock()

    def write(self, envelope: Mapping[str, object]) -> None:
        import json
        import os

        line = json.dumps(dict(envelope), sort_keys=True, ensure_ascii=False, default=str)
        with self._lock, open(self._path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            if self._fsync:
                fh.flush()
                os.fsync(fh.fileno())


@dataclass
class DecisionRefEmitter:
    """Builds and writes a decision-ref envelope per payment (opt-in).

    Construct with a signing key (Ed25519 hex or HMAC secret) plus emitter
    identity, hand it to :class:`~presidio_x402.gateway.HardenedX402Client` (or
    :class:`~presidio_x402.core.ScreeningPipeline`) as ``decision_ref_emitter``.
    When present, the pipeline calls :meth:`emit` once per payment with the
    gathered :class:`ControlResults`; when ``None`` (the default), no
    decision-ref code path runs at all.

    Signer independence is claim-critical (design note "Evidence envelope"): the
    ``signer`` here should be a policy/approval identity distinct from the payment
    wallet, or the record is only self-attested — :func:`verify_decision_ref`
    fails closed on self-approval.
    """

    signing_key: str
    signer: str = DEFAULT_DECISION_SIGNER
    algorithm: str = "ed25519"
    key_id: str | None = None
    writer: DecisionRefWriter | None = None
    policy_version: str = DEFAULT_POLICY_VERSION

    def emit(
        self,
        *,
        agent_id: str,
        payment_signer: str,
        network: str,
        binding: str,
        offer_hash: str | None = None,
        offer_hash_absent: str | None = None,
        details_hash: str,
        pay_to: str,
        amount: str,
        currency: str,
        resource_origin: str,
        controls: ControlResults,
        parents: Sequence[str] | None = None,
        prior_decision_refs: Sequence[str] | None = None,
    ) -> dict[str, object]:
        """Build, sign, write (if a writer is set) and return one envelope.

        No network I/O. Returns the envelope so a caller can archive it or attach
        the ``decision_ref`` to an audit event.
        """
        content = build_payment_decision_content(
            agent_id=agent_id,
            payment_signer=payment_signer,
            network=network,
            binding=binding,
            offer_hash=offer_hash,
            offer_hash_absent=offer_hash_absent,
            details_hash=details_hash,
            pay_to=pay_to,
            amount=amount,
            currency=currency,
            resource_origin=resource_origin,
            controls=controls,
            policy_version=self.policy_version,
            parents=parents,
            prior_decision_refs=prior_decision_refs,
        )
        envelope = build_decision_evidence(
            content,
            signing_key=self.signing_key,
            algorithm=self.algorithm,
            signer=self.signer,
            key_id=self.key_id,
            parents=parents,
            prior_decision_refs=prior_decision_refs,
        )
        if self.writer is not None:
            self.writer.write(envelope)
        return envelope


# ---------------------------------------------------------------------------
# Minimal CLI verifier: ``python -m presidio_x402.decision_ref <env.json> <trust.json>``
# Fully offline; exit 0 on verify, 1 on any fail-closed reason, 2 on usage error.
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Verify a decision-ref envelope (or a JSON-L set) against a trust store.

    Usage::

        python -m presidio_x402.decision_ref ENVELOPE.json TRUST.json [--parent P ...]

    ENVELOPE.json is either one envelope object or a JSON-L file of envelopes (one
    per line, as :class:`FileDecisionRefWriter` writes). Prints one line per
    record with its ``decision_ref``, verdict, and pass/fail reason. Exit 0 iff
    **every** record verifies; 1 if any fails; 2 on a usage error. No network I/O.
    """
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(prog="presidio_x402.decision_ref")
    parser.add_argument("envelope", help="path to an envelope .json or JSON-L file")
    parser.add_argument("trust_store", help="path to a trust-store@1 JSON file")
    parser.add_argument(
        "--parent",
        action="append",
        default=[],
        help="a required provenance parent (repeatable); e.g. capability-grant:<hash>",
    )
    args = parser.parse_args(argv)

    from pathlib import Path

    try:
        raw = Path(args.envelope).read_text(encoding="utf-8")
        trust_text = Path(args.trust_store).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    stripped = raw.strip()
    try:
        first = json.loads(stripped)
        envelopes = [first] if isinstance(first, dict) else list(first)
    except json.JSONDecodeError:
        envelopes = [json.loads(line) for line in stripped.splitlines() if line.strip()]

    require_parents = args.parent or None
    all_ok = True
    for env in envelopes:
        result = verify_decision_ref(env, trust_text, require_parents=require_parents)
        status = "OK" if result.ok else f"FAIL({result.reason})"
        print(f"{result.decision_ref or '<no-ref>'}  verdict={result.verdict}  {status}")
        all_ok = all_ok and result.ok
    return 0 if all_ok else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
