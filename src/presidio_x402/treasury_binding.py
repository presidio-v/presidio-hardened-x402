# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Treasury binding — exporting one payment decision as an audit-grade bundle.

A **treasury bundle** is the hand-off artifact that lets an agent payment
reconcile into a ledger's close: the signed ``payment-decision@1`` record of
*why* the payment was allowed, joined to the on-chain settlement that actually
moved the money, both verifiable offline against a pinned trust store.

Two artifacts, one join::

    payment-decision@1  (v0.9.0, decision_ref.py)  "the library concluded ALLOW under P"
             │
             │  decision_ref
             ▼
    settlement-ref@1     (this module)                "that decision authorized THIS settlement"
             │
             │  chain + tx_hash + block_number + log_index
             ▼
    the L1 chain observation the ledger already ingests independently

**What the join is, and what it is not.** ``settlement-ref@1`` is a *signed
off-chain join record*: the x402 policy signer's statement that a named decision
authorized a named settlement. It is not an on-chain anchor. An x402 payment
settles via ERC-3009 ``transferWithAuthorization``, whose calldata carries no
decision digest, so there is nothing on-chain to check a ``calldata_digest``
against; and if the committed ``tx_hash`` *is* the settlement, a
"decision precedes settlement" timestamp check compares a value with itself.
Rather than ship two fields that assert what they cannot prove, this artifact
asserts only what the signer can: *this decision, that transaction, signed*. The
auditor already trusts that signer for the decision itself; the join rides the
same trust, and being signed is what lets a consumer reject a forged or swapped
join at its boundary.

The strictly stronger alternative — a pre-settlement commitment transaction
carrying ``sha256(decision_ref)``, making the join on-chain rather than
signer-asserted — costs an extra chain transaction on every payment and changes
the settle path. It is deliberately deferred as an opt-in "strong anchor" mode.

**Fail-closed export.** :func:`export_bundle` re-runs the full
:func:`~presidio_x402.decision_ref.verify_decision_ref` (structure, hash,
``verdict == f(controls)``, self-approval admission, signature, parents) and
refuses to emit a bundle for an envelope that does not verify. It additionally
refuses a non-terminal (``REFER``) verdict, bounds the caller-supplied identity
strings, and bounds canonical nesting depth. No network I/O on any path here —
export and verify are both offline.

**Privacy bound, stated honestly.** The ``controls{}`` block of a decision-ref is
*structurally* PII-free (hashes, entity-type labels, enum verdicts — there is no
field that accepts a raw string). The top-level identity fields are **not**:
``agent_id``, ``pay_to``, ``resource_origin`` and ``mpa.approval_refs`` are
caller-supplied strings, and a wallet address is pseudonymous personal data to a
GDPR-minded auditor. They are present by design — a ledger cannot reconcile an
anonymous payment — so the mitigation is a *value bound* (length + charset,
:func:`check_identity_bounds`), not a claim that no free text can appear. The
settlement facts committed to the chain-join deliberately exclude the payer
address even though the receipt carries it: the join needs the transaction, not
the counterparty.

CLI (offline; exit 0 verified, 1 fail-closed, 2 usage)::

    python -m presidio_x402.treasury_binding export ENVELOPE.json \\
        --settlement settle.json --trust trust.json --key-file policy.key > bundle.json
    python -m presidio_x402.treasury_binding verify bundle.json trust.json
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .decision_ref import (
    DecisionRefError,
    _utcnow_ms_z,  # deliberately shared: both artifacts must timestamp identically
    verify_decision_ref,
)
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
    from ._types import SettlementReceipt

SETTLEMENT_REF_SCHEMA_ID = "presidio-hardened-x402/settlement-ref@1"
SETTLEMENT_FACTS_SCHEMA_ID = "presidio-hardened-x402/settlement-facts@1"
TREASURY_BUNDLE_SCHEMA_ID = "presidio-hardened-x402/treasury-bundle@1"

#: Verdicts a bundle may carry. ``REFER`` is excluded: an unresolved quorum is
#: an interim state, and reconciling against it would book the wrong conclusion
#: when it later resolves (the terminal record links the interim one through
#: ``prior_decision_refs``). ``DENY`` *is* exportable on purpose — a payment that
#: settled despite a DENY is precisely the anomaly an auditor must be able to
#: see, and refusing to export it would hide it.
TERMINAL_VERDICTS = frozenset({"ALLOW", "DENY"})

#: Maximum canonical nesting depth, matching the sibling Rust canonicaliser's
#: ``MAX_DEPTH``. Depth is defined **exactly** as: the top-level value sits at
#: depth 0, and every step into a nested object or array adds 1. A value at depth
#: 128 is accepted; a value at depth 129 is rejected. Both sides must agree on
#: this definition or the boundary vector grades differently in each language.
MAX_CANONICAL_DEPTH = 128

#: Upper bound for the integers a settlement-ref commits to. The sibling
#: canonicaliser deserialises JSON numbers into ``i64``/``u64``, so an integer
#: beyond ``i64::MAX`` is representable in Python and *not* in Rust — bounding it
#: here by schema is what keeps "both sides accept, or both reject" true.
I64_MAX = 2**63 - 1

#: Length bounds for the caller-supplied identity strings (T-TB-3). Values, not
#: field names: the point is to bound what a caller can put in a field that is
#: known to be free text, not to pretend the fields do not exist.
IDENTITY_BOUNDS = {
    "agent_id": 256,
    "actor.payment_signer": 128,
    "payment.pay_to": 128,
    "payment.resource_origin": 256,
}
#: ``mpa.approval_refs`` is a list; bound both its length and each element.
MAX_APPROVAL_REFS = 32
MAX_APPROVAL_REF_LEN = 512

#: Unicode general categories rejected inside an identity string: control,
#: format, surrogate, private-use and unassigned. This is a *charset* bound
#: rather than an ASCII allowlist — a Cyrillic or CJK agent id is legitimate,
#: a bidi-override or an unpaired surrogate in an auditor's disclosure pack is
#: not.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

#: Separator for the settlement uniqueness key. ``|`` cannot occur in a CAIP-2
#: chain id, a transaction hash, or a decimal index, so the key parses back
#: unambiguously even though the chain id itself contains a colon.
SETTLEMENT_KEY_SEP = "|"


class TreasuryBindingError(DecisionRefError):
    """Raised on any fail-closed refusal in the binding (export path).

    Subclasses :class:`~presidio_x402.decision_ref.DecisionRefError` (and through
    it :class:`~presidio_x402.mica.EvidenceError`), so a caller already handling
    evidence failures also handles these.
    """


# ---------------------------------------------------------------------------
# Canonical-domain bounds enforced on the export path.
# ---------------------------------------------------------------------------


def check_canonical_depth(payload: object, *, max_depth: int = MAX_CANONICAL_DEPTH) -> None:
    """Reject a payload nested deeper than the shared canonical bound.

    Iterative by design: a recursive walk over a hostile 10 000-deep structure
    raises ``RecursionError`` (an interpreter accident) instead of the typed
    refusal a fail-closed boundary owes its caller.
    """
    stack: list[tuple[object, int]] = [(payload, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, Mapping):
            children: Sequence[object] = list(node.values())
        elif isinstance(node, (list, tuple)):
            children = list(node)
        else:
            continue
        if depth + 1 > max_depth and children:
            raise TreasuryBindingError(
                f"canonical nesting exceeds the shared depth bound of {max_depth} "
                "(top-level value at depth 0); a sibling canonicaliser rejects it, "
                "so this side must reject it identically"
            )
        stack.extend((child, depth + 1) for child in children)


def _check_identity_string(value: object, label: str, max_len: int, *, allow_empty: bool) -> None:
    if not isinstance(value, str):
        raise TreasuryBindingError(
            f"identity field {label!r} must be a string, got {type(value).__name__}"
        )
    if not value and not allow_empty:
        raise TreasuryBindingError(f"identity field {label!r} must not be empty")
    if len(value) > max_len:
        raise TreasuryBindingError(
            f"identity field {label!r} exceeds {max_len} characters ({len(value)})"
        )
    for index, char in enumerate(value):
        if unicodedata.category(char) in _FORBIDDEN_CATEGORIES:
            raise TreasuryBindingError(
                f"identity field {label!r} carries a disallowed character at position "
                f"{index} (Unicode category {unicodedata.category(char)}): control, format, "
                "surrogate, private-use and unassigned code points are refused"
            )


def check_identity_bounds(content: Mapping[str, object]) -> None:
    """Bound every caller-supplied identity string in a decision-ref's content.

    The five values a caller controls verbatim — ``agent_id``,
    ``actor.payment_signer``, ``payment.pay_to``, ``payment.resource_origin`` and
    each ``controls.mpa.approval_refs`` entry — are checked for length and
    charset. ``agent_id`` may be empty (the pipeline emits ``""`` when no agent
    id is configured); the others may not.

    This does **not** claim the record is PII-free. It claims the record cannot
    carry an unbounded or non-printable caller string into an auditor's hands.
    """
    check_canonical_depth(content)
    _check_identity_string(
        content.get("agent_id"), "agent_id", IDENTITY_BOUNDS["agent_id"], allow_empty=True
    )

    actor = content.get("actor")
    if not isinstance(actor, Mapping):
        raise TreasuryBindingError("decision content must carry an actor{} block")
    _check_identity_string(
        actor.get("payment_signer"),
        "actor.payment_signer",
        IDENTITY_BOUNDS["actor.payment_signer"],
        allow_empty=False,
    )

    payment = content.get("payment")
    if not isinstance(payment, Mapping):
        raise TreasuryBindingError("decision content must carry a payment{} block")
    for name in ("pay_to", "resource_origin"):
        _check_identity_string(
            payment.get(name),
            f"payment.{name}",
            IDENTITY_BOUNDS[f"payment.{name}"],
            allow_empty=False,
        )

    controls = content.get("controls")
    mpa = controls.get("mpa") if isinstance(controls, Mapping) else None
    refs = mpa.get("approval_refs") if isinstance(mpa, Mapping) else None
    if refs is None:
        return
    if not isinstance(refs, list):
        raise TreasuryBindingError("controls.mpa.approval_refs must be a list when present")
    if len(refs) > MAX_APPROVAL_REFS:
        raise TreasuryBindingError(
            f"controls.mpa.approval_refs carries {len(refs)} entries (max {MAX_APPROVAL_REFS})"
        )
    for index, ref in enumerate(refs):
        _check_identity_string(
            ref, f"controls.mpa.approval_refs[{index}]", MAX_APPROVAL_REF_LEN, allow_empty=False
        )


# ---------------------------------------------------------------------------
# Settlement facts — the operator-completable input to the join.
# ---------------------------------------------------------------------------


def _validate_caip2(chain: object) -> str:
    if not isinstance(chain, str) or not chain:
        raise TreasuryBindingError("settlement 'chain' must be a non-empty CAIP-2 chain id")
    namespace, sep, reference = chain.partition(":")
    ok = (
        sep
        and chain.isascii()
        and 3 <= len(namespace) <= 8
        and all(c.isdigit() or (c.islower() and c.isalpha()) or c == "-" for c in namespace)
        and 1 <= len(reference) <= 32
        and all(c.isalnum() or c in "-_" for c in reference)
    )
    if not ok:
        raise TreasuryBindingError(
            f"settlement 'chain' {chain!r} is not a CAIP-2 chain id "
            "([-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}), e.g. 'eip155:8453'"
        )
    return chain


def _validate_tx_hash(tx_hash: object, chain: str) -> str:
    if not isinstance(tx_hash, str) or not tx_hash:
        raise TreasuryBindingError("settlement 'tx_hash' must be a non-empty string")
    if chain.startswith("eip155:"):
        # Canonical form for EVM: 0x + 64 lowercase hex. Case is normalised (not
        # merely accepted) so two operators exporting the same settlement produce
        # byte-identical join records — an id that differs by case would defeat
        # the one-settlement-one-leg uniqueness check downstream.
        candidate = tx_hash.lower()
        body = candidate[2:] if candidate.startswith("0x") else ""
        if (
            not candidate.startswith("0x")
            or len(body) != 64
            or not all(c in "0123456789abcdef" for c in body)
        ):
            raise TreasuryBindingError(
                f"settlement 'tx_hash' {tx_hash!r} is not an EVM transaction hash "
                "(0x + 64 hex) for an eip155 chain"
            )
        return candidate
    if (
        len(tx_hash) > 128
        or not tx_hash.isascii()
        or not all(c.isalnum() or c in "-_:" for c in tx_hash)
    ):
        raise TreasuryBindingError(
            f"settlement 'tx_hash' {tx_hash!r} is not a bounded ASCII transaction id"
        )
    return tx_hash


def _validate_index(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TreasuryBindingError(
            f"settlement {label!r} must be an integer (got {type(value).__name__}); "
            "the operator supplies it from a chain lookup keyed by tx_hash"
        )
    if not 0 <= value <= I64_MAX:
        raise TreasuryBindingError(
            f"settlement {label!r} must be within [0, {I64_MAX}] (i64::MAX); a sibling "
            "canonicaliser cannot represent a larger integer, so this side rejects it too"
        )
    return value


@dataclass(frozen=True)
class SettlementFacts:
    """The four chain facts a settlement-ref commits to, validated.

    ``chain`` and ``tx_hash`` are observable by the paying client on the paid
    response; ``block_number`` and ``log_index`` are **not** — the x402
    settlement echo carries neither, so the operator completes them from a chain
    or indexer lookup keyed by the transaction hash. That is the documented
    correlation procedure, and it is required rather than optional: without a log
    index there is no key on which a downstream ledger can enforce "one
    settlement → one leg".
    """

    chain: str
    tx_hash: str
    block_number: int
    log_index: int

    def __post_init__(self) -> None:
        chain = _validate_caip2(self.chain)
        object.__setattr__(self, "chain", chain)
        object.__setattr__(self, "tx_hash", _validate_tx_hash(self.tx_hash, chain))
        object.__setattr__(
            self, "block_number", _validate_index(self.block_number, "block_number")
        )
        object.__setattr__(self, "log_index", _validate_index(self.log_index, "log_index"))

    @property
    def settlement_key(self) -> str:
        """``chain|tx_hash|log_index`` — the uniqueness key for the join.

        A downstream ledger enforces "at most one settlement-ref per (period,
        chain, tx_hash, log_index)" on this value. ``block_number`` is
        deliberately absent: it is implied by the transaction hash, and including
        it would let a wrong-but-plausible height mint a second distinct key for
        one settlement.
        """
        return SETTLEMENT_KEY_SEP.join((self.chain, self.tx_hash, str(self.log_index)))

    def to_dict(self) -> dict[str, object]:
        """The committed block, in canonical field order (sorted on encode)."""
        return {
            "block_number": self.block_number,
            "chain": self.chain,
            "log_index": self.log_index,
            "tx_hash": self.tx_hash,
        }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> SettlementFacts:
        """Build from an operator settlement file (or any of its supersets).

        Accepts the record :func:`settlement_facts_record` writes — including the
        ``payer`` and ``receipt_hash`` fields, which are read and *dropped*: the
        join commits to the transaction, never to the counterparty.
        """
        if not isinstance(raw, Mapping):
            raise TreasuryBindingError("settlement facts must be a JSON object")
        required = ("chain", "tx_hash", "block_number", "log_index")
        missing = [k for k in required if raw.get(k) is None]
        if missing:
            raise TreasuryBindingError(
                f"settlement facts missing {', '.join(missing)}; block_number and log_index "
                "are not echoed by the x402 settlement receipt and must be completed by the "
                "operator from a chain lookup keyed by tx_hash"
            )
        return cls(
            chain=raw["chain"],  # type: ignore[arg-type]
            tx_hash=raw["tx_hash"],  # type: ignore[arg-type]
            block_number=raw["block_number"],  # type: ignore[arg-type]
            log_index=raw["log_index"],  # type: ignore[arg-type]
        )


def settlement_facts_record(
    receipt: SettlementReceipt, *, decision_ref: str | None = None
) -> dict[str, object]:
    """Render an observed receipt as the operator-completable settlement file.

    This is what a :class:`SettlementWriter` persists and what
    ``export --settlement`` consumes once ``block_number`` and ``log_index`` are
    filled in. ``complete`` says whether that step is still outstanding, so the
    gap is visible in the file itself rather than discovered at export time.
    """
    return {
        "schema": SETTLEMENT_FACTS_SCHEMA_ID,
        "decision_ref": decision_ref,
        "chain": receipt.chain,
        "network": receipt.network,
        "tx_hash": receipt.tx_hash,
        "block_number": receipt.block_number,
        "log_index": receipt.log_index,
        "payer": receipt.payer,
        "success": receipt.success,
        "observed_at": receipt.observed_at,
        "receipt_hash": receipt.receipt_hash,
        "complete": receipt.is_complete,
        "note": (
            "block_number and log_index are not carried by the x402 settlement echo; "
            "complete them from a chain/indexer lookup keyed by tx_hash before export."
        ),
    }


# ---------------------------------------------------------------------------
# Settlement sinks — mirrors the audit-log / decision-ref writer conventions.
# ---------------------------------------------------------------------------


class SettlementWriter:
    """Sink protocol for observed settlement records (structural).

    Any object with a ``write(record: Mapping) -> None`` method qualifies. A
    writer MUST NOT perform network I/O on the capture path — it runs inline on
    the client's paid response.
    """

    def write(self, record: Mapping[str, object]) -> None:  # pragma: no cover - protocol
        raise NotImplementedError


class NullSettlementWriter(SettlementWriter):
    """Discards records. The explicit off-switch used in tests."""

    def write(self, record: Mapping[str, object]) -> None:
        return


class FileSettlementWriter(SettlementWriter):
    """Appends one JSON record per line to a file (JSON-L), fsync by default.

    Mirrors :class:`~presidio_x402.decision_ref.FileDecisionRefWriter`: per-write
    fsync so the record survives a kernel-level process death, a lock for
    thread-safety, UTF-8, ``ensure_ascii`` off for byte-parity with the family
    canonical form.
    """

    def __init__(self, path: str, *, fsync: bool = True) -> None:
        import threading

        self._path = path
        self._fsync = fsync
        self._lock = threading.Lock()

    def write(self, record: Mapping[str, object]) -> None:
        import json
        import os

        line = json.dumps(dict(record), sort_keys=True, ensure_ascii=False, default=str)
        with self._lock, open(self._path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            if self._fsync:
                fh.flush()
                os.fsync(fh.fileno())


# ---------------------------------------------------------------------------
# settlement-ref@1 — the signed off-chain join record.
# ---------------------------------------------------------------------------


def build_settlement_ref_content(
    *, decision_ref: str, facts: SettlementFacts, issued_at: str | None = None
) -> dict[str, object]:
    """The attested ``settlement-ref@1`` content.

    Commits to exactly five values: the decision it joins, and the four chain
    facts that identify the settlement log entry. Nothing else — no calldata
    digest, no precedence timestamp, no payer.
    """
    if not (isinstance(decision_ref, str) and len(decision_ref) == 64):
        raise TreasuryBindingError("decision_ref must be the 64-hex thin decision id")
    if not all(c in "0123456789abcdef" for c in decision_ref):
        raise TreasuryBindingError("decision_ref must be lowercase hex")
    return {
        "schema": SETTLEMENT_REF_SCHEMA_ID,
        "issued_at": issued_at or _utcnow_ms_z(),
        "decision_ref": decision_ref,
        "settlement": facts.to_dict(),
    }


def build_settlement_evidence(
    content: Mapping[str, object],
    *,
    signing_key: str,
    algorithm: str = "ed25519",
    signer: str,
    key_id: str | None = None,
    source_version: str | None = None,
) -> dict[str, object]:
    """Sign a ``settlement-ref@1`` content into a family ``evidence-ref@1`` envelope.

    Same primitives as the decision-ref envelope
    (:func:`~presidio_x402.mica.sign_evidence` over
    ``canonical({content_hash, signer})``) so one verifier handles both. The
    ``settlement_ref`` id is the content hash itself: unlike the decision-ref
    there is no thin four-field preimage, because every field of this content is
    already part of the join and nothing would be abbreviated away.

    **No network I/O.**
    """
    if content.get("schema") != SETTLEMENT_REF_SCHEMA_ID:
        raise TreasuryBindingError(
            f"attested content schema must be {SETTLEMENT_REF_SCHEMA_ID!r}; "
            f"got {content.get('schema')!r}"
        )
    facts = SettlementFacts.from_mapping(content.get("settlement") or {})
    a_hash = sha256_hex(content)
    signature = sign_evidence(a_hash, signer, algorithm=algorithm, key=signing_key)
    version = source_version or _library_version()
    claimed_at = _utcnow_ms_z()
    ref: dict[str, object] = {
        "item_id": a_hash,
        "source": signer,
        "source_version": version,
        "ledger_ref": f"x402-settlement:{a_hash}",
        "content_hash": a_hash,
        "signer": signer,
        "signature": signature,
        "claimed_at": claimed_at,
    }
    envelope: dict[str, object] = {
        "schema": EVIDENCE_SCHEMA_ID,
        "use_case": "x402-settlement-join",
        "source": signer,
        "source_version": version,
        "generated_at": claimed_at,
        "attested_content": {"schema": SETTLEMENT_REF_SCHEMA_ID},
        "evidence": [ref],
        # Companion data (ignored by generic evidence-ref@1 verifiers; consumed
        # by verify_settlement_ref below):
        "signing_algorithm": algorithm,
        "settlement": dict(content),
        "artifact_hash": a_hash,
        "settlement_ref": a_hash,
        "decision_ref": content["decision_ref"],
        "settlement_key": facts.settlement_key,
        "disclaimer": (
            "Signed off-chain join record: the x402 policy signer asserts that the named "
            "decision authorized the named settlement. It is NOT an on-chain anchor and "
            "proves nothing about the transaction beyond the signer's assertion; the "
            "transaction itself must be observed independently on the chain."
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
# Verification (read path) — offline, fail-closed, distinct reasons.
# ---------------------------------------------------------------------------

REASON_MALFORMED = "malformed"
REASON_DECISION = "decision"
REASON_SETTLEMENT_MALFORMED = "settlement_malformed"
REASON_SETTLEMENT_HASH_MISMATCH = "settlement_hash_mismatch"
REASON_SETTLEMENT_UNKNOWN_SIGNER = "settlement_unknown_signer"
REASON_SETTLEMENT_BAD_SIGNATURE = "settlement_bad_signature"
REASON_JOIN_MISMATCH = "join_mismatch"
REASON_SIGNER_MISMATCH = "signer_mismatch"
REASON_NON_TERMINAL_VERDICT = "non_terminal_verdict"
REASON_IDENTITY_BOUNDS = "identity_bounds"


@dataclass(frozen=True)
class BundleVerification:
    """The outcome of verifying one treasury bundle (never raises to the caller).

    ``ok`` is the fail-closed conjunction of every layer. On failure ``reason``
    carries exactly one code — the first layer that failed, in verification
    order — and ``detail`` carries the underlying decision-ref reason when the
    failure was inside the decision envelope.
    """

    ok: bool
    reason: str | None = None
    detail: str | None = None
    decision_ref: str | None = None
    settlement_ref: str | None = None
    settlement_key: str | None = None
    verdict: str | None = None
    checked: tuple[str, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return self.ok


def _fail(reason: str, **kw: object) -> BundleVerification:
    return BundleVerification(ok=False, reason=reason, **kw)  # type: ignore[arg-type]


def verify_settlement_ref(
    envelope: Mapping[str, object],
    trust: Mapping[str, object],
    *,
    expected_decision_ref: str | None = None,
) -> tuple[bool, str | None, str | None]:
    """Verify a settlement-ref envelope: ``(ok, reason, settlement_ref)``.

    Layers: structure → content-hash recompute → schema/field revalidation →
    join match (when ``expected_decision_ref`` is given) → signature against the
    pinned trust store. ``trust`` is an already-normalised trust store.
    """
    if not isinstance(envelope, Mapping):
        return False, REASON_SETTLEMENT_MALFORMED, None
    evidence = envelope.get("evidence")
    content = envelope.get("settlement")
    if (
        not isinstance(evidence, list)
        or len(evidence) != 1
        or not isinstance(evidence[0], Mapping)
        or not isinstance(content, Mapping)
        or content.get("schema") != SETTLEMENT_REF_SCHEMA_ID
    ):
        return False, REASON_SETTLEMENT_MALFORMED, None
    ref = evidence[0]
    content_hash = ref.get("content_hash")
    signer = ref.get("signer")
    signature = ref.get("signature")
    if not (
        isinstance(content_hash, str) and isinstance(signer, str) and isinstance(signature, str)
    ):
        return False, REASON_SETTLEMENT_MALFORMED, None

    try:
        recomputed = sha256_hex(content)
    except EvidenceError:
        return False, REASON_SETTLEMENT_MALFORMED, None
    if recomputed != content_hash:
        return False, REASON_SETTLEMENT_HASH_MISMATCH, recomputed

    # Revalidate the committed fields rather than trusting that whoever signed
    # them applied the schema: a signed-but-out-of-domain integer is exactly the
    # input a sibling canonicaliser would reject, and admitting it here would
    # move the divergence downstream.
    try:
        SettlementFacts.from_mapping(content.get("settlement") or {})
    except (TreasuryBindingError, EvidenceError):
        return False, REASON_SETTLEMENT_MALFORMED, recomputed
    joined = content.get("decision_ref")
    if not isinstance(joined, str) or not joined:
        return False, REASON_SETTLEMENT_MALFORMED, recomputed
    if expected_decision_ref is not None and joined != expected_decision_ref:
        return False, REASON_JOIN_MISMATCH, recomputed

    entry = trust.get(signer)
    if not isinstance(entry, Mapping):
        return False, REASON_SETTLEMENT_UNKNOWN_SIGNER, recomputed
    verify = verify_ed25519 if entry.get("alg") == "ed25519" else verify_hmac
    keys = entry.get("keys")
    if not (
        isinstance(keys, list)
        and any(isinstance(k, str) and verify(content_hash, signer, signature, k) for k in keys)
    ):
        return False, REASON_SETTLEMENT_BAD_SIGNATURE, recomputed
    return True, None, recomputed


def verify_bundle(
    bundle: Mapping[str, object],
    trust_store: str | Mapping[str, object],
    *,
    actor_controllers: Sequence[str] | None = None,
) -> BundleVerification:
    """Verify a treasury bundle offline, fail-closed, one distinct reason.

    Order (first failure wins):

    1. **structure** — bundle schema, both envelopes present (``malformed``).
    2. **decision** — the full :func:`verify_decision_ref` chain; its reason code
       is surfaced in ``detail`` (``decision``).
    3. **terminal verdict** — ``REFER`` is refused (``non_terminal_verdict``).
    4. **identity bounds** — the caller-supplied strings are re-bounded on the
       read path, so a bundle built by an older or laxer producer still fails
       here (``identity_bounds``).
    5. **settlement** — content hash, field domain, and signature
       (``settlement_*``), plus the join to the decision (``join_mismatch``).
    6. **signer pinning** — both envelopes must be signed by the signer the
       bundle's ``trust_store_ref`` names (``signer_mismatch``). A join signed by
       a *different* trusted party is not the decision signer's assertion, and
       admitting it would let any trust-store member re-point any decision at any
       transaction.

    Never raises to the caller.
    """
    checked: list[str] = []
    if not isinstance(bundle, Mapping) or bundle.get("schema") != TREASURY_BUNDLE_SCHEMA_ID:
        return _fail(REASON_MALFORMED)
    decision_envelope = bundle.get("decision_ref_envelope")
    settlement_envelope = bundle.get("settlement_ref_envelope")
    trust_ref = bundle.get("trust_store_ref")
    if not (
        isinstance(decision_envelope, Mapping)
        and isinstance(settlement_envelope, Mapping)
        and isinstance(trust_ref, Mapping)
    ):
        return _fail(REASON_MALFORMED)
    checked.append("structure")

    try:
        trust = load_trust_store(trust_store)
    except EvidenceError:
        return _fail(REASON_MALFORMED, checked=tuple(checked))

    decision = verify_decision_ref(
        decision_envelope, trust_store, actor_controllers=actor_controllers
    )
    if not decision.ok:
        return _fail(
            REASON_DECISION,
            detail=decision.reason,
            decision_ref=decision.decision_ref,
            checked=tuple(checked),
        )
    checked.append("decision")

    if decision.verdict not in TERMINAL_VERDICTS:
        return _fail(
            REASON_NON_TERMINAL_VERDICT,
            detail=decision.verdict,
            decision_ref=decision.decision_ref,
            verdict=decision.verdict,
            checked=tuple(checked),
        )
    checked.append("terminal")

    content = decision_envelope.get("payment_decision")
    try:
        check_identity_bounds(content)  # type: ignore[arg-type]
    except (TreasuryBindingError, EvidenceError) as exc:
        return _fail(
            REASON_IDENTITY_BOUNDS,
            detail=str(exc),
            decision_ref=decision.decision_ref,
            verdict=decision.verdict,
            checked=tuple(checked),
        )
    checked.append("identity")

    ok, reason, settlement_ref = verify_settlement_ref(
        settlement_envelope, trust, expected_decision_ref=decision.decision_ref
    )
    if not ok:
        return _fail(
            reason or REASON_SETTLEMENT_MALFORMED,
            decision_ref=decision.decision_ref,
            settlement_ref=settlement_ref,
            verdict=decision.verdict,
            checked=tuple(checked),
        )
    checked.append("settlement")

    pinned = trust_ref.get("signer")
    decision_signer = _envelope_signer(decision_envelope)
    settlement_signer = _envelope_signer(settlement_envelope)
    if not (isinstance(pinned, str) and pinned and pinned == decision_signer == settlement_signer):
        return _fail(
            REASON_SIGNER_MISMATCH,
            detail=(
                f"trust_store_ref={pinned!r} decision={decision_signer!r} "
                f"settlement={settlement_signer!r}"
            ),
            decision_ref=decision.decision_ref,
            settlement_ref=settlement_ref,
            verdict=decision.verdict,
            checked=tuple(checked),
        )
    checked.append("signer")

    settlement_content = settlement_envelope.get("settlement")
    facts = SettlementFacts.from_mapping(
        settlement_content.get("settlement") if isinstance(settlement_content, Mapping) else {}
    )
    return BundleVerification(
        ok=True,
        decision_ref=decision.decision_ref,
        settlement_ref=settlement_ref,
        settlement_key=facts.settlement_key,
        verdict=decision.verdict,
        checked=tuple(checked),
    )


def _envelope_signer(envelope: Mapping[str, object]) -> str | None:
    evidence = envelope.get("evidence")
    if isinstance(evidence, list) and len(evidence) == 1 and isinstance(evidence[0], Mapping):
        signer = evidence[0].get("signer")
        return signer if isinstance(signer, str) else None
    return None


# ---------------------------------------------------------------------------
# The adapter — export a verified decision + settlement as one bundle.
# ---------------------------------------------------------------------------


def export_bundle(
    decision_envelope: Mapping[str, object],
    facts: SettlementFacts,
    *,
    trust_store: str | Mapping[str, object],
    signing_key: str,
    algorithm: str = "ed25519",
    signer: str | None = None,
    key_id: str | None = None,
    actor_controllers: Sequence[str] | None = None,
    issued_at: str | None = None,
) -> dict[str, object]:
    """Build the treasury-ingest bundle for one verified decision. Fail-closed.

    Refuses, with a distinct :class:`TreasuryBindingError` each time, when: the
    decision envelope does not self-verify against ``trust_store`` (every layer,
    including the signature — a bundle whose signature was never checked is not
    evidence of anything); the verdict is non-terminal; an identity string is
    out of bounds; the settlement facts are out of domain; or the settlement-ref
    would be signed by an identity other than the decision's signer.

    ``trust_store`` is required rather than optional on purpose. "Refuses to
    export a non-verifying envelope" is a claim about the *signature* too, and
    an exporter that skipped it would emit bundles whose central promise had
    never been tested.

    **No network I/O.**
    """
    result = verify_decision_ref(
        decision_envelope, trust_store, actor_controllers=actor_controllers
    )
    if not result.ok:
        raise TreasuryBindingError(
            f"refusing to export a decision-ref that does not verify: {result.reason} "
            "(fail-closed)"
        )
    if result.verdict not in TERMINAL_VERDICTS:
        raise TreasuryBindingError(
            f"refusing to export a non-terminal verdict {result.verdict!r}: an unresolved "
            "quorum is an interim state; export the terminal decision that supersedes it"
        )
    content = decision_envelope.get("payment_decision")
    if not isinstance(content, Mapping):
        raise TreasuryBindingError("decision envelope carries no payment_decision content")
    check_identity_bounds(content)

    decision_signer = _envelope_signer(decision_envelope)
    effective_signer = signer or decision_signer
    if not effective_signer:
        raise TreasuryBindingError("decision envelope carries no signer")
    if decision_signer != effective_signer:
        raise TreasuryBindingError(
            f"refusing to sign the join as {effective_signer!r} when the decision was signed "
            f"by {decision_signer!r}: the join is the decision signer's own assertion"
        )

    decision_ref = result.decision_ref
    if not isinstance(decision_ref, str):  # pragma: no cover - verify_decision_ref guarantees it
        raise TreasuryBindingError("decision envelope carries no recomputable decision_ref")

    settlement_content = build_settlement_ref_content(
        decision_ref=decision_ref, facts=facts, issued_at=issued_at
    )
    settlement_envelope = build_settlement_evidence(
        settlement_content,
        signing_key=signing_key,
        algorithm=algorithm,
        signer=effective_signer,
        key_id=key_id,
    )

    return {
        "schema": TREASURY_BUNDLE_SCHEMA_ID,
        "generated_at": settlement_envelope["generated_at"],
        "source_version": settlement_envelope["source_version"],
        "decision_ref": decision_ref,
        "settlement_ref": settlement_envelope["settlement_ref"],
        "settlement_key": settlement_envelope["settlement_key"],
        "verdict": result.verdict,
        "decision_ref_envelope": dict(decision_envelope),
        "settlement_ref_envelope": settlement_envelope,
        "trust_store_ref": {
            "signer": effective_signer,
            "algorithm": algorithm,
            "key_id": key_id,
            "note": (
                "Resolve this signer against your own pinned trust store. No key material "
                "travels in this bundle by design: a bundle-supplied public key would make "
                "verification trust-on-first-use and defeat the pin it exists to enforce."
            ),
        },
        "ingest_status": "treasury-ingest-pending",
        "disclaimer": (
            "Two signed records and the join between them. The decision-ref proves what the "
            "library concluded under a declared predicate; the settlement-ref is the signer's "
            "assertion that this decision authorized that transaction. Neither proves the "
            "transaction occurred — the chain observation is independent evidence, and the "
            "classification it supports remains the ledger's own dual-control judgment."
        ),
    }


# ---------------------------------------------------------------------------
# CLI — offline; exit 0 verified, 1 fail-closed, 2 usage.
# ---------------------------------------------------------------------------


def _read_json(path: str) -> object:
    import json
    from pathlib import Path

    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except RecursionError as exc:  # deeply nested input, before any bound applies
        raise ValueError("input JSON is nested too deeply to parse") from exc


def _load_signing_key(key_file: str | None) -> str:
    """Read the signing key from a file or the environment — never from argv.

    A key passed as a command-line argument is visible in ``ps`` output and in
    shell history to every user on the host, so the flag simply does not exist.
    """
    import os
    from pathlib import Path

    if key_file:
        return Path(key_file).read_text(encoding="utf-8").strip()
    key = os.environ.get("PRESIDIO_X402_EVIDENCE_KEY", "")
    if not key:
        raise ValueError(
            "no signing key: pass --key-file or set PRESIDIO_X402_EVIDENCE_KEY "
            "(a key on the command line would be visible in ps output)"
        )
    return key.strip()


def main(argv: Sequence[str] | None = None) -> int:
    """Export or verify a treasury bundle. Fully offline; exit 0/1/2.

    Usage::

        python -m presidio_x402.treasury_binding export ENVELOPE.json \\
            --settlement settle.json --trust trust.json [--key-file policy.key] \\
            [--key-id ID] [--algorithm ed25519|hmac-sha256] > bundle.json
        python -m presidio_x402.treasury_binding verify BUNDLE.json TRUST.json
    """
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(prog="presidio_x402.treasury_binding")
    sub = parser.add_subparsers(dest="command", required=True)

    exp = sub.add_parser("export", help="export a verified decision + settlement as a bundle")
    exp.add_argument("envelope", help="path to a decision-ref envelope .json")
    exp.add_argument("--settlement", required=True, help="path to a settlement-facts .json")
    exp.add_argument(
        "--trust", required=True, help="path to the trust-store .json to verify against"
    )
    exp.add_argument(
        "--key-file",
        default=None,
        help="file holding the signing key (or set PRESIDIO_X402_EVIDENCE_KEY)",
    )
    exp.add_argument("--algorithm", default="ed25519", choices=["ed25519", "hmac-sha256"])
    exp.add_argument("--key-id", default=None, help="trust-store key id to pin in the bundle")
    exp.add_argument(
        "--signer", default=None, help="override the signer id (must match the decision's)"
    )

    ver = sub.add_parser("verify", help="verify a bundle offline against a trust store")
    ver.add_argument("bundle", help="path to a bundle .json")
    ver.add_argument("trust_store", help="path to a trust-store .json")

    args = parser.parse_args(argv)

    if args.command == "export":
        try:
            envelope = _read_json(args.envelope)
            settlement_raw = _read_json(args.settlement)
            trust_text = _read_json(args.trust)
            signing_key = _load_signing_key(args.key_file)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not isinstance(envelope, dict) or not isinstance(settlement_raw, dict):
            print("error: envelope and settlement must each be a JSON object", file=sys.stderr)
            return 2
        try:
            facts = SettlementFacts.from_mapping(settlement_raw)
            declared = settlement_raw.get("decision_ref")
            bundle = export_bundle(
                envelope,
                facts,
                trust_store=trust_text,  # type: ignore[arg-type]
                signing_key=signing_key,
                algorithm=args.algorithm,
                signer=args.signer,
                key_id=args.key_id,
            )
            if isinstance(declared, str) and declared and declared != bundle["decision_ref"]:
                raise TreasuryBindingError(
                    f"settlement file names decision_ref {declared!r} but the envelope's is "
                    f"{bundle['decision_ref']!r}: refusing to join a settlement to a decision "
                    "it was not observed with"
                )
        except EvidenceError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        json.dump(bundle, sys.stdout, sort_keys=True, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    try:
        bundle = _read_json(args.bundle)
        trust_text = _read_json(args.trust_store)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not isinstance(bundle, dict):
        print("error: bundle must be a JSON object", file=sys.stderr)
        return 2
    result = verify_bundle(bundle, trust_text)  # type: ignore[arg-type]
    detail = f"/{result.detail}" if result.detail else ""
    status = "OK" if result.ok else f"FAIL({result.reason}{detail})"
    print(
        f"{result.decision_ref or '<no-ref>'}  verdict={result.verdict}  "
        f"settlement={result.settlement_key or '<none>'}  {status}"
    )
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
