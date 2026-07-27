# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Capability certificates — operator-signed, attenuable spending grants.

Turns spending *authority* from configuration (``PolicyConfig`` read from env or
kwargs) into a *capability*: a signed, portable, attenuable, expiring grant that
a verifier admits **locally, with no network round-trip**. This is Pillar I of
the Computational Jurisprudence program (Stantchev, arXiv 2026) and the seed of a
caveat-format standards track (see ``plan/capability-certificates-design.md``).

Schema: ``presidio-hardened/capability-grant@1``.

Design creed — *more secure = less coordination*. The honest exercise path is
O(1) local verification. Monotone attenuation holds **by construction**: the
caveat language is conjunctive and negation-free, so a child grant can only ever
*narrow* the authority of its parent, never broaden it. Every caveat rule below is
a subset rule; adding a caveat can only shrink the admitted (url, amount, time)
set. Do **not** add a caveat type whose combination with another can widen
authority — that would break the monotonicity property the paper restricts to
exactly this fragment.

Wire format (family Layer-0, mirrored via :mod:`presidio_x402.mica`):

- canonical JSON = sorted keys, ``(",", ":")`` separators, UTF-8,
  ``ensure_ascii=False``, **floats rejected** (:func:`mica.canonical_bytes`);
- ``grant_id`` / ``parent_hash`` content addressing = SHA-256 over the canonical
  bytes of the grant *including* its signature (a grant is only addressable once
  signed);
- detached Ed25519 signature over the canonical bytes of the grant with the
  ``signature`` field **removed** (the signing preimage — see
  :func:`_signing_preimage`);
- ``trust-store@1`` shape (reused via :func:`mica.load_trust_store`) supplies the
  operator public key that a root grant verifies against.

Amounts are integer micro-USD (``int``) or a decimal *string* (``"0.05"``);
never a float. The strict canonical profile rejects floats outright, and the
caveat parser converts both accepted forms to :class:`~decimal.Decimal` for
comparison, mirroring ``policy_engine._decimal_usd``.

Out of scope for ``@1`` (stated in the design doc): revocation beyond expiry
(accumulators are the research track — **expiry IS the revocation story for
@1**), sealed chains / ZK proof tiers, bonds, and MCP-server exposure. This pass
adds no network call and does not wire capability into the MCP server or the
screening-api.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from .mica import (
    EvidenceError,
    canonical_bytes,
    load_trust_store,
    sha256_hex,
)

CAPABILITY_SCHEMA_ID = "presidio-hardened/capability-grant@1"

#: The grant fields (including ``signature``) — any other key fails closed.
_GRANT_FIELDS = frozenset(
    {
        "schema",
        "grant_id",
        "subject",
        "subject_public_key",
        "caveats",
        "issuer",
        "parent_hash",
        "issued_at",
        "signature",
    }
)

_KNOWN_CAVEATS = frozenset(
    {
        "max_per_call_usd",
        "daily_limit_usd",
        "window_seconds",
        "valid_from",
        "valid_until",
        "endpoint_prefixes",
    }
)

_MAX_STR = 512


class CapabilityError(EvidenceError):
    """Raised on any capability-grant rejection (fail-closed, distinct reasons).

    Subclasses :class:`~presidio_x402.mica.EvidenceError` so a caller that already
    catches the family evidence error also catches capability failures. The
    message carries the distinct rejection reason (unknown schema, bad hex,
    expired, unsigned, broadened, …).
    """


# ---------------------------------------------------------------------------
# Amount / time helpers (float-free, mirroring policy_engine + action_ref)
# ---------------------------------------------------------------------------


def _amount_decimal(value: object, field_name: str) -> Decimal:
    """Parse an amount to :class:`Decimal`. Accepts ``int`` (micro-USD) or a
    decimal ``str``; **rejects floats** and non-finite / negative values.

    Integer inputs are interpreted as micro-USD (1e-6 USD) so a caveat can be
    expressed in atomic units without a float ever entering the wire form. A
    string is a plain decimal USD amount (``"0.05"``). This mirrors the
    family float rule (``mica._reject_uncanonicalisable``) and ``policy_engine._decimal_usd``.
    """
    if isinstance(value, bool):  # bool is an int subclass — never an amount
        raise CapabilityError(f"{field_name} must not be a boolean")
    if isinstance(value, float):
        raise CapabilityError(
            f"{field_name} must be an integer (micro-USD) or a decimal string, "
            "never a float (strict canonical profile rejects floats)"
        )
    if isinstance(value, int):
        amount = Decimal(value) / Decimal(1_000_000)
    elif isinstance(value, str):
        try:
            amount = Decimal(value)
        except InvalidOperation as exc:
            raise CapabilityError(
                f"{field_name} is not a valid decimal amount: {value!r}"
            ) from exc
    else:
        raise CapabilityError(
            f"{field_name} must be an integer or decimal string, got {type(value)}"
        )
    if not amount.is_finite() or amount < 0:
        raise CapabilityError(f"{field_name} must be a finite non-negative USD amount")
    return amount


def _parse_rfc3339_utc(value: object, field_name: str) -> datetime:
    """Parse an RFC 3339 UTC timestamp string to an aware ``datetime`` in UTC.

    Accepts a trailing ``Z`` or an explicit ``+00:00``; a naive or non-UTC value
    is rejected (an unverifiable window is never admitted). Mirrors the
    conformant-timestamp discipline in :mod:`presidio_x402.action_ref`.
    """
    if not isinstance(value, str) or not value:
        raise CapabilityError(f"{field_name} must be a non-empty RFC3339 UTC string")
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise CapabilityError(f"{field_name} is not a valid RFC3339 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        raise CapabilityError(f"{field_name} must be timezone-aware (UTC); got naive {value!r}")
    return dt.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime) -> str:
    """Emit an RFC3339 UTC string with a trailing ``Z`` (second precision)."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Caveat model — all conjunctive, all optional except the (implicit) validity
# window, all subset-preserving. See the design doc's monotone-fragment argument.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Caveats:
    """Parsed, normalised caveats of one grant.

    Every field is optional; ``None`` means *unconstrained on this axis by this
    grant*. Because caveats are conjunctive across a chain, an axis left ``None``
    by one hop is still constrained by any other hop that sets it — the effective
    authority is the **intersection**, so absence never widens.
    """

    max_per_call_usd: Decimal | None = None
    daily_limit_usd: Decimal | None = None
    window_seconds: int | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    endpoint_prefixes: tuple[str, ...] | None = None


def _parse_caveats(raw: object) -> Caveats:
    """Validate and normalise a caveats object (fail-closed on any anomaly)."""
    if not isinstance(raw, Mapping):
        raise CapabilityError("caveats must be an object")
    unknown = set(raw.keys()) - _KNOWN_CAVEATS
    if unknown:
        # Fail closed on unknown caveat keys: an unrecognised caveat could be a
        # negation/widening type from a future, non-monotone fragment, and
        # silently ignoring it would admit authority the issuer did not grant.
        raise CapabilityError(f"unknown caveat(s): {sorted(unknown)} (fail-closed)")

    max_call = (
        _amount_decimal(raw["max_per_call_usd"], "caveats.max_per_call_usd")
        if "max_per_call_usd" in raw
        else None
    )
    daily = (
        _amount_decimal(raw["daily_limit_usd"], "caveats.daily_limit_usd")
        if "daily_limit_usd" in raw
        else None
    )

    window = None
    if "window_seconds" in raw:
        w = raw["window_seconds"]
        if isinstance(w, bool) or not isinstance(w, int) or w <= 0:
            raise CapabilityError("caveats.window_seconds must be a positive integer")
        window = w

    valid_from = (
        _parse_rfc3339_utc(raw["valid_from"], "caveats.valid_from")
        if "valid_from" in raw
        else None
    )
    valid_until = (
        _parse_rfc3339_utc(raw["valid_until"], "caveats.valid_until")
        if "valid_until" in raw
        else None
    )
    if valid_from is not None and valid_until is not None and valid_from > valid_until:
        raise CapabilityError("caveats.valid_from must not be after caveats.valid_until")

    prefixes: tuple[str, ...] | None = None
    if "endpoint_prefixes" in raw:
        ep = raw["endpoint_prefixes"]
        if (
            not isinstance(ep, Sequence)
            or isinstance(ep, (str, bytes))
            or len(ep) == 0
            or not all(isinstance(p, str) and p for p in ep)
        ):
            raise CapabilityError(
                "caveats.endpoint_prefixes must be a non-empty list of non-empty URL prefixes"
            )
        for p in ep:
            if not (p.startswith("http://") or p.startswith("https://")):
                raise CapabilityError(f"endpoint prefix must be an http(s) URL prefix; got {p!r}")
        prefixes = tuple(ep)

    return Caveats(
        max_per_call_usd=max_call,
        daily_limit_usd=daily,
        window_seconds=window,
        valid_from=valid_from,
        valid_until=valid_until,
        endpoint_prefixes=prefixes,
    )


# ---------------------------------------------------------------------------
# Grant model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    """One parsed, structurally-valid capability grant (not yet chain-verified).

    ``raw`` retains the exact wire dict so content-addressing and signature
    verification recompute from the original bytes, never from a re-serialised
    view. ``grant_hash`` is the SHA-256 over the canonical bytes of ``raw``
    (including the signature) — the value a child cites as ``parent_hash``.
    """

    schema: str
    grant_id: str
    subject: str
    subject_public_key: str | None
    caveats: Caveats
    issuer: str
    parent_hash: str | None
    issued_at: datetime
    signature: str
    raw: Mapping[str, object]
    grant_hash: str

    @property
    def is_root(self) -> bool:
        return self.parent_hash is None


def _require_str(
    raw: Mapping[str, object], name: str, *, allow_missing: bool = False
) -> str | None:
    if name not in raw:
        if allow_missing:
            return None
        raise CapabilityError(f"grant missing required field {name!r}")
    value = raw[name]
    if value is None and allow_missing:
        return None
    if not isinstance(value, str) or not value or len(value) > _MAX_STR:
        raise CapabilityError(
            f"grant field {name!r} must be a non-empty string <= {_MAX_STR} chars"
        )
    if "\x00" in value:
        raise CapabilityError(f"grant field {name!r} contains a null byte")
    return value


def _is_hex(value: str, length: int | None = None) -> bool:
    try:
        b = bytes.fromhex(value)
    except ValueError:
        return False
    return length is None or len(b) == length


def _signing_preimage(raw: Mapping[str, object]) -> bytes:
    """The canonical bytes a grant's detached signature is computed over.

    Defined exactly as: the grant object with the ``signature`` field removed,
    encoded by :func:`mica.canonical_bytes` (sorted keys, ``(",", ":")``, UTF-8,
    ``ensure_ascii=False``, floats rejected). Every other field — including
    ``grant_id`` and ``parent_hash`` — is inside the signed preimage, so the
    binding to the parent and the grant's own id are both signature-protected.
    """
    without_sig = {k: v for k, v in raw.items() if k != "signature"}
    return canonical_bytes(without_sig)


def parse_grant(raw: object) -> Grant:
    """Structurally validate one grant dict and content-address it (fail-closed).

    Checks: exact schema constant, presence/typing of required fields, hex shape
    of ``subject_public_key`` (when present) and ``signature``, and caveat
    well-formedness. Does **not** verify the signature or chain — that is
    :func:`verify_chain`'s job. Distinct :class:`CapabilityError` messages per
    failure class.
    """
    if not isinstance(raw, Mapping):
        raise CapabilityError("grant must be an object")
    extra = set(raw.keys()) - _GRANT_FIELDS
    if extra:
        raise CapabilityError(f"grant has unknown field(s): {sorted(extra)} (fail-closed)")

    schema = raw.get("schema")
    if schema != CAPABILITY_SCHEMA_ID:
        raise CapabilityError(
            f"unsupported grant schema {schema!r} (expected {CAPABILITY_SCHEMA_ID!r})"
        )

    grant_id = _require_str(raw, "grant_id")
    subject = _require_str(raw, "subject")
    issuer = _require_str(raw, "issuer")
    signature = _require_str(raw, "signature")
    if not _is_hex(signature, 64):
        raise CapabilityError(
            "grant signature must be 128 lowercase hex chars (Ed25519, 64 bytes)"
        )

    subject_pub = _require_str(raw, "subject_public_key", allow_missing=True)
    if subject_pub is not None and not _is_hex(subject_pub, 32):
        raise CapabilityError(
            "subject_public_key must be 64 lowercase hex chars (Ed25519 public key, 32 bytes)"
        )

    parent_hash = _require_str(raw, "parent_hash", allow_missing=True)
    if parent_hash is not None and not _is_hex(parent_hash, 32):
        raise CapabilityError("parent_hash must be a 64-hex SHA-256 content hash")

    if "caveats" not in raw:
        raise CapabilityError("grant missing required field 'caveats'")
    caveats = _parse_caveats(raw["caveats"])

    issued_at = _parse_rfc3339_utc(raw.get("issued_at"), "issued_at")

    grant_hash = sha256_hex(raw)  # content hash over the FULL (signed) grant

    return Grant(
        schema=schema,
        grant_id=grant_id,  # type: ignore[arg-type]
        subject=subject,  # type: ignore[arg-type]
        subject_public_key=subject_pub,
        caveats=caveats,
        issuer=issuer,  # type: ignore[arg-type]
        parent_hash=parent_hash,
        issued_at=issued_at,
        signature=signature,  # type: ignore[arg-type]
        raw=dict(raw),
        grant_hash=grant_hash,
    )


# ---------------------------------------------------------------------------
# Issuance / delegation (write path)
# ---------------------------------------------------------------------------


def _caveats_to_wire(caveats: Mapping[str, object]) -> dict[str, object]:
    """Validate caveats then echo the exact wire form the caller supplied.

    Parsing first fails closed on any malformed caveat; the returned dict is the
    caller's own values (so amounts stay in their chosen ``int``/``str`` form and
    canonicalisation is byte-stable), sorted for readability only — canonical
    bytes re-sort regardless.
    """
    _parse_caveats(caveats)  # fail-closed validation; result intentionally unused
    return {k: caveats[k] for k in sorted(caveats)}


def issue_grant(
    *,
    subject: str,
    issuer: str,
    caveats: Mapping[str, object],
    issuer_private_key: str,
    subject_public_key: str | None = None,
    issued_at: datetime | None = None,
    grant_id: str | None = None,
) -> dict[str, object]:
    """Mint and sign a **root** capability grant (no parent).

    The returned dict is a wire-ready ``capability-grant@1`` object. The
    detached Ed25519 signature is computed over :func:`_signing_preimage` with
    ``issuer_private_key`` (64 lowercase hex, the operator key whose public half
    lives in the verifier trust store). ``grant_id`` defaults to the SHA-256 of
    the signing preimage so distinct grants get distinct ids without a nonce.

    Supply ``subject_public_key`` when the grant may be *further delegated*: a
    child's signature verifies against it, so a root that omits it is a leaf that
    cannot delegate.
    """
    caveats_wire = _caveats_to_wire(caveats)
    body: dict[str, object] = {
        "schema": CAPABILITY_SCHEMA_ID,
        "subject": subject,
        "issuer": issuer,
        "caveats": caveats_wire,
        "parent_hash": None,
        "issued_at": _rfc3339(issued_at or _utcnow()),
    }
    if subject_public_key is not None:
        if not _is_hex(subject_public_key, 32):
            raise CapabilityError("subject_public_key must be 64 lowercase hex chars")
        body["subject_public_key"] = subject_public_key
    body["grant_id"] = grant_id or sha256_hex(body)
    body["signature"] = _sign_preimage(body, issuer_private_key)
    return body


def delegate_grant(
    parent: Mapping[str, object],
    *,
    parent_private_key: str,
    caveats: Mapping[str, object],
    subject: str,
    subject_public_key: str | None = None,
    issuer: str | None = None,
    issued_at: datetime | None = None,
    grant_id: str | None = None,
) -> dict[str, object]:
    """Mint and sign a **child** grant attenuating ``parent``.

    The child's ``parent_hash`` is the content hash of ``parent`` (over its full
    signed bytes). The child signature is computed with ``parent_private_key`` —
    the private half of the parent's ``subject_public_key`` — so a verifier
    checks the child against the parent's declared delegation key. Raises if the
    parent did not publish a ``subject_public_key`` (a leaf cannot delegate) or
    if the requested caveats are not an attenuation of the parent's (checked here
    at mint time *and* re-checked in :func:`verify_chain`, which is authoritative).
    """
    parent_grant = parse_grant(parent)
    if parent_grant.subject_public_key is None:
        raise CapabilityError(
            "parent grant published no subject_public_key — it is a leaf and cannot be delegated"
        )
    child_caveats = _parse_caveats(caveats)
    # Fail-closed at mint time so a misuse is caught early; verify_chain repeats
    # this as the authoritative gate on the read path.
    _check_attenuation(parent_grant.caveats, child_caveats)

    caveats_wire = _caveats_to_wire(caveats)
    body: dict[str, object] = {
        "schema": CAPABILITY_SCHEMA_ID,
        "subject": subject,
        "issuer": issuer or parent_grant.subject,
        "caveats": caveats_wire,
        "parent_hash": parent_grant.grant_hash,
        "issued_at": _rfc3339(issued_at or _utcnow()),
    }
    if subject_public_key is not None:
        if not _is_hex(subject_public_key, 32):
            raise CapabilityError("subject_public_key must be 64 lowercase hex chars")
        body["subject_public_key"] = subject_public_key
    body["grant_id"] = grant_id or sha256_hex(body)
    body["signature"] = _sign_preimage(body, parent_private_key)
    return body


def _sign_preimage(body: Mapping[str, object], private_key: str) -> str:
    """Detached Ed25519 signature over the grant signing preimage (hex).

    Reuses the family signing primitive shape (:func:`mica.sign_evidence`) but
    signs the capability preimage rather than the evidence ``{content_hash,
    signer}`` tuple, because a capability grant's authority lives in the *whole*
    object (caveats, parent binding, subject), not a hash summary.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if not private_key or not _is_hex(private_key, 32):
        raise CapabilityError("issuer/parent private key must be 64 lowercase hex chars")
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    return sk.sign(_signing_preimage(body)).hex()


# ---------------------------------------------------------------------------
# Attenuation — every rule makes child authority a SUBSET of the parent's.
# ---------------------------------------------------------------------------


def _limit_narrows(parent: Decimal | None, child: Decimal | None, name: str) -> None:
    """A monetary cap: child must be present and <= parent whenever the parent
    constrains it. If the parent caps an axis, the child may not leave it
    unbounded (that would widen), and may not raise it."""
    if parent is None:
        return  # parent unconstrained on this axis — child may set any bound (narrows or equal)
    if child is None:
        raise CapabilityError(
            f"attenuation violation: parent caps {name} at {parent} but child leaves it "
            "unbounded (would broaden authority)"
        )
    if child > parent:
        raise CapabilityError(
            f"attenuation violation: child {name}={child} exceeds parent {name}={parent} "
            "(would broaden authority)"
        )


def _window_subset(parent: Caveats, child: Caveats) -> None:
    """Child validity window must be a subset of the parent's.

    ``valid_from`` may only move later (>=), ``valid_until`` only earlier (<=).
    A parent bound that the child drops would widen the window, so a child must
    carry a bound at least as tight as any the parent sets."""
    if parent.valid_from is not None and (
        child.valid_from is None or child.valid_from < parent.valid_from
    ):
        raise CapabilityError(
            "attenuation violation: child valid_from is earlier than / drops parent's "
            "(would widen the validity window)"
        )
    if parent.valid_until is not None and (
        child.valid_until is None or child.valid_until > parent.valid_until
    ):
        raise CapabilityError(
            "attenuation violation: child valid_until is later than / drops parent's "
            "(would widen the validity window)"
        )


def _window_seconds_narrows(parent: Caveats, child: Caveats) -> None:
    """``window_seconds`` sizes the rolling aggregate ledger window.

    For a fixed aggregate cap, a shorter rolling window evicts spend sooner and
    admits more throughput over time. A child may therefore only keep or lengthen
    the parent's budget window. Dropping a parent-set window is also a broadening.
    """
    if parent.window_seconds is None:
        return
    if child.window_seconds is None or child.window_seconds < parent.window_seconds:
        raise CapabilityError(
            "attenuation violation: child window_seconds is shorter than / drops parent's "
            "(a shorter budget window evicts spend sooner — would broaden authority)"
        )


def _prefixes_extend(parent: Caveats, child: Caveats) -> None:
    """Every child endpoint prefix must fall under a parent prefix on URL
    host/path boundaries.

    This makes the child's admitted-URL set a subset of the parent's without
    allowing prefix-confusion siblings such as ``/inference-evil`` or
    ``api.example.com.evil``.
    """
    from .policy_engine import _endpoint_prefix_matches

    if parent.endpoint_prefixes is None:
        return  # parent unrestricted on URL — child may add any restriction (narrows)
    if child.endpoint_prefixes is None:
        raise CapabilityError(
            "attenuation violation: parent restricts endpoint_prefixes but child drops them "
            "(would broaden the admitted-URL set)"
        )
    for cp in child.endpoint_prefixes:
        if not any(_endpoint_prefix_matches(pp, cp) for pp in parent.endpoint_prefixes):
            raise CapabilityError(
                f"attenuation violation: child prefix {cp!r} does not extend any parent prefix "
                f"{list(parent.endpoint_prefixes)!r} (would broaden the admitted-URL set)"
            )


def _check_attenuation(parent: Caveats, child: Caveats) -> None:
    """Assert the child caveats are an attenuation (subset) of the parent's.

    Every rule below is a subset rule: it can only shrink the admitted
    (url, amount, time) set, never grow it. Together they make the whole caveat
    fragment monotone by construction. Raises :class:`CapabilityError` with a
    distinct reason on the first violation."""
    _limit_narrows(parent.max_per_call_usd, child.max_per_call_usd, "max_per_call_usd")
    _limit_narrows(parent.daily_limit_usd, child.daily_limit_usd, "daily_limit_usd")
    _window_seconds_narrows(parent, child)
    _window_subset(parent, child)
    _prefixes_extend(parent, child)


# ---------------------------------------------------------------------------
# Chain verification (read path) — fail-closed, no network, O(chain length).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedGrantChain:
    """A capability chain that has passed full verification.

    Holds the ordered parsed grants (root first) and the **effective caveats** =
    the intersection of every hop's caveats. The effective caveats are what the
    :class:`~presidio_x402.policy_engine.PolicyConfig` bridge consumes and what
    :meth:`check_payment` enforces at exercise time.
    """

    grants: tuple[Grant, ...]
    effective: Caveats

    @property
    def subject(self) -> str:
        """The terminal subject — the agent this chain authorises."""
        return self.grants[-1].subject

    def check_payment(
        self,
        *,
        resource_url: str,
        amount_usd: Decimal | int | str,
        at: datetime | None = None,
    ) -> None:
        """Exercise-time check: a payment must satisfy EVERY grant in the chain.

        Intersection semantics — sound by construction: the effective caveats are
        the intersection of the chain, so a single check against ``effective`` is
        equivalent to checking each hop. Raises :class:`CapabilityError` with a
        distinct reason if the amount exceeds any hop's per-call cap, the URL is
        outside the intersected prefix set, or the moment is outside the validity
        window. ``daily_limit_usd`` / ``window_seconds`` are aggregate budgets
        enforced by the :class:`~presidio_x402.policy_engine.PolicyEngine` ledger
        via the config bridge, not by this per-call check.
        """
        now = at or _utcnow()
        amount = _exercise_amount(amount_usd)
        eff = self.effective

        if eff.valid_from is not None and now < eff.valid_from:
            raise CapabilityError(f"payment at {_rfc3339(now)} is before grant valid_from")
        if eff.valid_until is not None and now > eff.valid_until:
            raise CapabilityError(
                f"payment at {_rfc3339(now)} is after grant valid_until (expired)"
            )

        if eff.max_per_call_usd is not None and amount > eff.max_per_call_usd:
            raise CapabilityError(
                f"payment {amount} exceeds effective max_per_call_usd {eff.max_per_call_usd}"
            )

        if eff.endpoint_prefixes is not None:
            from .policy_engine import _endpoint_prefix_matches

            if any(_endpoint_prefix_matches(p, resource_url) for p in eff.endpoint_prefixes):
                return
            raise CapabilityError(
                f"resource_url {resource_url!r} is outside the granted endpoint prefixes "
                f"{list(eff.endpoint_prefixes)!r}"
            )


def _exercise_amount(value: Decimal | int | str) -> Decimal:
    if isinstance(value, Decimal):
        if not value.is_finite() or value < 0:
            raise CapabilityError("exercise amount must be a finite non-negative Decimal")
        return value
    return _amount_decimal(value, "amount_usd")


def _intersect(grants: Sequence[Grant]) -> Caveats:
    """Intersect the caveats of a verified chain into effective caveats.

    Each axis takes the tighter bound across all hops (max of lower bounds, min
    of upper bounds / caps), and endpoint prefixes intersect to the most-specific
    (deepest) hop's set — which, because attenuation guarantees every child
    prefix extends a parent prefix, is already a subset of every ancestor's set.
    Because attenuation was verified hop-by-hop first, this intersection is
    well-defined and equals the terminal grant's caveats on the monotone axes;
    computing it explicitly keeps the bridge robust to any future non-strict hop.
    """
    max_call: Decimal | None = None
    daily: Decimal | None = None
    window: int | None = None
    vfrom: datetime | None = None
    vuntil: datetime | None = None
    prefixes: tuple[str, ...] | None = None

    for g in grants:
        c = g.caveats
        max_call = _tighter_cap(max_call, c.max_per_call_usd)
        daily = _tighter_cap(daily, c.daily_limit_usd)
        window = _tighter_window(window, c.window_seconds)
        if c.valid_from is not None:
            vfrom = c.valid_from if vfrom is None else max(vfrom, c.valid_from)
        if c.valid_until is not None:
            vuntil = c.valid_until if vuntil is None else min(vuntil, c.valid_until)
        if c.endpoint_prefixes is not None:
            # Attenuation guarantees the deeper set extends the shallower, so the
            # deeper (later) set is the intersection. Keep the latest non-None.
            prefixes = c.endpoint_prefixes

    return Caveats(
        max_per_call_usd=max_call,
        daily_limit_usd=daily,
        window_seconds=window,
        valid_from=vfrom,
        valid_until=vuntil,
        endpoint_prefixes=prefixes,
    )


def _tighter_cap(current, candidate):
    """min() that treats ``None`` as 'unconstrained' (candidate wins)."""
    if candidate is None:
        return current
    if current is None:
        return candidate
    return min(current, candidate)


def _tighter_window(current: int | None, candidate: int | None) -> int | None:
    """The tighter aggregate window is the longer one."""
    if candidate is None:
        return current
    if current is None:
        return candidate
    return max(current, candidate)


def verify_chain(
    chain: Sequence[Mapping[str, object]],
    trust_store: str | Mapping[str, object],
    *,
    at: datetime | None = None,
) -> VerifiedGrantChain:
    """Verify a capability chain end-to-end and return it (fail-closed).

    Steps, all local and O(chain length):

    1. Parse every grant (schema, fields, hex, caveats) — fail-closed.
    2. The **root** grant's signature verifies against an operator key resolved
       from ``trust_store`` (``trust-store@1`` shape, via
       :func:`mica.load_trust_store`), keyed by the root ``issuer``.
    3. Each **child** grant's ``parent_hash`` must equal the content hash of the
       preceding grant, and its signature must verify against the parent's
       ``subject_public_key`` (the parent must have published one).
    4. Attenuation is checked **hop-by-hop**: each child's caveats must be a
       subset of its parent's (:func:`_check_attenuation`).
    5. The chain's *validity window* is checked against ``at`` (default: now); an
       expired or not-yet-valid chain is rejected here so verification and
       exercise agree.

    Returns a :class:`VerifiedGrantChain` whose ``effective`` caveats are the
    intersection of the chain. Any failure raises :class:`CapabilityError` with a
    distinct reason; nothing fails open.
    """
    if not isinstance(chain, Sequence) or isinstance(chain, (str, bytes)) or len(chain) == 0:
        raise CapabilityError("chain must be a non-empty list of grants (root first)")

    grants = [parse_grant(g) for g in chain]

    root = grants[0]
    if not root.is_root:
        raise CapabilityError("first grant in chain must be a root (parent_hash absent/null)")

    trust = load_trust_store(trust_store)
    entry = trust.get(root.issuer)
    if entry is None:
        raise CapabilityError(
            f"root issuer {root.issuer!r} is not in the trust store (unknown operator key)"
        )
    if entry.get("alg") != "ed25519":
        raise CapabilityError(
            f"root issuer {root.issuer!r} trust entry must be ed25519 for capability grants"
        )
    root_msg_ok = _verify_grant_sig(root, entry["keys"])  # type: ignore[index]
    if not root_msg_ok:
        raise CapabilityError(
            f"root grant signature does not verify against any trust-store key for "
            f"issuer {root.issuer!r}"
        )

    # Walk children: hash-link, signature against parent key, attenuation.
    for parent, child in zip(grants, grants[1:], strict=False):
        if child.is_root:
            raise CapabilityError(
                "only the first grant may be a root; a later grant has no parent"
            )
        if child.parent_hash != parent.grant_hash:
            raise CapabilityError(
                "chain broken: child parent_hash does not match the preceding grant's content hash"
            )
        if parent.subject_public_key is None:
            raise CapabilityError(
                "chain broken: parent published no subject_public_key, so it cannot delegate"
            )
        if not _verify_grant_sig(child, [parent.subject_public_key]):
            raise CapabilityError(
                "child grant signature does not verify against the parent's subject_public_key"
            )
        _check_attenuation(parent.caveats, child.caveats)

    effective = _intersect(grants)

    # Validity-window gate at verification time so verify and exercise agree.
    now = at or _utcnow()
    if effective.valid_from is not None and now < effective.valid_from:
        raise CapabilityError("capability chain is not yet valid (before valid_from)")
    if effective.valid_until is not None and now > effective.valid_until:
        raise CapabilityError("capability chain has expired (after valid_until)")

    return VerifiedGrantChain(grants=tuple(grants), effective=effective)


def _verify_grant_sig(grant: Grant, public_keys: Sequence[str]) -> bool:
    """Verify a grant's detached Ed25519 signature over its signing preimage.

    Reuses the family verification primitive shape but over the capability
    preimage. Fail-closed: bad hex, bad key, or a non-matching signature all
    return ``False``. Succeeds if the signature matches ANY listed key (supports
    operator key rotation for the root)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    message = _signing_preimage(grant.raw)
    for key in public_keys:
        if not (isinstance(key, str) and _is_hex(key, 32)):
            continue
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
            pk.verify(bytes.fromhex(grant.signature), message)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


# ---------------------------------------------------------------------------
# PolicyEngine bridge — capability -> configuration, at config-build time only.
# ---------------------------------------------------------------------------


def policy_config_from_chain(chain: VerifiedGrantChain, *, agent_id: str | None = None):
    """Build a :class:`~presidio_x402.policy_engine.PolicyConfig` from a verified
    chain's **effective caveats** (the intersection).

    This is the whole integration surface: spending authority that used to be
    read from env/kwargs is now the projection of a verified capability chain.
    The existing gate order (PII -> trusted-wallet -> policy -> replay -> MPA) is
    unchanged; the capability check slots in exactly where the policy *config* is
    built, not as a new gate and not as a network call. Amounts are carried as
    decimal *strings* into the config so no float ever enters — the downstream
    ``PolicyEngine`` re-parses them with its own ``Decimal`` path.

    Per-call and per-endpoint caps map to ``PolicyConfig``; the endpoint prefixes
    become per-endpoint caps at the effective ``max_per_call_usd`` (or the daily
    limit when no per-call cap is set) so the policy ledger enforces the granted
    URL scope. The validity window is **not** a ``PolicyConfig`` concept — it is
    enforced by :meth:`VerifiedGrantChain.check_payment` at exercise time, which
    the caller invokes alongside the policy check.

    Float boundary: the *grant* wire form is strictly float-free (the strict
    canonical profile rejects floats), and the effective caveats are carried as
    :class:`~decimal.Decimal`. ``PolicyConfig``, however, is in-process **runtime
    configuration** whose amount fields are declared ``float`` and are re-parsed
    to ``Decimal`` internally by ``PolicyEngine._decimal_usd`` before any
    comparison. The bridge therefore converts the exact ``Decimal`` caps to
    ``float`` at this one boundary — the float lives only inside the runtime
    policy object, never in a grant, a signature preimage, or any canonical
    bytes. This keeps the wire-format invariant intact while feeding
    ``PolicyEngine`` a value of its declared type (matching every other
    ``PolicyConfig`` construction site).
    """
    from .policy_engine import PolicyConfig

    eff = chain.effective
    per_endpoint: dict[str, float] = {}
    endpoint_cap = (
        eff.max_per_call_usd if eff.max_per_call_usd is not None else eff.daily_limit_usd
    )
    if eff.endpoint_prefixes is not None and endpoint_cap is not None:
        for prefix in eff.endpoint_prefixes:
            per_endpoint[prefix] = float(endpoint_cap)

    return PolicyConfig(
        max_per_call_usd=float(eff.max_per_call_usd) if eff.max_per_call_usd is not None else None,
        daily_limit_usd=float(eff.daily_limit_usd) if eff.daily_limit_usd is not None else None,
        per_endpoint=per_endpoint,
        window_seconds=eff.window_seconds if eff.window_seconds is not None else 86_400,
        agent_id=agent_id or chain.subject,
    )
