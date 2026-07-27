"""Seeded capability-grant@1 chain builders for the E2 experiments.

Shared by ``e2_replay.py`` (latency sweep) and ``e2_violations.py`` (detection
table). Everything here is deterministic from an integer ``seed`` so a run is
reproducible: Ed25519 private keys are derived as ``SHA-256(seed || role)`` (a
valid 32-byte Ed25519 seed) rather than drawn from the OS CSPRNG, and caveats /
depths are fixed functions of the arguments. Chains are built **only** with the
released ``capability.py`` helpers (``issue_grant`` / ``delegate_grant`` /
``verify_chain``) — no caveat-language extension, no reimplementation.

No network I/O. Import-safe without the ``[nlp]`` extra.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric import ed25519

from presidio_x402.capability import (
    VerifiedGrantChain,
    delegate_grant,
    issue_grant,
    verify_chain,
)

OPERATOR_ID = "e2-operator"

#: A validity window wide enough that every latency-sweep payment falls inside it
#: (so the window branch of ``check_payment`` is exercised but never the cause of
#: a block). Violation cases override ``at`` to land outside it on purpose.
_VALID_FROM = datetime(2026, 1, 1, tzinfo=timezone.utc)
_VALID_UNTIL = datetime(2027, 1, 1, tzinfo=timezone.utc)


def _keypair(seed: int, role: str) -> tuple[str, str]:
    """Deterministic (private_hex, public_hex) Ed25519 keypair from (seed, role)."""
    material = hashlib.sha256(f"{seed}:{role}".encode()).digest()
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(material)
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def trust_store(seed: int) -> dict:
    """The ``trust-store@1`` mapping holding this seed's operator public key."""
    _op_priv, op_pub = _keypair(seed, "operator")
    return {OPERATOR_ID: {"alg": "ed25519", "public_key": op_pub}}


@dataclass(frozen=True)
class ChainSpec:
    """Declarative caveat overlay for one delegation hop (subset of ``@1``)."""

    max_per_call_usd: str | None = None
    endpoint_prefixes: tuple[str, ...] | None = None


def build_chain(
    depth: int,
    *,
    seed: int = 42,
    endpoint_prefixes: tuple[str, ...] | None = None,
    root_cap: str = "1.00",
    per_hop_narrow: str = "0.05",
    with_window: bool = True,
    valid_from: datetime = _VALID_FROM,
    valid_until: datetime = _VALID_UNTIL,
    verify_at: datetime | None = None,
) -> tuple[VerifiedGrantChain, dict]:
    """Build and verify a ``depth``-hop chain (root + ``depth-1`` delegations).

    The per-call cap starts at ``root_cap`` and narrows by ``per_hop_narrow`` at
    each hop (a strict, monotone attenuation the ``@1`` fragment guarantees). When
    ``endpoint_prefixes`` is ``None`` the chain leaves the URL axis unconstrained,
    so every corpus URL is admitted — the latency sweep varies *depth*, not the
    admitted set. ``with_window`` stamps the same wide validity window on every
    hop (equal bounds are a valid subset) so the window branch is exercised.

    Returns ``(verified_chain, trust_store)``.
    """
    if depth < 1:
        raise ValueError("depth must be >= 1")
    ts = trust_store(seed)
    op_priv, _op_pub = _keypair(seed, "operator")

    def caveats(hop: int) -> dict:
        cap = Decimal(root_cap) - Decimal(per_hop_narrow) * hop
        if cap <= 0:
            raise ValueError(f"depth {depth} exhausts root_cap {root_cap} at hop {hop}")
        c: dict = {"max_per_call_usd": f"{cap:.2f}"}
        if endpoint_prefixes is not None:
            c["endpoint_prefixes"] = list(endpoint_prefixes)
        if with_window:
            c["valid_from"] = valid_from.isoformat().replace("+00:00", "Z")
            c["valid_until"] = valid_until.isoformat().replace("+00:00", "Z")
        return c

    root_priv, root_pub = _keypair(seed, "hop0")
    grants = [
        issue_grant(
            subject="agent-0",
            issuer=OPERATOR_ID,
            issuer_private_key=op_priv,
            subject_public_key=root_pub,
            caveats=caveats(0),
            issued_at=valid_from,
        )
    ]
    parent_priv = root_priv
    for hop in range(1, depth):
        _child_priv, child_pub = _keypair(seed, f"hop{hop}")
        child = delegate_grant(
            grants[-1],
            parent_private_key=parent_priv,
            subject=f"agent-{hop}",
            subject_public_key=child_pub,
            caveats=caveats(hop),
            issued_at=valid_from,
        )
        grants.append(child)
        parent_priv = _child_priv

    # verify at a moment inside the window so the configured chain is admitted.
    at = verify_at or (valid_from + timedelta(days=1))
    return verify_chain(grants, ts, at=at), ts


def effective_cap(chain: VerifiedGrantChain) -> Decimal:
    """The effective per-call cap of a chain (for crafting over-budget cases)."""
    cap = chain.effective.max_per_call_usd
    return cap if cap is not None else Decimal("1.00")


# A raw (unverified) broadened chain: a child that RAISES the parent's per-call
# cap. verify_chain rejects it (attenuation violation) — used by the violation set
# in trust-store mode to exercise the verify-time rejection path.
def broadened_chain(seed: int, *, kind: str) -> tuple[list[dict], dict]:
    """Return a raw (list-of-dict) chain that must FAIL verification, plus its
    trust store. ``kind`` selects the broadening: ``cap`` raises the per-call cap;
    ``prefix`` escapes the parent prefix; ``window`` widens ``valid_until``.

    These are minted with :func:`delegate_grant`'s mint-time check bypassed by
    signing the child directly against the parent key with a broadened caveat —
    the authoritative rejection is :func:`verify_chain`'s, which the violation
    runner invokes. To avoid duplicating the sign path, we build a legal parent
    then hand-broaden the child via the library and rely on verify_chain.
    """
    from presidio_x402.capability import _sign_preimage, parse_grant, sha256_hex

    ts = trust_store(seed)
    op_priv, _ = _keypair(seed, "operator")
    root_priv, root_pub = _keypair(seed, "hop0")
    child_priv, child_pub = _keypair(seed, "hop1")

    root = issue_grant(
        subject="agent-0",
        issuer=OPERATOR_ID,
        issuer_private_key=op_priv,
        subject_public_key=root_pub,
        caveats={
            "max_per_call_usd": "0.50",
            "endpoint_prefixes": ["https://api.example.com/v1"],
            "valid_until": _VALID_UNTIL.isoformat().replace("+00:00", "Z"),
        },
        issued_at=_VALID_FROM,
    )
    # Each child keeps the parent's other bounds and broadens exactly one axis, so
    # verify_chain rejects with the axis-specific attenuation reason.
    parent_until = _VALID_UNTIL.isoformat().replace("+00:00", "Z")
    if kind == "cap":
        child_caveats = {  # per-call cap RAISED
            "max_per_call_usd": "5.00",
            "endpoint_prefixes": ["https://api.example.com/v1"],
            "valid_until": parent_until,
        }
    elif kind == "prefix":
        child_caveats = {  # endpoint prefix ESCAPES the parent set
            "max_per_call_usd": "0.50",
            "endpoint_prefixes": ["https://evil.example.net/"],
            "valid_until": parent_until,
        }
    elif kind == "window":
        child_caveats = {  # valid_until pushed LATER — window widened
            "max_per_call_usd": "0.50",
            "endpoint_prefixes": ["https://api.example.com/v1"],
            "valid_until": datetime(2099, 1, 1, tzinfo=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
    else:
        raise ValueError(f"unknown broadening kind {kind!r}")

    # Hand-mint the broadened child WITHOUT delegate_grant's mint-time attenuation
    # check (we WANT an invalid child; verify_chain is the authoritative gate).
    body: dict = {
        "schema": root["schema"],
        "subject": "agent-1",
        "issuer": "agent-0",
        "caveats": {k: child_caveats[k] for k in sorted(child_caveats)},
        "parent_hash": parse_grant(root).grant_hash,
        "issued_at": _VALID_FROM.isoformat().replace("+00:00", "Z"),
        "subject_public_key": child_pub,
    }
    body["grant_id"] = sha256_hex(body)
    body["signature"] = _sign_preimage(body, root_priv)
    return [root, body], ts
