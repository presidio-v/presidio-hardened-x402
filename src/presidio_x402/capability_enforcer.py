"""CapabilityEnforcer — pre-transmission capability-grant@1 enforcement stage.

An explicit, opt-in :class:`~presidio_x402.core.ScreeningPipeline` stage that
makes each outgoing x402 payment prove it is authorised by a verified
``presidio-hardened/capability-grant@1`` chain (Pillar I of the Computational
Jurisprudence program; Stantchev, arXiv 2026) **before** the payment is signed
and transmitted. It is the end-to-end wiring the arXiv resubmission plan calls
**E2** ("Capability-enforced x402 payments, end-to-end"); it is also the
concrete realization of **CJ-EVAL Phase A/B** — the capability library
(``capability.py``) is the Phase-B dependency, and this stage is what puts a
per-payment ``verify_chain`` / ``check_payment`` on the decision path so B2
(grant verification time on the payment path) becomes measurable end-to-end.
See ``plan/e2-capability-enforcer-design.md``.

**This module reuses, it does not reimplement.** Chain verification is
:func:`presidio_x402.capability.verify_chain`; per-call caveat enforcement is
:meth:`presidio_x402.capability.VerifiedGrantChain.check_payment` (budget /
endpoint-prefix / validity-window); the effective-caveats → policy projection is
:func:`presidio_x402.capability.policy_config_from_chain`; the block-time
evidence record is the family ``payment-decision@1`` artifact built and signed by
:mod:`presidio_x402.decision_ref`, parent-linked to the chain's terminal
``grant_hash`` via :func:`presidio_x402.decision_ref.capability_parents`. **No
caveat-language extension** is introduced here: the stage enforces exactly the
``@1`` caveats (``max_per_call_usd``, ``endpoint_prefixes``, validity window);
aggregate budgets (``daily_limit_usd`` / ``window_seconds``) remain the
``PolicyEngine`` ledger's job via the existing config bridge. Jurisdiction is
**not** representable in the ``@1`` caveat fragment and is therefore *not*
enforced here (extending the fragment is explicitly out of scope).

**Two construction modes (constructor decides):**

- *configured chain* — a :class:`~presidio_x402.capability.VerifiedGrantChain`
  verified once at wiring time; every call enforces its effective caveats
  (including the validity window re-checked at exercise time);
- *trust store* — a ``trust-store@1`` mapping; a chain **presented per call** is
  verified against it (:func:`verify_chain`) and then enforced.

**Default OFF.** The pipeline runs this stage only when a ``CapabilityEnforcer``
is wired in; when it is absent, no code in this module runs and pipeline
behaviour is byte-identical to prior releases.

**No network I/O.** Verification and enforcement are local and O(chain length);
evidence emission only hashes and signs. The stage never reaches out.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING

from .capability import (
    CapabilityError,
    VerifiedGrantChain,
    policy_config_from_chain,
    verify_chain,
)
from .decision_ref import (
    ControlResults,
    capability_parents,
    details_hash,
    policy_snapshot_hash,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from ._types import PaymentDetails
    from .decision_ref import DecisionRefEmitter


@dataclass
class StageTiming:
    """Per-stage monotonic (``perf_counter_ns``) timing for one payment.

    The three fields are the per-stage breakdown E2 reports against the published
    5.73 ms p99 redaction-only baseline (arXiv:2604.11430v2; cited, not
    re-derived): PII **redaction**, **capability verification** (chain resolve +
    per-call caveat check), and **evidence write** (build + sign + write the
    ``payment-decision@1`` record — the success record on allow, the DENY record
    on block). A field stays ``None`` when its stage did not run on this call.
    """

    redaction_ns: int | None = None
    capability_verify_ns: int | None = None
    evidence_write_ns: int | None = None


class CapabilityEnforcer:
    """Verify + enforce a capability-grant@1 chain against an outgoing payment.

    Parameters
    ----------
    chain:
        A pre-verified :class:`~presidio_x402.capability.VerifiedGrantChain`
        (configured-chain mode). Mutually exclusive with ``trust_store``.
    trust_store:
        A ``trust-store@1`` mapping (or its JSON text). In this mode a chain must
        be *presented per call* (``presented_chain=``) and is verified against
        this store before enforcement. Mutually exclusive with ``chain``.
    emitter:
        Optional :class:`~presidio_x402.decision_ref.DecisionRefEmitter`. When
        set, a signed ``payment-decision@1`` DENY record is emitted on every
        block, parent-linked to the chain's terminal ``grant_hash``. When
        ``None``, blocking still happens (fail-closed) but no record is written.
        Wire the **same** emitter the pipeline uses on its allow path so allow and
        block records land in one sink.
    agent_id:
        Optional agent identifier carried into the effective ``PolicyConfig``
        snapshot hash and the evidence record's ``agent_id``.
    """

    def __init__(
        self,
        *,
        chain: VerifiedGrantChain | None = None,
        trust_store: str | Mapping[str, object] | None = None,
        emitter: DecisionRefEmitter | None = None,
        agent_id: str | None = None,
    ) -> None:
        if (chain is None) == (trust_store is None):
            raise ValueError(
                "CapabilityEnforcer requires exactly one of chain= (configured) or "
                "trust_store= (verify a presented chain per call)"
            )
        self._chain = chain
        self._trust_store = trust_store
        self._emitter = emitter
        self._agent_id = agent_id

    @property
    def mode(self) -> str:
        """``"configured"`` (fixed chain) or ``"trust_store"`` (verify per call)."""
        return "configured" if self._chain is not None else "trust_store"

    def resolve_chain(
        self,
        presented_chain: Sequence[Mapping[str, object]] | None = None,
        *,
        at: datetime | None = None,
    ) -> VerifiedGrantChain:
        """Return the chain to enforce (fail-closed).

        Configured-chain mode returns the pre-verified chain (its validity window
        is re-checked at exercise time by :meth:`enforce`). Trust-store mode
        verifies ``presented_chain`` against the store with :func:`verify_chain`
        (which itself gates the window at ``at``) and returns the verified result.
        """
        if self._chain is not None:
            if presented_chain is not None:
                raise CapabilityError(
                    "enforcer is in configured-chain mode; a per-call presented_chain "
                    "is not accepted (construct with trust_store= to verify presented chains)"
                )
            return self._chain
        if presented_chain is None:
            raise CapabilityError(
                "enforcer is in trust-store mode; a per-call presented_chain is required"
            )
        return verify_chain(presented_chain, self._trust_store, at=at)  # type: ignore[arg-type]

    def enforce(
        self,
        details: PaymentDetails,
        amount_usd: Decimal | float | int | str,
        *,
        resource_url: str | None = None,
        presented_chain: Sequence[Mapping[str, object]] | None = None,
        at: datetime | None = None,
        timing: StageTiming | None = None,
        pii_verdict: str = "PII_NONE",
        pii_entities: Sequence[str] = (),
        pii_mutated: bool = False,
    ) -> VerifiedGrantChain:
        """Enforce the chain's effective caveats against one outgoing payment.

        Runs pre-transmission. On success returns the
        :class:`~presidio_x402.capability.VerifiedGrantChain`. On any caveat
        violation (over-budget per-call, out-of-prefix endpoint, or an
        expired / not-yet-valid window) it emits a DENY evidence record (when an
        emitter is configured) and raises
        :class:`~presidio_x402.capability.CapabilityError` — the payment is
        blocked before it is signed.

        ``resource_url`` should be the **original, pre-redaction** URL (endpoint
        prefixes match against the real host/path; a redacted URL would corrupt
        the match, exactly as the replay fingerprint and trusted-wallet check key
        off the original URL). It defaults to ``details.resource_url``.

        ``timing`` — when supplied — receives ``capability_verify_ns`` (chain
        resolve + :meth:`check_payment`) and, on the block path,
        ``evidence_write_ns`` (build + sign + write the DENY record).
        """
        url = resource_url if resource_url is not None else details.resource_url
        amount = amount_usd if isinstance(amount_usd, Decimal) else Decimal(str(amount_usd))

        t0 = time.perf_counter_ns()
        try:
            chain = self.resolve_chain(presented_chain, at=at)
            chain.check_payment(resource_url=url, amount_usd=amount, at=at)
        except CapabilityError:
            if timing is not None:
                timing.capability_verify_ns = time.perf_counter_ns() - t0
            self._emit_block_evidence(
                details,
                amount=amount,
                timing=timing,
                pii_verdict=pii_verdict,
                pii_entities=pii_entities,
                pii_mutated=pii_mutated,
                presented_chain=presented_chain,
                at=at,
            )
            raise
        if timing is not None:
            timing.capability_verify_ns = time.perf_counter_ns() - t0
        return chain

    def _emit_block_evidence(
        self,
        details: PaymentDetails,
        *,
        amount: Decimal,
        timing: StageTiming | None,
        pii_verdict: str,
        pii_entities: Sequence[str],
        pii_mutated: bool,
        presented_chain: Sequence[Mapping[str, object]] | None,
        at: datetime | None,
    ) -> None:
        """Emit the DENY ``payment-decision@1`` record for a blocked payment.

        Best-effort by contract (mirrors the pipeline's allow-path emission): a
        record of a decision must never change the decision, so an emitter/sink
        failure is swallowed rather than raised — the block still stands.

        The capability denial is represented as a **policy-authority
        ``VIOLATION``** (the caveats *are* the spending policy: the effective
        chain projects to a ``PolicyConfig`` via the existing bridge, whose
        content hash is recorded as ``policy_snapshot_hash``), so ``f(controls)``
        recomputes to ``DENY``. Downstream gates (replay, MPA) were never
        reached, so they carry their neutral defaults. The grant hash travels as
        the provenance **parent** that names which authority denied the payment;
        a verifier recomputes the DENY and checks the parent linkage offline.
        """
        if self._emitter is None:
            return
        # Which chain was denying? In trust-store mode the presented chain may
        # itself be unverifiable (a forged/expired grant) — then there is no
        # terminal grant_hash to link, and the record is emitted parent-less.
        try:
            chain = self.resolve_chain(presented_chain, at=at)
        except CapabilityError:
            chain = None

        parents = capability_parents(chain)
        snapshot_hash = (
            policy_snapshot_hash(policy_config_from_chain(chain, agent_id=self._agent_id))
            if chain is not None
            else "sha256:" + ("0" * 64)
        )
        controls = ControlResults(
            pii_verdict=pii_verdict,
            pii_entities=tuple(pii_entities),
            pii_mutated=pii_mutated,
            trusted_wallet_verdict="TRUSTED",
            policy_verdict="VIOLATION",
            policy_snapshot_hash=snapshot_hash,
        )
        d_hash = details_hash(
            pay_to=details.pay_to,
            amount=details.amount,
            currency=details.currency,
            network=details.network,
        )
        from .core import resource_origin

        t0 = time.perf_counter_ns()
        try:
            self._emitter.emit(
                agent_id=self._agent_id or (chain.subject if chain is not None else ""),
                payment_signer=details.pay_to,
                network=details.network,
                binding="x402",
                offer_hash_absent="not-retained",
                details_hash=d_hash,
                pay_to=details.pay_to,
                amount=details.amount,
                currency=details.currency,
                resource_origin=resource_origin(details.resource_url),
                controls=controls,
                parents=parents or None,
            )
        except Exception:  # noqa: BLE001 - a record must never undo the block
            import logging

            logging.getLogger("presidio_x402.capability_enforcer").exception(
                "capability-block evidence emission failed (block outcome unaffected)"
            )
        finally:
            if timing is not None:
                timing.evidence_write_ns = time.perf_counter_ns() - t0
