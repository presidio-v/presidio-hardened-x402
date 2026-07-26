# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""ScreeningPipeline — the rail-agnostic screening core (v0.5.0, session-3 T2).

The patent-relevant four-control sequence (PII filter → trusted-wallet check →
policy engine → replay guard → MPA) extracted from the x402 gateway so that it
operates on :class:`~presidio_x402._types.PaymentDetails` alone and contains no
payment-protocol assumptions. Bindings (:mod:`presidio_x402.bindings`) translate
rail-specific wire formats into ``PaymentDetails``; the pipeline and its
security guarantees are reused unchanged across rails.

Behavioural contract: this module was extracted verbatim from
``gateway.HardenedX402Client`` — audit events, metric names, exception types,
rollback semantics, and redaction behaviour are byte-identical to v0.4.0. The
existing gateway test suite is the conformance proof.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Literal

import httpx

from .exceptions import (
    MPADeniedError,
    MPATimeoutError,
    PIIBlockedError,
    PolicyViolationError,
    ReplayDetectedError,
    X402PaymentError,
)
from .replay_guard import ReplayGuard, compute_fingerprint
from .telemetry import security_control_span, set_span_attribute

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from ._types import PaymentDetails
    from .audit_log import AuditLog
    from .capability import VerifiedGrantChain
    from .decision_ref import DecisionRefEmitter
    from .metrics import MetricsCollector
    from .mpa import MPAEngine
    from .pii_filter import PIIFilter
    from .policy_engine import PolicyEngine
    from .screening_client import ScreeningClient

logger = logging.getLogger("presidio_x402.core")

# Max characters of an exception message retained in audit records. Exception
# text frequently carries fragments of the offending input (JSON snippets,
# signing-key material, wallet addresses) — truncation caps blast radius.
SAFE_EXC_MESSAGE_MAX = 80

_USD_PEGGED = frozenset({"USDC", "USDT", "DAI", "USDCE", "USDBC"})


def safe_exc_message(exc: BaseException, max_len: int = SAFE_EXC_MESSAGE_MAX) -> str:
    """Truncate an exception message before it can reach an audit record."""
    msg = str(exc)
    if len(msg) > max_len:
        msg = msg[:max_len] + "...[truncated]"
    return msg


def resource_origin(url: str) -> str:
    """Scheme + host[:port] of a resource URL (allowlist key)."""
    parsed = httpx.URL(url)
    return str(parsed.copy_with(path="", query=None, fragment=None)).rstrip("/")


def amount_to_usd(amount: str, currency: str) -> float:
    """Convert a payment amount string to USD.

    Supports USD-pegged stablecoins only (USDC, USDT, DAI, USDCE, USDBC).
    Non-stablecoin currencies raise :class:`X402PaymentError` because without a
    price oracle the USD value cannot be determined, and silently understating it
    would allow policy limits to be bypassed.
    """
    try:
        value = Decimal(amount)
    except InvalidOperation as exc:
        raise X402PaymentError(f"Invalid payment amount {amount!r}: not a numeric value") from exc
    if not value.is_finite() or value < 0:
        raise X402PaymentError(
            f"Invalid payment amount {amount!r}: must be a finite non-negative number. "
            "Non-finite values (nan, inf, -inf) bypass comparison-based limit checks "
            "and are rejected to preserve policy enforcement integrity."
        )
    if currency.upper() not in _USD_PEGGED:
        raise X402PaymentError(
            f"Unsupported currency {currency!r} for policy enforcement. "
            f"Supported stablecoins: {sorted(_USD_PEGGED)}. "
            "For non-stablecoin payments configure a custom price oracle."
        )
    return float(value)


class ScreeningPipeline:
    """Pre-execution screening: PII → wallet allowlist → policy → replay → MPA.

    Rail-agnostic. Construct with the security components (typically done by a
    binding client such as :class:`~presidio_x402.gateway.HardenedX402Client`)
    and call :meth:`apply` with the parsed :class:`PaymentDetails` immediately
    before the payment is signed. If signing subsequently fails, call
    :meth:`rollback` with the returned fingerprint.
    """

    def __init__(
        self,
        *,
        pii_filter: PIIFilter,
        policy: PolicyEngine,
        replay: ReplayGuard,
        audit: AuditLog,
        pii_action: Literal["redact", "block", "warn"] = "redact",
        pii_entities: list[str] | None = None,
        mpa_engine: MPAEngine | None = None,
        metrics_collector: MetricsCollector | None = None,
        trusted_wallets: dict[str, frozenset[str]] | None = None,
        screening_client: ScreeningClient | None = None,
        remote_screening: bool = False,
        decision_ref_emitter: DecisionRefEmitter | None = None,
        capability_chain: VerifiedGrantChain | None = None,
        agent_id: str | None = None,
    ) -> None:
        if remote_screening and screening_client is None:
            raise ValueError("remote_screening=True requires a screening_client instance")
        self._pii_filter = pii_filter
        self._pii_entities = pii_entities
        self._pii_action = pii_action
        self._policy = policy
        self._replay = replay
        self._audit = audit
        self._mpa = mpa_engine
        self._metrics = metrics_collector
        self._trusted_wallets = trusted_wallets
        self._screening_client = screening_client
        self._remote_screening = remote_screening
        # Decision-ref emission is strictly opt-in: when the emitter is None (the
        # default) NO decision-ref code path runs and apply() is byte-identical to
        # prior releases. See presidio_x402.decision_ref.
        self._decision_emitter = decision_ref_emitter
        self._capability_chain = capability_chain
        self._agent_id = agent_id

    def rollback(self, *, resource_url: str, amount_usd: float, fingerprint: str) -> None:
        """Reverse the spend + replay fingerprint speculatively committed in
        :meth:`apply`.

        The policy spend and replay fingerprint are recorded *before* the payment
        is signed (so the TOCTOU-critical check+record stays atomic under a
        single lock — a guarantee that cannot span the async signer ``await``).
        When the payment is subsequently denied (MPA) or fails to sign, this
        compensating rollback keeps the spend ledger consistent with payments
        that actually committed and frees the fingerprint for a legitimate retry
        (F-03, 2026-06-03).
        """
        self._policy.refund(resource_url=resource_url, amount_usd=amount_usd)
        self._replay.release(fingerprint)

    async def apply(
        self,
        details: PaymentDetails,
        *,
        mpa_signatures: dict[str, str] | None = None,
        raw_offer_hash: str | None = None,
        on_decision_ref: Callable[[Mapping[str, object]], None] | None = None,
    ) -> tuple[PaymentDetails, str]:
        """Apply PIIFilter → PolicyEngine → ReplayGuard → MPAEngine → AuditLog.

        Returns a ``(details, fingerprint)`` tuple: the (possibly modified)
        :class:`~presidio_x402._types.PaymentDetails` with PII redacted from
        metadata fields if ``pii_action="redact"``, plus the replay fingerprint
        recorded for this payment so the caller can roll it back if signing
        fails.

        ``on_decision_ref``, when given, is called once with the emitted
        decision-ref envelope (nothing is called if emission is disabled or
        fails). It exists so a caller can correlate *this* payment's decision-ref
        with the settlement receipt it later observes, without the pipeline
        holding per-payment state that concurrent calls would race on — the
        caller's closure owns the value. Like the emitter itself it must not
        perform network I/O and must not raise; a raising callback is caught and
        logged with the emission.

        Raises on policy violation, replay, PII block, or MPA denial/timeout.
        On MPA denial/timeout the spend + replay commit is rolled back before
        re-raising.
        """
        amount_usd = amount_to_usd(details.amount, details.currency)

        # Decision-ref emission is opt-in. When an emitter is configured we track
        # each control's verdict as it runs so a single payment-decision@1 record
        # can be signed on the success path. When it is None this stays None and
        # no extra work happens (byte-identical default behaviour).
        decision_controls = None
        if self._decision_emitter is not None:
            from .decision_ref import ControlResults

            decision_controls = ControlResults()

        # Preserve the original resource_url for replay-guard fingerprinting.
        # In pii_action="redact" mode the URL gets rewritten with PII tokens
        # masked; using the redacted URL for fingerprinting would collide
        # distinct user-specific URLs (e.g. /user/alice@.../pay vs
        # /user/bob@.../pay both reduce to /user/<EMAIL_ADDRESS>/pay) and
        # produce false-positive ReplayDetectedError. Original URL is never
        # passed downstream to signer / MPA — only used for the local HMAC.
        original_resource_url = details.resource_url

        # ------------------------------------------------------------------
        # 1. PII Filter (local regex/NLP or remote screening service)
        # ------------------------------------------------------------------
        with security_control_span(
            "pii_filter",
            amount_usd=amount_usd,
            network=details.network,
            pii_action=self._pii_action,
            remote_screening=self._remote_screening,
        ) as pii_span:
            if self._remote_screening and self._screening_client is not None:
                (
                    clean_url,
                    clean_desc,
                    clean_reason,
                    pii_entities,
                ) = await self._screening_client.scan_payment_fields(
                    details.resource_url,
                    details.description,
                    details.reason,
                    entities=self._pii_entities,
                )
                # Defense-in-depth (F-06, 2026-06-03): the remote screener is the
                # only scan of the three primary fields, so a mis-redacting, empty,
                # or silently degraded response would pass PII through unredacted.
                # Re-run the fast local regex filter over its output as a cheap
                # backstop. On a correct remote response the fields are already
                # masked, so this finds nothing; it only catches what the remote
                # missed, and feeds those entities into the block/redact decision.
                clean_url, url_ent = self._pii_filter.scan_and_redact(clean_url)
                clean_desc, desc_ent = self._pii_filter.scan_and_redact(clean_desc)
                clean_reason, reason_ent = self._pii_filter.scan_and_redact(clean_reason)
                pii_entities = list(pii_entities) + url_ent + desc_ent + reason_ent
            else:
                clean_url, clean_desc, clean_reason, pii_entities = (
                    self._pii_filter.scan_payment_fields(
                        details.resource_url, details.description, details.reason
                    )
                )

            # The remote screening API only covers the three primary string fields.
            # The `extra` dict is arbitrary server-controlled JSON and must be
            # scanned locally for defense-in-depth — this closes REQ-1 against
            # malicious 402 servers that smuggle PII through the extra channel.
            clean_extra, extra_entities = self._pii_filter.scan_dict(details.extra)
            if extra_entities:
                pii_entities = list(pii_entities) + list(extra_entities)

            set_span_attribute(pii_span, "presidio_x402.pii.entity_count", len(pii_entities))
            if pii_entities:
                entity_types = [e.entity_type for e in pii_entities]
                set_span_attribute(
                    pii_span,
                    "presidio_x402.pii.entity_types",
                    sorted(set(entity_types)),
                )
                if self._pii_action == "block":
                    set_span_attribute(pii_span, "presidio_x402.outcome", "blocked")
                    self._audit.emit(
                        "PII_BLOCKED",
                        resource_url=clean_url,
                        amount_usd=amount_usd,
                        network=details.network,
                        outcome="blocked",
                        pii_entities_found=entity_types,
                    )
                    if self._metrics:
                        self._metrics.record_pii_detection(entity_types, "block")
                        self._metrics.record_payment_blocked("pii", amount_usd)
                    raise PIIBlockedError(
                        f"PII detected in payment metadata: "
                        f"{', '.join(sorted(set(entity_types)))}",
                        entities=entity_types,
                    )
                elif self._pii_action == "redact":
                    self._audit.emit(
                        "PII_REDACTED",
                        resource_url=clean_url,
                        amount_usd=amount_usd,
                        network=details.network,
                        outcome="allowed",
                        pii_entities_found=entity_types,
                    )
                    if self._metrics:
                        self._metrics.record_pii_detection(entity_types, "redact")
                    # Replace metadata fields with redacted versions.
                    # resource_url is replaced AFTER replay-fingerprint computation
                    # earlier in this function so the original URL still drives
                    # deduplication; from this point on every downstream consumer
                    # (signer, MPA webhooks, audit log post-event) sees clean_url.
                    # The `extra` dict is also redacted in-place when PII is found
                    # in any of its string values (REQ-1 — closes F-A 2026-05-03).
                    details = replace(
                        details,
                        resource_url=clean_url,
                        description=clean_desc,
                        reason=clean_reason,
                        extra=clean_extra if extra_entities else details.extra,
                    )
                elif self._metrics:
                    # pii_action == "warn": log already happened in PIIFilter
                    self._metrics.record_pii_detection(entity_types, "warn")
            set_span_attribute(pii_span, "presidio_x402.outcome", "allowed")

        # Record the PII verdict for the decision-ref (success path: never
        # PII_BLOCKED, since that raises above). Only entity-type LABELS enter
        # here — the screened strings never do (PII-freedom by construction).
        if decision_controls is not None:
            entity_labels = sorted({e.entity_type for e in pii_entities})
            if not entity_labels:
                decision_controls.pii_verdict = "PII_NONE"
            elif self._pii_action == "redact":
                decision_controls.pii_verdict = "PII_REDACTED"
                decision_controls.pii_mutated = True
            elif self._pii_action == "warn":
                decision_controls.pii_verdict = "PII_WARNED"
            decision_controls.pii_entities = tuple(entity_labels)

        # ------------------------------------------------------------------
        # 2. Trusted-wallet allowlist (pay_to substitution defence)
        # ------------------------------------------------------------------
        if self._trusted_wallets is not None:
            # Key the allowlist off the ORIGINAL (pre-redaction) origin. PII
            # redaction can rewrite the host (IP literals via IP_ADDRESS,
            # digit-laden DNS labels via US_SSN/PHONE_NUMBER), which would shift
            # the origin string out of the allowlist, miss the lookup, and
            # silently skip the pay_to check entirely. The host is a
            # security-control key, not PII — this mirrors the replay
            # fingerprint, which also keys off original_resource_url below
            # (CWE-348 / F-02, 2026-06-03).
            origin = resource_origin(original_resource_url)
            allowed = self._trusted_wallets.get(origin)
            if allowed is not None and details.pay_to.lower() not in allowed:
                # The raw origin may contain a redactable host; keep it out of
                # the persisted audit message and surface only the redacted URL.
                self._audit.emit(
                    "WALLET_BLOCKED",
                    resource_url=clean_url,
                    amount_usd=amount_usd,
                    network=details.network,
                    outcome="blocked",
                    error_message=f"pay_to {details.pay_to!r} not in trusted wallet allowlist",
                )
                if self._metrics:
                    self._metrics.record_payment_blocked("wallet", amount_usd)
                raise X402PaymentError(
                    f"pay_to wallet {details.pay_to!r} not in trusted allowlist"
                )

        # ------------------------------------------------------------------
        # 3. Policy Engine
        # ------------------------------------------------------------------
        with security_control_span(
            "policy",
            amount_usd=amount_usd,
            network=details.network,
        ) as policy_span:
            try:
                self._policy.check_and_record(
                    resource_url=details.resource_url, amount_usd=amount_usd
                )
                set_span_attribute(policy_span, "presidio_x402.outcome", "allowed")
                if decision_controls is not None:
                    from .decision_ref import policy_limit_hash, policy_snapshot_hash

                    decision_controls.policy_verdict = "ALLOW"
                    decision_controls.policy_snapshot_hash = policy_snapshot_hash(
                        self._policy.config
                    )
                    decision_controls.policy_limit_hash = policy_limit_hash(self._policy.config)
            except PolicyViolationError as exc:
                set_span_attribute(policy_span, "presidio_x402.outcome", "blocked")
                set_span_attribute(
                    policy_span,
                    "presidio_x402.policy.limit_usd",
                    exc.limit_usd if exc.limit_usd is not None else 0.0,
                )
                self._audit.emit(
                    "POLICY_BLOCKED",
                    resource_url=clean_url,
                    amount_usd=amount_usd,
                    network=details.network,
                    outcome="blocked",
                    policy_limit_usd=exc.limit_usd,
                )
                if self._metrics:
                    self._metrics.record_policy_violation("limit_exceeded")
                    self._metrics.record_payment_blocked("policy", amount_usd)
                raise

        # ------------------------------------------------------------------
        # 4. Replay Guard
        # ------------------------------------------------------------------
        fingerprint = compute_fingerprint(
            resource_url=original_resource_url,  # ORIGINAL URL — see top of method
            pay_to=details.pay_to,
            amount=details.amount,
            currency=details.currency,
            deadline_seconds=details.deadline_seconds,
            network=details.network,
        )
        with security_control_span(
            "replay",
            amount_usd=amount_usd,
            network=details.network,
        ) as replay_span:
            try:
                self._replay.check_and_record(fingerprint)
                set_span_attribute(replay_span, "presidio_x402.outcome", "allowed")
                if decision_controls is not None:
                    from .decision_ref import fingerprint_hash

                    decision_controls.replay_verdict = "FRESH"
                    decision_controls.replay_fingerprint_hash = fingerprint_hash(fingerprint)
            except ReplayDetectedError:
                set_span_attribute(replay_span, "presidio_x402.outcome", "blocked")
                set_span_attribute(
                    replay_span,
                    "presidio_x402.replay.fingerprint_prefix",
                    fingerprint[:16],
                )
                self._audit.emit(
                    "REPLAY_BLOCKED",
                    resource_url=clean_url,
                    amount_usd=amount_usd,
                    network=details.network,
                    outcome="blocked",
                    replay_fingerprint=fingerprint[:16],
                )
                if self._metrics:
                    self._metrics.record_replay_detection()
                    self._metrics.record_payment_blocked("replay", amount_usd)
                raise

        # ------------------------------------------------------------------
        # 5. Multi-Party Authorization (if configured)
        # ------------------------------------------------------------------
        if self._mpa is not None:
            with security_control_span(
                "mpa",
                amount_usd=amount_usd,
                network=details.network,
                mpa_threshold=self._mpa.config.threshold,
            ) as mpa_span:
                try:
                    await self._mpa.request_approval(
                        details, amount_usd, provided_signatures=mpa_signatures
                    )
                    set_span_attribute(mpa_span, "presidio_x402.outcome", "approved")
                    if self._metrics:
                        self._metrics.record_mpa_event("approved")
                    if decision_controls is not None:
                        decision_controls.mpa_verdict = "APPROVED"
                        decision_controls.mpa_required = True
                        decision_controls.mpa_threshold = self._mpa.config.threshold
                except (MPADeniedError, MPATimeoutError) as exc:
                    # Roll back the spend + replay fingerprint committed at steps 3–4:
                    # an MPA-denied/timed-out payment was never signed, so it must not
                    # charge the budget or burn the fingerprint (which would block the
                    # legitimate crypto-mode retry that carries the countersignatures).
                    self.rollback(
                        resource_url=details.resource_url,
                        amount_usd=amount_usd,
                        fingerprint=fingerprint,
                    )
                    outcome = "timeout" if isinstance(exc, MPATimeoutError) else "denied"
                    set_span_attribute(mpa_span, "presidio_x402.outcome", outcome)
                    safe_msg, _ = self._pii_filter.scan_and_redact(safe_exc_message(exc))
                    self._audit.emit(
                        "MPA_BLOCKED",
                        resource_url=clean_url,
                        amount_usd=amount_usd,
                        network=details.network,
                        outcome="blocked",
                        error_message=safe_msg,
                    )
                    if self._metrics:
                        self._metrics.record_mpa_event(outcome)
                        self._metrics.record_payment_blocked(f"mpa_{outcome}", amount_usd)
                    raise

        # Trusted-wallet verdict on the success path is TRUSTED (an UNTRUSTED
        # pay_to raises above, before we reach here).
        if decision_controls is not None:
            decision_controls.trusted_wallet_verdict = "TRUSTED"

        # Emit the signed payment-decision@1 record immediately before returning
        # to the caller, which signs next. No network I/O on this path.
        if self._decision_emitter is not None and decision_controls is not None:
            self._emit_decision_ref(
                details,
                decision_controls,
                raw_offer_hash=raw_offer_hash,
                on_decision_ref=on_decision_ref,
            )

        return details, fingerprint

    def _emit_decision_ref(
        self,
        details: PaymentDetails,
        controls: object,
        *,
        raw_offer_hash: str | None = None,
        on_decision_ref: Callable[[Mapping[str, object]], None] | None = None,
    ) -> None:
        """Build and write one payment-decision@1 record (opt-in path only).

        Best-effort by contract: emission must never change the payment outcome,
        so any emitter/signing failure is caught and logged rather than raised —
        a decision the gateway already made must not be undone by a record of it.
        """
        from .decision_ref import capability_parents, details_hash

        try:
            origin = resource_origin(details.resource_url)
            d_hash = details_hash(
                pay_to=details.pay_to,
                amount=details.amount,
                currency=details.currency,
                network=details.network,
            )
            envelope = self._decision_emitter.emit(  # type: ignore[union-attr]
                agent_id=self._agent_id or "",
                payment_signer=details.pay_to,
                network=details.network,
                binding="x402",
                offer_hash=raw_offer_hash,
                offer_hash_absent="not-retained",
                details_hash=d_hash,
                pay_to=details.pay_to,
                amount=details.amount,
                currency=details.currency,
                resource_origin=origin,
                controls=controls,  # type: ignore[arg-type]
                parents=capability_parents(self._capability_chain),
            )
            if on_decision_ref is not None:
                on_decision_ref(envelope)
        except Exception:
            logger.exception("decision-ref emission failed (payment outcome unaffected)")
