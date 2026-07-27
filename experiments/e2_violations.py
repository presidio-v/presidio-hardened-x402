"""E2 violation set + detection-table runner (CapabilityEnforcer).

Fifty crafted violation cases across five classes, each with an expected verdict
(``blocked``):

  * ``over_budget``        — amount exceeds the effective per-call cap
  * ``out_of_prefix``      — resource URL outside the granted endpoint prefixes
  * ``expired``            — payment exercised after the grant's ``valid_until``
  * ``broadened_child``    — a presented child grant broadens its parent (the
                             ``over-depth / broadened child`` class): per-call cap
                             raised, prefix escaped, or window widened →
                             ``verify_chain`` rejects at verification time
  * ``replayed``           — a byte-identical repeat of an already-seen payment

The cases are a committed, declarative artifact (``e2_violations.jsonl``); the
runner materializes each case's seeded grant chain with the released
``capability.py`` helpers, drives it through the **full** pipeline, and prints the
plan's **detection table** — per class: ``n``, ``blocked``, ``evidence_emitted``
(a structured record was produced — the signed ``payment-decision@1`` DENY record
for the capability classes, or the hash-chained audit block event for the replay
class), and ``decision_ref`` (signed DENY records specifically). Per the plan this
is a detection table, **not** an accuracy-theater score.

Regenerate the JSONL with ``--emit``; run the table (default) with no flags. No
network I/O. Import-safe without the ``[nlp]`` extra.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from experiments.e2_chains import broadened_chain, build_chain  # noqa: E402
from presidio_x402._types import PaymentDetails  # noqa: E402
from presidio_x402.audit_log import AuditLog  # noqa: E402
from presidio_x402.capability import CapabilityError  # noqa: E402
from presidio_x402.capability_enforcer import CapabilityEnforcer  # noqa: E402
from presidio_x402.core import ScreeningPipeline  # noqa: E402
from presidio_x402.decision_ref import DecisionRefEmitter  # noqa: E402
from presidio_x402.exceptions import ReplayDetectedError  # noqa: E402
from presidio_x402.pii_filter import PIIFilter  # noqa: E402
from presidio_x402.policy_engine import PolicyEngine  # noqa: E402
from presidio_x402.replay_guard import ReplayGuard  # noqa: E402

JSONL_PATH = Path(__file__).parent / "e2_violations.jsonl"
SEED = 2026
_SIGNER_KEY = "22" * 32  # deterministic Ed25519 hex; sandbox-only
_PREFIX = "https://api.example.com/v1"
_IN_PREFIX_URL = "https://api.example.com/v1/inference/run"
_CLASSES = ("over_budget", "out_of_prefix", "expired", "broadened_child", "replayed")

# A grant window already expired relative to "now" so the per-call check_payment
# (which exercises at wall-clock now) rejects an otherwise-valid chain.
_PAST_FROM = datetime(2026, 6, 1, tzinfo=timezone.utc)
_PAST_UNTIL = datetime(2026, 6, 15, tzinfo=timezone.utc)
_PAST_VERIFY = datetime(2026, 6, 5, tzinfo=timezone.utc)


def generate_cases() -> list[dict]:
    """Deterministically build the 50-case violation set (10 per class)."""
    cases: list[dict] = []
    for i in range(10):
        cases.append(
            {
                "id": f"vio-over_budget-{i:02d}",
                "klass": "over_budget",
                "resource_url": f"{_IN_PREFIX_URL}?q={i}",
                "amount_usd": f"{0.60 + 0.10 * i:.2f}",  # > effective cap 0.50
                "expected": "blocked",
                "reason_class": "amount exceeds effective max_per_call_usd",
            }
        )
    for i in range(10):
        # sibling host / sibling path that shares a leading substring but escapes
        # the prefix on a host/path boundary — the confusable case must still block.
        url = (
            f"https://api.example.com/v2/inference/run?q={i}"
            if i % 2 == 0
            else f"https://api.example.com.evil.net/v1/run?q={i}"
        )
        cases.append(
            {
                "id": f"vio-out_of_prefix-{i:02d}",
                "klass": "out_of_prefix",
                "resource_url": url,
                "amount_usd": "0.01",
                "expected": "blocked",
                "reason_class": "resource_url outside granted endpoint_prefixes",
            }
        )
    for i in range(10):
        cases.append(
            {
                "id": f"vio-expired-{i:02d}",
                "klass": "expired",
                "resource_url": f"{_IN_PREFIX_URL}?q={i}",
                "amount_usd": "0.01",
                "expected": "blocked",
                "reason_class": "payment exercised after grant valid_until",
            }
        )
    for i in range(10):
        kind = ("cap", "prefix", "window")[i % 3]
        cases.append(
            {
                "id": f"vio-broadened_child-{i:02d}",
                "klass": "broadened_child",
                "resource_url": f"{_PREFIX}/run?q={i}",
                "amount_usd": "0.01",
                "broaden_kind": kind,
                "expected": "blocked",
                "reason_class": f"child broadens parent ({kind}) — verify_chain rejects",
            }
        )
    for i in range(10):
        cases.append(
            {
                "id": f"vio-replayed-{i:02d}",
                "klass": "replayed",
                "resource_url": f"{_IN_PREFIX_URL}/r{i}",
                "amount_usd": "0.02",
                "expected": "blocked",
                "reason_class": "byte-identical repeat of an already-seen payment",
            }
        )
    return cases


def emit_jsonl(path: Path = JSONL_PATH) -> int:
    cases = generate_cases()
    with path.open("w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c, sort_keys=True) + "\n")
    return len(cases)


class _AuditCapture:
    def __init__(self) -> None:
        self.events: list = []

    def write(self, event) -> None:
        self.events.append(event)


class _RecordCapture:
    def __init__(self) -> None:
        self.records: list = []

    def write(self, envelope) -> None:
        self.records.append(dict(envelope))


def _details(case: dict) -> PaymentDetails:
    return PaymentDetails(
        resource_url=case["resource_url"],
        pay_to="0x" + "cd" * 20,
        amount=case["amount_usd"],
        currency="USDC",
        network="base-sepolia",
        deadline_seconds=300,
    )


def _make_pipeline(enforcer, emitter):
    audit_cap = _AuditCapture()
    pipeline = ScreeningPipeline(
        pii_filter=PIIFilter(mode="regex"),
        policy=PolicyEngine(None),
        replay=ReplayGuard(ttl=3600),
        audit=AuditLog(audit_cap),
        pii_action="redact",
        decision_ref_emitter=emitter,
        capability_enforcer=enforcer,
    )
    return pipeline, audit_cap


async def _run_case(case: dict) -> dict:
    """Run one case through the full pipeline; return an outcome dict."""
    klass = case["klass"]
    records = _RecordCapture()
    emitter = DecisionRefEmitter(
        signing_key=_SIGNER_KEY, signer="e2-policy-signer", writer=records
    )

    if klass == "broadened_child":
        raw_chain, trust = broadened_chain(SEED, kind=case["broaden_kind"])
        enforcer = CapabilityEnforcer(trust_store=trust, emitter=emitter)
        pipeline, audit_cap = _make_pipeline(enforcer, emitter)
        presented = raw_chain
        chain_for_provenance = None
    else:
        if klass == "expired":
            chain, _ts = build_chain(
                2,
                seed=SEED,
                endpoint_prefixes=(_PREFIX,),
                root_cap="0.60",
                per_hop_narrow="0.10",
                valid_from=_PAST_FROM,
                valid_until=_PAST_UNTIL,
                verify_at=_PAST_VERIFY,
            )
        else:
            chain, _ts = build_chain(
                2, seed=SEED, endpoint_prefixes=(_PREFIX,), root_cap="0.60", per_hop_narrow="0.10"
            )
        enforcer = CapabilityEnforcer(chain=chain, emitter=emitter, agent_id=chain.subject)
        pipeline, audit_cap = _make_pipeline(enforcer, emitter)
        pipeline._capability_chain = chain  # provenance parent on any success emit
        presented = None
        chain_for_provenance = chain

    blocked = False
    block_gate = None
    try:
        if klass == "replayed":
            # First send must be allowed; the byte-identical repeat is the violation.
            await pipeline.apply(_details(case), presented_chain=presented)
            await pipeline.apply(_details(case), presented_chain=presented)
        else:
            await pipeline.apply(_details(case), presented_chain=presented)
    except CapabilityError:
        blocked, block_gate = True, "capability"
    except ReplayDetectedError:
        blocked, block_gate = True, "replay"

    audit_blocked = any(getattr(e, "outcome", None) == "blocked" for e in audit_cap.events)
    decision_refs = sum(
        1 for r in records.records if r.get("payment_decision", {}).get("verdict") == "DENY"
    )
    return {
        "id": case["id"],
        "klass": klass,
        "blocked": blocked,
        "block_gate": block_gate,
        "evidence_emitted": bool(decision_refs) or audit_blocked,
        "decision_ref": decision_refs,
        "expected": case["expected"],
        "_provenance_ok": chain_for_provenance is not None or klass == "broadened_child",
    }


async def _run_all(cases: list[dict]) -> list[dict]:
    return [await _run_case(c) for c in cases]


def _table(outcomes: list[dict]) -> str:
    agg: dict[str, dict[str, int]] = defaultdict(
        lambda: {"n": 0, "blocked": 0, "evidence_emitted": 0, "decision_ref": 0}
    )
    for o in outcomes:
        a = agg[o["klass"]]
        a["n"] += 1
        a["blocked"] += int(o["blocked"])
        a["evidence_emitted"] += int(o["evidence_emitted"])
        a["decision_ref"] += int(o["decision_ref"] > 0)
    lines = [
        f"{'class':<18} {'n':>3} {'blocked':>8} {'evidence':>9} {'decision_ref':>13}",
        "-" * 54,
    ]
    tot = {"n": 0, "blocked": 0, "evidence_emitted": 0, "decision_ref": 0}
    for klass in _CLASSES:
        a = agg[klass]
        for k in tot:
            tot[k] += a[k]
        lines.append(
            f"{klass:<18} {a['n']:>3} {a['blocked']:>8} "
            f"{a['evidence_emitted']:>9} {a['decision_ref']:>13}"
        )
    lines.append("-" * 54)
    lines.append(
        f"{'TOTAL':<18} {tot['n']:>3} {tot['blocked']:>8} "
        f"{tot['evidence_emitted']:>9} {tot['decision_ref']:>13}"
    )
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description="E2 violation detection table")
    p.add_argument("--emit", action="store_true", help="(re)write e2_violations.jsonl and exit")
    p.add_argument("--jsonl", type=Path, default=JSONL_PATH)
    p.add_argument("--json-out", type=Path, default=None, help="also dump per-case outcomes JSON")
    args = p.parse_args()

    if args.emit:
        n = emit_jsonl(args.jsonl)
        print(f"wrote {n} cases to {args.jsonl}")
        return

    if not args.jsonl.exists():
        emit_jsonl(args.jsonl)
    cases = [json.loads(line) for line in args.jsonl.read_text().splitlines() if line.strip()]
    outcomes = asyncio.run(_run_all(cases))

    print(
        f"E2 violation set — {len(cases)} cases (SANDBOX; detection table, not accuracy theater)\n"
    )
    print(_table(outcomes))
    all_blocked = all(o["blocked"] for o in outcomes)
    print(f"\nall expected-blocked cases blocked: {all_blocked}")
    if args.json_out:
        args.json_out.write_text(json.dumps(outcomes, indent=2))
        print(f"per-case outcomes → {args.json_out}")
    if not all_blocked:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
