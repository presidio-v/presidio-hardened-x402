"""E2 corpus-replay latency harness — CapabilityEnforcer on the payment path.

Replays the 2,000-triple labeled corpus (``tools/corpus/corpus.jsonl``) through
the **full** :class:`~presidio_x402.core.ScreeningPipeline` with a
:class:`~presidio_x402.capability_enforcer.CapabilityEnforcer` configured at chain
depths ``{1, 2, 4, 6}`` (built with ``capability.py`` helpers, seeded — see
``e2_chains.py``), collecting the per-stage latency breakdown E2 demands:

    redaction | capability verification | evidence write

as p50 / p99 (ms), plus the total added latency (capability verify + evidence
write) that composes with the published **5.73 ms p99 redaction-only baseline**
(arXiv:2604.11430v2, NLP mode; **cited, not re-derived here**). Results are written
as CSV with a metadata sidecar; sandbox runs are labelled in that metadata.

This is the arXiv-resubmission-plan **E2** latency leg and the runnable
realization of **CJ-EVAL Phase A2** (per-gate decomposition) + **Phase B2** (grant
verification time on the payment path). It measures the *released* grant@1 artifact
end-to-end; ZK-tier numbers remain literature-cited (CJ-EVAL Phase C).

Runnable now at reduced scale (``--limit``); the full 2,000×{depths}×N sweep runs
later on the owner's Mac mini (use ``--pii-mode nlp`` there to compose against the
5.73 ms NLP baseline; regex mode is the zero-setup sandbox default).

**No network I/O.** A deterministic non-network stub stands in for the signer; the
pipeline is driven directly (no HTTP). Usage::

    python -m experiments.e2_replay                      # sandbox: regex, limit 200
    python -m experiments.e2_replay --limit 2000 --pii-mode nlp --production
    python -m experiments.e2_replay --depths 1 2 4 6 --n 5 --out results/e2.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from corpus.generate import CORPUS_DIR, load_corpus  # noqa: E402
from experiments.e2_chains import build_chain  # noqa: E402
from presidio_x402._types import PaymentDetails  # noqa: E402
from presidio_x402.audit_log import AuditLog, NullAuditWriter  # noqa: E402
from presidio_x402.capability_enforcer import CapabilityEnforcer, StageTiming  # noqa: E402
from presidio_x402.core import ScreeningPipeline  # noqa: E402
from presidio_x402.decision_ref import (  # noqa: E402
    DecisionRefEmitter,
    NullDecisionRefWriter,
)
from presidio_x402.pii_filter import PIIFilter  # noqa: E402
from presidio_x402.policy_engine import PolicyEngine  # noqa: E402
from presidio_x402.replay_guard import ReplayGuard  # noqa: E402

DEFAULT_DEPTHS = (1, 2, 4, 6)
_STAGES = ("redaction", "capability_verify", "evidence_write", "added_total")
_STUB_PAY_TO = "0x" + "ab" * 20
_SIGNER_KEY = "11" * 32  # deterministic Ed25519 hex; sandbox-only, not a real key


def _percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    idx = (p / 100) * (len(s) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (idx - lo) * (s[hi] - s[lo])


def _synth_amount(index: int, cap: float) -> str:
    """A small, deterministic per-sample amount strictly below the effective cap."""
    # 0.001 .. min(0.03, cap*0.5) — always admitted by the latency chains.
    ceiling = min(0.03, cap * 0.5)
    val = 0.001 + (index % 30) * (ceiling - 0.001) / 30.0
    return f"{val:.4f}"


def _details(sample, index: int, cap: float) -> PaymentDetails:
    # deadline_seconds is unique per sample so the replay fingerprint is unique and
    # the replay gate never false-blocks a distinct corpus payment.
    return PaymentDetails(
        resource_url=sample.resource_url,
        pay_to=_STUB_PAY_TO,
        amount=_synth_amount(index, cap),
        currency="USDC",
        network="base-sepolia",
        deadline_seconds=300 + index,
        description=sample.description,
        reason=sample.reason,
    )


@dataclass
class DepthResult:
    depth: int
    n: int
    per_stage: dict[str, dict[str, float]]


def _build_pipeline(chain, trust, pii_mode: str, mode: str) -> ScreeningPipeline:
    emitter = DecisionRefEmitter(
        signing_key=_SIGNER_KEY,
        signer="e2-policy-signer",
        writer=NullDecisionRefWriter(),  # measure build+sign cost, no disk I/O
    )
    # per-call mode: verify the PRESENTED chain against the trust store on every
    # payment (verify_chain scales with depth — the E1/E2 verification-vs-depth
    # curve). configured mode: chain verified once at wiring, per-call is only the
    # O(1) check_payment (a verify-once / cached comparison point).
    if mode == "trust-store":
        enforcer = CapabilityEnforcer(trust_store=trust, emitter=emitter, agent_id=chain.subject)
    else:
        enforcer = CapabilityEnforcer(chain=chain, emitter=emitter, agent_id=chain.subject)
    return ScreeningPipeline(
        pii_filter=PIIFilter(mode=pii_mode),
        policy=PolicyEngine(None),  # permissive: no aggregate limit → all allow
        replay=ReplayGuard(ttl=3600),
        audit=AuditLog(NullAuditWriter()),
        pii_action="redact",
        decision_ref_emitter=emitter,
        capability_chain=chain,
        capability_enforcer=enforcer,
        agent_id=chain.subject,
    )


async def _run_depth(
    depth: int, samples: list, *, seed: int, pii_mode: str, mode: str, n_warmup: int
) -> DepthResult:
    chain, trust = build_chain(depth, seed=seed)
    raw_chain = [dict(g.raw) for g in chain.grants]  # presented per call in trust-store mode
    presented = raw_chain if mode == "trust-store" else None
    cap = float(chain.effective.max_per_call_usd or 1.0)
    pipeline = _build_pipeline(chain, trust, pii_mode, mode)

    # Warm-up (discarded): spaCy model load for nlp, regex compile, first-sign.
    for i in range(min(n_warmup, len(samples))):
        s = samples[i % len(samples)]
        await pipeline.apply(
            _details(s, 10_000_000 + i, cap),
            stage_timings=StageTiming(),
            presented_chain=presented,
        )

    acc: dict[str, list[float]] = {k: [] for k in _STAGES}
    for i, s in enumerate(samples):
        t = StageTiming()
        await pipeline.apply(_details(s, i, cap), stage_timings=t, presented_chain=presented)
        red = (t.redaction_ns or 0) / 1e6
        ver = (t.capability_verify_ns or 0) / 1e6
        ev = (t.evidence_write_ns or 0) / 1e6
        acc["redaction"].append(red)
        acc["capability_verify"].append(ver)
        acc["evidence_write"].append(ev)
        acc["added_total"].append(ver + ev)  # added over redaction-only baseline

    per_stage = {
        stage: {
            "p50_ms": round(_percentile(v, 50), 4),
            "p95_ms": round(_percentile(v, 95), 4),
            "p99_ms": round(_percentile(v, 99), 4),
            "mean_ms": round(statistics.mean(v), 4) if v else 0.0,
        }
        for stage, v in acc.items()
    }
    return DepthResult(depth=depth, n=len(samples), per_stage=per_stage)


def _metadata(args, samples_n: int) -> dict:
    return {
        "experiment": "E2",
        "artifact": "presidio-hardened/capability-grant@1 (released) enforced end-to-end",
        "sandbox": not args.production,
        "note": (
            "SANDBOX / reduced-scale run — NOT a paper number"
            if not args.production
            else "production-scale run"
        ),
        "baseline_cited": {
            "redaction_only_p99_ms": 5.73,
            "mode": "nlp",
            "source": "arXiv:2604.11430v2 (cited, not re-derived here)",
        },
        "pii_mode": args.pii_mode,
        "enforce_mode": args.mode,
        "seed": args.seed,
        "n_samples": samples_n,
        "depths": list(args.depths),
        "host": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "zk_tier": "literature-cited only (CJ-EVAL Phase C); NOT measured here",
    }


def main() -> None:
    p = argparse.ArgumentParser(description="E2 corpus-replay latency harness")
    p.add_argument("--depths", type=int, nargs="+", default=list(DEFAULT_DEPTHS))
    p.add_argument("--limit", type=int, default=200, help="reduced-scale sample cap (0 = all)")
    p.add_argument("--n", type=int, default=1, help="warm-up iterations before timing")
    p.add_argument("--pii-mode", choices=["regex", "nlp"], default="regex")
    p.add_argument(
        "--mode",
        choices=["trust-store", "configured"],
        default="trust-store",
        help="trust-store: verify presented chain per call (depth-scaling curve); "
        "configured: verify once, per-call check_payment only (cached comparison)",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--corpus", type=Path, default=CORPUS_DIR / "corpus.jsonl")
    p.add_argument("--out", type=Path, default=Path(__file__).parent / "results" / "e2_replay.csv")
    p.add_argument(
        "--production",
        action="store_true",
        help="clear the sandbox label (use only on the disclosed benchmark host)",
    )
    args = p.parse_args()

    if not args.corpus.exists():
        raise SystemExit(f"corpus not found at {args.corpus} (E2 requires the in-repo corpus)")
    samples = load_corpus(args.corpus)
    if args.limit and args.limit > 0:
        samples = samples[: args.limit]

    meta = _metadata(args, len(samples))
    print(
        f"E2 replay: {meta['note']}  mode={args.pii_mode}  n={len(samples)}  depths={args.depths}"
    )

    results = [
        asyncio.run(
            _run_depth(
                d, samples, seed=args.seed, pii_mode=args.pii_mode, mode=args.mode, n_warmup=args.n
            )
        )
        for d in args.depths
    ]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        # metadata rows (prefixed with '#') so the CSV is self-describing / labelled.
        for k, v in meta.items():
            w.writerow([f"# {k}", json.dumps(v) if isinstance(v, (dict, list)) else v])
        w.writerow(["depth", "n", "stage", "p50_ms", "p95_ms", "p99_ms", "mean_ms"])
        for r in results:
            for stage in _STAGES:
                s = r.per_stage[stage]
                w.writerow(
                    [r.depth, r.n, stage, s["p50_ms"], s["p95_ms"], s["p99_ms"], s["mean_ms"]]
                )

    print(f"\nwrote {args.out}")
    print(f"{'depth':>5} {'verify p50/p99':>18} {'evidence p50/p99':>18} {'added p99':>10}")
    for r in results:
        v = r.per_stage["capability_verify"]
        e = r.per_stage["evidence_write"]
        a = r.per_stage["added_total"]
        print(
            f"{r.depth:>5} {v['p50_ms']:>8.3f}/{v['p99_ms']:<8.3f} "
            f"{e['p50_ms']:>8.3f}/{e['p99_ms']:<8.3f} {a['p99_ms']:>10.3f}"
        )


if __name__ == "__main__":
    main()
