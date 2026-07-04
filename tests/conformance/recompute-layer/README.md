# recompute-layer — `recompute_mismatch`

Integrity is not derivation. A decision record can be intact, correctly signed, and
schema-valid, and its recorded verdict can still fail to re-derive from its own controls.
That failure needs its own name and its own check; this directory is both.

## The four layers

The boundaries are load-bearing, and people collapse them:

- **integrity** — the record was preserved (hash/digest, schema);
- **signature** — who signed it (admission: is the signer entitled to decide?);
- **recompute** — the verdict follows from the *declared* controls — **this layer**;
- **attestation** — the declared controls are the *real* controls (separate, not here).

A record that fails the recompute layer is flagged under `recompute_mismatch`. The name
was proposed and agreed on [x402-foundation/x402#2332](https://github.com/x402-foundation/x402/issues/2332)
(babyblueviper1, Tuttotorna, vstantch, 2026-07-04): it is the honest name because nothing
was tampered with — the decision simply does not follow from its own controls.

`recompute_mismatch` is **additive, never an override**: an integrity/signature check can
say the receipt is intact and correctly signed while recompute says the decision does not
re-derive, and both stand on their own.

## The concrete instance: `verdict = f(controls)`

`f` is the pure precedence-combinator over the five recorded control verdicts
(`[pii, trusted_wallet, policy, replay, mpa]`, first-failure-wins, MPA timeout → REFER)
already pinned by the [`decision-ref`](../decision-ref/) fixture. `recompute_check.py`
runs it over that fixture and **discriminates across layers**:

| decision-ref vector | recompute | why |
|---|---|---|
| `presidio-x402-decision-001` | AGREES | clean controls, `f=ALLOW=recorded` |
| `presidio-x402-decision-signer-equals-runtime` | AGREES | its failure is **admission** (signer is the actor's wallet) — a *different* layer; recompute correctly does not flag it |
| `presidio-x402-decision-verdict-not-recomputable` | `recompute_mismatch` | recorded `ALLOW`, but `policy.verdict=VIOLATION` ⇒ `f=DENY` |

That the admission negative is *not* flagged here is the point: recompute is one layer, not
all of them.

Run it:

```
python3 tests/conformance/recompute-layer/recompute_check.py   # exits 0; discriminates
python3 -m pytest tests/test_recompute_layer.py -q             # CI coverage
```

## Scope — what this proves and does not

- **Does** prove: given the recorded controls, the recorded verdict does not equal
  `f(controls)`. The signed decision does not re-derive from its own inputs.
- **Does not** prove: that the controls themselves are truthful. A recorder who lies about
  `policy.verdict` gets a clean recompute over a false premise — an *attestation* failure,
  not a recompute one. Recompute checks derivation, not honesty.

## Provenance

Proposed as a layer for the APS accountability-record suite
([aeoess/aps-conformance-suite#9](https://github.com/aeoess/aps-conformance-suite/pull/9),
cold-clone-graded clean twice by babyblueviper1, placement endorsed by Tuttotorna). APS
declined new failure-class vocabulary on 2026-07-04 pending a written contribution policy,
so the layer is homed here beside its concrete instance — the `decision-ref` fixture — where
it is CI-covered. The APS-shaped record and cross-language verifier remain on the closed PR
branch for reference.
