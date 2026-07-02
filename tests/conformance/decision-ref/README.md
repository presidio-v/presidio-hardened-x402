# x402 payment-decision-ref conformance fixture

`decision_ref` for x402 payment decisions, aligned with the agent-governance
decision-provenance contract that autogen#7353 and crewAI#4877 converged on
(reference: `babyblueviper1/preaction-governance-conformance`):

```
artifact_hash = sha256(JCS(payment-decision@1 content))
decision_ref  = sha256(JCS({artifact_hash, artifact_type, policy_version, verdict}))
```

The rich payment-decision content is the *artifact*; `decision_ref` is the thin,
self-describing-preimage id over it (sibling to `action_ref`). x402's depth over the
generic shape: `verdict = f(controls)` — a pure precedence-combinator over the five
recorded control verdicts (`pii → trusted_wallet → policy → replay → mpa`,
first-failure-wins; MPA timeout → `REFER`). The verdict is *recomputable*, not asserted.

Leads with the two fail-closed negatives:

- `signer_equals_runtime` — the verdict signer resolves to the actor's own wallet
  (self-approval is not a second opinion).
- `verdict_not_recomputable` — the recorded verdict ≠ `f(controls)`.

The third negative we offered (details-hash over unredacted fields) is already
`presidio-x402-002` / `PII_BLOCKED` in the action-ref fixture.

Validate offline (zero-dependency, the same grading `@babyblueviper1` runs on landed
vectors):

```
pytest tests/test_decision_ref_conformance.py
```

Regenerate the fixture: `python build_fixture.py`.

**Destination:** contributed upstream to `giskard09/argentum-core`
`examples/conformance/presidio/`, where `presidio-x402-001/002/003` (our action-ref /
screen-ref vectors) already live.
