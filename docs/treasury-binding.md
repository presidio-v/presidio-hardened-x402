# Treasury binding — bundle shape and ingest contract

How one x402 payment becomes something a ledger can reconcile into an
audit-grade close: the signed record of *why* the payment was allowed, joined to
the on-chain settlement that moved the money, both verifiable offline against a
pinned trust store.

Introduced in v0.10.0. The producing side is entirely in this repository; the
consuming side is a companion change in the ledger repository and is **not
merged yet**, so a bundle is marked `"ingest_status": "treasury-ingest-pending"`
until that surface is agreed.

## The two artifacts and the join

```
payment-decision@1   (v0.9.0)    "the library concluded ALLOW under predicate P"
        │  decision_ref
        ▼
settlement-ref@1     (v0.10.0)   "that decision authorized THIS settlement"
        │  chain + tx_hash + block_number + log_index
        ▼
the L1 chain observation the ledger ingests independently
```

`settlement-ref@1` commits to exactly five values:

```json
{
  "schema": "presidio-hardened-x402/settlement-ref@1",
  "issued_at": "2026-07-26T12:00:00.000Z",
  "decision_ref": "<64 hex>",
  "settlement": {
    "block_number": 19284411,
    "chain": "eip155:84532",
    "log_index": 7,
    "tx_hash": "0x…"
  }
}
```

…signed into the family `presidio-hardened/evidence-ref@1` envelope with the
same primitives as the decision-ref, so one verifier handles both.

### What the join is not

It is **not** an on-chain anchor. An x402 payment settles via ERC-3009
`transferWithAuthorization`, whose calldata carries no decision digest — there is
nothing on chain to check a `calldata_digest` against. And if the committed
`tx_hash` *is* the settlement, a "decision precedes settlement" timestamp check
compares a value with itself. Rather than ship two fields that assert what they
cannot prove, the record asserts only what the signer can: *this decision, that
transaction, signed*. The auditor already trusts that signer for the decision;
the join rides the same trust, and being signed is what lets a consumer reject a
forged or swapped join at its boundary.

The strictly stronger alternative — a pre-settlement commitment transaction
carrying `sha256(decision_ref)`, making the join on-chain rather than
signer-asserted — costs an extra chain transaction on every payment and changes
the settle path. It is deferred as an opt-in "strong anchor" mode, not
abandoned.

## Bundle shape

```json
{
  "schema": "presidio-hardened-x402/treasury-bundle@1",
  "generated_at": "…", "source_version": "0.10.0",
  "decision_ref": "<64 hex>", "settlement_ref": "<64 hex>",
  "settlement_key": "eip155:84532|0x…|7",
  "verdict": "ALLOW",
  "decision_ref_envelope": { "…evidence-ref@1…" },
  "settlement_ref_envelope": { "…evidence-ref@1…" },
  "trust_store_ref": { "signer": "presidio-hardened-x402-policy",
                       "algorithm": "ed25519", "key_id": "…" },
  "ingest_status": "treasury-ingest-pending"
}
```

**No key material travels in the bundle, by design.** `trust_store_ref` *names*
the signer and key id; it never carries the public key. A bundle-supplied key
would make verification trust-on-first-use and defeat the pin it exists to
enforce. The consumer resolves the signer against its own store or rejects.

`settlement_key` is `chain|tx_hash|log_index`. It is the value a ledger enforces
"at most one settlement-ref per (period, key)" on — the uniqueness invariant
that stops one settled payment from being counted into two closes.
`block_number` is deliberately *not* part of the key: it is implied by the
transaction hash, and including it would let a wrong-but-plausible height mint a
second distinct key for one settlement.

**The uniqueness invariant is the consumer's to enforce, and the key is only as
trustworthy as `log_index`.** x402 does not — and cannot — enforce
one-settlement-one-leg: that check lives in the treasury ledger
(`presidio-hardened-treasury#49`, still pending, hence `treasury-ingest-pending`).
And `log_index` is an *operator-supplied* fact — the on-wire settlement receipt
carries only the transaction hash and network, not the log index — so a producer
who is themselves inside the threat model (the operator, per the plan's L-layer
mapping) can emit two valid bundles for one on-chain settlement under two
different `log_index` values. The signature binds the *decision↔settlement*
assertion; it does **not** attest that `log_index` is the real chain log index.
A consuming ledger must therefore corroborate `log_index` against its own
independent chain observation before treating the key as unique — never on the
bundle's word alone. (Threat T-TB-2.)

## Producing a bundle

### 1. Capture the settlement facts

```python
from presidio_x402 import FileSettlementWriter, HardenedX402Client
from presidio_x402.decision_ref import DecisionRefEmitter

client = HardenedX402Client(
    payment_signer=my_signer,
    decision_ref_emitter=DecisionRefEmitter(signing_key=policy_key),
    settlement_writer=FileSettlementWriter("settlements.jsonl"),
)
```

The client parses the settlement echo (`PAYMENT-RESPONSE`,
`X-PAYMENT-RESPONSE`, or `X-PAYMENT-RECEIPT`) on the paid response and writes one
`settlement-facts@1` record per payment, correlated with that payment's
`decision_ref`. Capture is strictly observational: it runs after the paid
response is in hand, performs no network I/O, and cannot change a payment
outcome.

**The echo carries the transaction hash and the network — not a block number and
not a log index.** Those two fields come back `null`, and the record says
`"complete": false`. Completing them is an operator step:

```bash
# look the transaction up on the chain / your indexer, then fill in:
#   "block_number": 19284411,
#   "log_index": 7
```

They are required rather than optional because without a log index there is no
key on which the ledger can enforce one-settlement-one-leg.

### 2. Export

```bash
python -m presidio_x402.treasury_binding export decision.json \
    --settlement settle.json --trust trust.json --key-file policy.key > bundle.json
```

The signing key is read from `--key-file` or `PRESIDIO_X402_EVIDENCE_KEY`, never
from a command-line argument — a key in `argv` is visible in `ps` output to
every user on the host.

Export **refuses**, with a distinct error each time, when:

| refusal | why |
|---|---|
| the decision-ref does not verify | every layer, signature included. A bundle whose signature was never checked is not evidence of anything — which is why `--trust` is required, not optional |
| the verdict is `REFER` | an unresolved quorum is an interim state; export the terminal decision that supersedes it. `DENY` **is** exportable on purpose: a settlement that happened despite a DENY is the anomaly an auditor most needs to see |
| an identity string is out of bounds | see below |
| the settlement facts are out of domain | non-CAIP-2 chain, malformed transaction hash, index past `i64::MAX`, missing block/log index |
| the join would be signed by another identity | the join is the *decision signer's* assertion. Otherwise any trust-store member could re-point any decision at any transaction |

### 3. Verify (anyone, offline)

```bash
python -m presidio_x402.treasury_binding verify bundle.json trust.json   # exit 0 iff verified
```

Exit 0 verified, 1 fail-closed with a distinct reason, 2 usage error. Layers, in
order, first failure wins: `structure → decision → terminal → identity →
settlement → signer → summary`.

The last layer is worth naming. The bundle's top-level `decision_ref`,
`settlement_ref`, `settlement_key` and `verdict` are a convenience mirror of what
the envelopes already prove, and verification never *reads* them — every value it
reports is re-derived. But a consumer enforcing uniqueness reads
`settlement_key`, so a mirror that can disagree with what it mirrors is a trap:
swap in a settlement-ref for a different transaction and the stale key still
names the old one. Disagreement is therefore a rejection, not a warning.

## Privacy bound, stated honestly

The `controls{}` block of a decision-ref is *structurally* PII-free: every value
is a hash, an entity-type label, an enum verdict, or a boolean, and there is no
field that accepts a raw string.

The top-level identity fields are **not**. `agent_id`, `pay_to`,
`resource_origin` and `mpa.approval_refs` are caller-supplied strings, and a
wallet address is pseudonymous personal data to a GDPR-minded auditor. They are
present by design — a ledger cannot reconcile an anonymous payment — so the
mitigation is a **value bound**, not a claim that no free text can appear:

- length: `agent_id` ≤ 256, `pay_to` ≤ 128, `resource_origin` ≤ 256,
  `approval_refs` ≤ 32 entries of ≤ 512 characters;
- charset: no control, format, surrogate, private-use or unassigned code point.
  A Cyrillic or CJK agent id is legitimate; a bidi override in an auditor's
  disclosure pack is not.

The bound is applied on **both** paths — a bundle from an older or laxer
producer still fails on read. The settlement facts deliberately exclude the payer
address even though the receipt carries it: the join needs the transaction, not
the counterparty.

## Ingest contract (for the consuming side)

1. **Verify before storing.** Resolve `trust_store_ref.signer` against your own
   pinned store, deny by default on an unknown signer. Nothing enters an evidence
   store before its signature verifies.
2. **Run the full decision semantics, not just the signature.** Recompute
   `verdict == f(controls)` and re-apply the admission check (`signer` must not be
   one of the actor's controllers). A signature-only verifier admits both of the
   negatives shipped in the conformance vectors.
3. **Enforce uniqueness on `settlement_key`.** At most one settlement-ref per
   (period, key). Content-addressed storage does *not* give you this for free —
   two refs differing only in `issued_at` are distinct blobs.
4. **Treat the decision-ref as classification evidence feeding dual control,
   never as a control in its own right.** It proves what the library concluded
   under a *declared* predicate; it cannot prove the predicate was the real one,
   and it cannot manufacture a settlement that did not happen. The chain
   observation is independent evidence and the classification remains the
   consumer's own judgment.
5. **Bound the inbound volume.** Valid-but-irrelevant bundles are an
   availability problem: evidence should be pulled for a settlement leg already
   being classified, not pushed into a close.

## Residual risks

- **Stolen signer key.** Signature verification does not cover it. Mitigation is
  operational: `key_id` pinning with a revocation path, short signer epochs, and
  the fact that a full-semantics consumer still requires an independent L1
  settlement to corroborate amount and counterparty.
- **Cryptographically valid, semantically false verdict.** A record whose
  `controls` were fabricated signs and recomputes correctly. This is the honesty
  bound of the whole scheme; containment, not elimination, is the answer — see
  ingest contract point 4.

## See also

- `tests/conformance/treasury-binding/README.md` — the cross-language vector set
  and what each axis is actually at risk of.
- `presidio_x402.decision_ref` — the `payment-decision@1` producer/verifier this
  builds on.
