# Treasury-binding conformance vectors

The **normative cross-language contract** for the treasury binding. x402 is
Python, the ledger it binds to is Rust, and there is no `import` across that
boundary in either direction. The contract is the *bytes* — so the binding's
correctness rests on these vectors, not on any shared code.

```
tools/tests/conformance/treasury-binding/     ← authored here
  vectors/canonical-bytes.json                  the shared canonical-JSON profile
  vectors/settlement-ref.json                   the signed join record, golden + rejects
  vectors/decision-ref-negatives.json           the two family negatives
  PROVENANCE.json                               per-file sha256 (drift detection)
  build_vectors.py                              deterministic generator
```

Python side: `tests/conformance/test_treasury_binding_vectors.py` (in CI).
Rust side: a companion test in the ledger repository over these same files —
**not yet landed**. Until it does, "green on both sides" is half-proven, and
nothing in this repository claims otherwise.

## What each file pins

**`canonical-bytes.json`** — the strict profile: sorted keys, `(",", ":")`
separators, UTF-8, `ensure_ascii=False`, floats and non-string keys rejected.
Every accept case carries `canonical_hex`, a hex dump of the expected bytes, so
no whitespace or escaping question is left to interpretation.

Cases are one of three kinds, because not every input can be written as JSON:

| kind | why | example |
|---|---|---|
| `inline` | a literal payload | the ASCII baseline |
| `raw-json` | the exact source text matters | a lone surrogate is legal JSON text with no valid UTF-8 encoding |
| `construct` | a recipe | a 129-deep literal is unreadable; a non-string-keyed object cannot be written as JSON at all |

**The depth definition is pinned in the file and must be read before grading
the boundary cases.** The top-level value is at depth 0; every step into a
nested container adds 1; depth 128 is accepted and depth 129 is rejected. An
off-by-one in the *definition* grades the two boundary vectors in opposite
directions, which looks exactly like a canonicaliser bug and is not one.

**`settlement-ref.json`** — the `settlement-ref@1` join record: canonical bytes,
content hash, signing message, detached signature under the pinned test key, and
the `settlement_key` a ledger enforces uniqueness on. Plus the schema rejections
that keep "both sides accept, or both reject" true: integers past `i64::MAX`,
negative and boolean indices, floats, a rail nickname where a CAIP-2 chain id
belongs, a malformed transaction hash, and the incomplete-facts case an operator
hits when they skip the chain lookup.

**`decision-ref-negatives.json`** — the two family negatives as complete signed
envelopes. Both are cryptographically valid; both must still be rejected. A
verifier that checks only the signature admits both, which is the entire point
of shipping them:

- `decision-signer-equals-runtime` — the signer resolves to the actor's own
  payment wallet. Self-approval is not a second opinion.
- `decision-verdict-not-recomputable` — the recorded verdict is not
  `f(controls)`. Signed over the tampered content, so hash and signature both
  check out; only recomputation catches it.

## The axes, and what is actually at risk on each

| axis | risk | status |
|---|---|---|
| non-ASCII escaping | the two encoders escape differently and hashes diverge on any record with an emoji, an accent, or a control character | **highest attention.** Both are believed to pass non-ASCII through raw and to use `\b \f \n \r \t` + `\u00xx`; pinned here so it is proven, not assumed |
| key ordering on non-ASCII keys | assumed divergent in an earlier draft; it is not | UTF-8 byte-lexicographic order **is** code-point order, by construction. Pinned so a future toolchain change cannot break the equality silently |
| lone surrogates | one side crashes where the other refuses | both reject, at *different layers* — Rust cannot parse it into a `String`, Python parses it and cannot encode it. The contract is that both reject with a typed error, not that both reject in the same place |
| non-string object keys | `json.dumps` sorts integer keys numerically (1, 2, 10) and only then stringifies; every sibling sorts the strings (`"1"`, `"10"`, `"2"`) | a **producer-side** guard: unreachable from JSON text, so Rust satisfies it trivially and Python must enforce it explicitly |
| integers past `i64`/`u64` | representable in Python, not in Rust | schema-bounded on `block_number`/`log_index` to `[0, i64::MAX]` — the only integers a sibling ever canonicalises here |
| floats | not portable across encoders | both reject |
| depth | Rust caps at 128; Python's canonicaliser has no cap | the bound is enforced on the export path, the only path a sibling consumes |

## Regenerating

```bash
python tests/conformance/treasury-binding/build_vectors.py
```

Deterministic: every timestamp is pinned, so an unchanged generator reproduces
byte-identical files. A `PROVENANCE.json` hash that moves without a generator
change means a vector was hand-edited — investigate before trusting any
conformance result, on either side.

## Companion (out of this repository's control)

The ledger side vendors these files and adds a test asserting that its own
`canonical_bytes` + `sha256` reproduce every `content_hash`, that its Ed25519
verify accepts every pinned signature, and that the hard cases are accepted or
rejected identically. That test is authored there, tracked as part of the
inbound-evidence companion change, and is what turns this half-proof into the
byte-interop guarantee the binding rests on.
