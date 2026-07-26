# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Regenerate the treasury-binding cross-language conformance vectors.

Run from this directory::

    python build_vectors.py

Deterministic by construction — every timestamp is pinned, so a re-run of an
unchanged generator reproduces byte-identical files and ``PROVENANCE.json``
hashes. A hash that moves without a generator change means a vector was edited
in place; investigate before trusting any conformance result.

These vectors are the **normative contract** between this repository's Python
canonicaliser (``presidio_x402.mica``) and the sibling Rust one. They are
authored here and vendored *into* the Rust repository, where an equivalent test
must reproduce every ``sha256`` and accept every pinned signature — see
``README.md``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from presidio_x402.decision_ref import (  # noqa: E402
    ControlResults,
    build_decision_evidence,
    build_payment_decision_content,
    compute_decision_ref,
)
from presidio_x402.mica import canonical_bytes, sha256_hex, sign_evidence  # noqa: E402
from presidio_x402.treasury_binding import (  # noqa: E402
    SettlementFacts,
    build_settlement_evidence,
    build_settlement_ref_content,
)

HERE = Path(__file__).resolve().parent
VECTORS = HERE / "vectors"

#: The family test key (private ``01`` × 32). Public key is pinned in every
#: sibling repository's trust-store vector.
PRIV_HEX = "01" * 32
PUB_HEX = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
SIGNER = "presidio-hardened-x402-policy"
KEY_ID = "presidio-v/presidio-evidence:trust-store:x402-policy-2026q3"

#: Pinned so the generator is deterministic.
ISSUED_AT = "2026-07-26T12:00:00.000Z"
GENERATED_AT = "2026-07-26"
SOURCE_VERSION = "0.10.0"

MAX_DEPTH = 128


def _accept(name: str, payload: object, note: str = "") -> dict:
    encoded = canonical_bytes(payload)
    return {
        "name": name,
        "kind": "inline",
        "payload": payload,
        "expect": "accept",
        "canonical_hex": encoded.hex(),
        "canonical_utf8": encoded.decode("utf-8"),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "note": note,
    }


def _nested(depth: int) -> object:
    """``depth`` nested single-key objects with a string leaf.

    The leaf sits at exactly ``depth`` under the shared depth definition (the
    top-level value is at depth 0; every step into a container adds 1), so
    ``_nested(128)`` is the last accepted shape and ``_nested(129)`` the first
    rejected one. Expressed constructively rather than as a literal so both
    languages build the same shape without a 129-level-deep JSON file.
    """
    node: object = "x"
    for _ in range(depth):
        node = {"a": node}
    return node


def canonical_vectors() -> dict:
    accept = [
        _accept(
            "ascii-baseline",
            {"b": "2", "a": "1"},
            "sorted keys, no spaces — the profile's floor.",
        ),
        _accept(
            "non-ascii-escaping",
            {
                "emoji": "payment 💸 settled",
                "combining": "égalité",
                "precomposed": "égalité",
                "del": "before\u007fafter",
                "c0-control": "line\u0001break",
                "tab-newline": "a\tb\nc\rd\be\ff",
            },
            "THE high-attention axis (R1). Both sides must pass non-ASCII through as raw "
            "UTF-8, use the short forms \\b \\f \\n \\r \\t, and \\u00xx-escape other C0 "
            "controls. U+007F DEL is NOT escaped by either side. NFC and NFD spellings of "
            "the same grapheme are distinct byte sequences and must not fold together.",
        ),
        _accept(
            "non-ascii-keys",
            {"zebra": 1, "écu": 2, "über": 3, "中": 4, "a": 5},
            "Key ordering is proven-equal, not assumed: UTF-8 byte-lexicographic order IS "
            "code-point order by construction, so Python's sort_keys (code point) and a "
            "Rust String sort (UTF-8 bytes) agree. Pinned so a future toolchain change "
            "cannot silently break the equality.",
        ),
        _accept(
            "integer-boundaries",
            {"i64_max": 2**63 - 1, "zero": 0, "one": 1},
            "The largest integer the shared profile admits. Anything above it is "
            "schema-rejected on the settlement-ref (see settlement-ref.json).",
        ),
        _accept(
            "nested-depth-128",
            _nested(MAX_DEPTH),
            "Depth boundary, accepted side. Leaf at depth 128 with the top-level value at "
            "depth 0.",
        ),
    ]
    # The depth-128 case is huge as an inline literal; carry it constructively.
    accept[-1] = {
        "name": "nested-depth-128",
        "kind": "construct",
        "construct": {"op": "nested-object", "key": "a", "leaf": "x", "depth": MAX_DEPTH},
        "expect": "accept",
        "canonical_hex": canonical_bytes(_nested(MAX_DEPTH)).hex(),
        "sha256": sha256_hex(_nested(MAX_DEPTH)),
        "note": accept[-1]["note"],
    }

    reject = [
        {
            "name": "float-anywhere",
            "kind": "inline",
            "payload": {"amount": 0.1},
            "expect": "reject",
            "reject_reason": "float",
            "rejects_at": {"python": "encode", "rust": "encode"},
            "note": "Floats are not portable across encoders; both sides refuse rather "
            "than emit an unverifiable content_hash.",
        },
        {
            "name": "float-nested-in-array",
            "kind": "inline",
            "payload": {"xs": [1, 2, 3.0]},
            "expect": "reject",
            "reject_reason": "float",
            "rejects_at": {"python": "encode", "rust": "encode"},
            "note": "3.0 is a float even though it is integral — the guard is by type.",
        },
        {
            "name": "lone-surrogate",
            "kind": "raw-json",
            "payload_json": '{"k":"\\ud800"}',
            "expect": "reject",
            "reject_reason": "lone-surrogate",
            "rejects_at": {"python": "encode", "rust": "parse"},
            "note": "RFC 8259 permits the escape, so the TEXT is well-formed JSON, but the "
            "value has no UTF-8 encoding. The two sides reject at different layers — Rust "
            "cannot even parse it into a String; Python parses it and fails to encode — so "
            "the contract is that BOTH reject, with a typed error, not that both reject in "
            "the same place. Python raises EvidenceError (never a bare UnicodeEncodeError).",
        },
        {
            "name": "non-string-object-key",
            "kind": "construct",
            "construct": {"op": "int-keyed-object", "keys": [1, 10, 2], "value": "v"},
            "expect": "reject",
            "reject_reason": "non-string-key",
            "rejects_at": {"python": "encode", "rust": "unrepresentable"},
            "note": "Unreachable from JSON text — JSON has no non-string keys — so this is "
            "a PRODUCER-side guard, not a parse-side one. It matters because Python's "
            "json.dumps would sort integer keys numerically (1, 2, 10) and only then "
            "stringify, while every sibling sorts the strings ('1', '10', '2'): a silent "
            "hash divergence. Rust cannot construct the input at all, so 'both reject' "
            "holds trivially on that side.",
        },
        {
            "name": "nested-depth-129",
            "kind": "construct",
            "construct": {"op": "nested-object", "key": "a", "leaf": "x", "depth": MAX_DEPTH + 1},
            "expect": "reject",
            "reject_reason": "too-deep",
            "rejects_at": {"python": "bound", "rust": "encode"},
            "note": "Depth boundary, rejected side. Python's canonicaliser itself has no "
            "depth cap (the interpreter's recursion limit is not a contract), so the bound "
            "is enforced by treasury_binding.check_canonical_depth on the export path — "
            "which is the only path whose output a sibling canonicaliser ever sees.",
        },
    ]
    return {
        "description": (
            "Cross-language canonical-JSON contract for the treasury binding. Profile: "
            'sorted keys, (",", ":") separators, UTF-8, ensure_ascii=False, floats and '
            "non-string keys rejected. 'canonical_hex' is the hex dump of the expected "
            "bytes so no whitespace or escaping question is left to interpretation."
        ),
        "depth_definition": (
            "The top-level value is at depth 0; every step into a nested object or array "
            "adds 1. A value at depth 128 is accepted; a value at depth 129 is rejected. "
            "Pin this definition before grading the boundary vectors — an off-by-one in "
            "the definition grades the two cases in opposite directions."
        ),
        "generated_at": GENERATED_AT,
        "accept": accept,
        "reject": reject,
    }


def _decision_envelope(*, verdict_override: str | None = None, self_signed: bool = False) -> dict:
    controls = ControlResults(
        pii_verdict="PII_REDACTED",
        pii_entities=("EMAIL_ADDRESS",),
        pii_mutated=True,
        trusted_wallet_verdict="TRUSTED",
        policy_verdict="ALLOW",
        policy_snapshot_hash="sha256:" + "11" * 32,
        replay_verdict="FRESH",
        replay_fingerprint_hash="sha256:" + "22" * 32,
        mpa_verdict="NOT_REQUIRED",
        mpa_required=False,
    )
    pay_to = "0x00000000000000000000000000000000c0ffee00"
    content = build_payment_decision_content(
        agent_id="did:presidio:x402:conformance-agent",
        payment_signer=pay_to,
        network="base-sepolia",
        binding="x402",
        offer_hash="sha256:" + "33" * 32,
        details_hash="sha256:" + "44" * 32,
        pay_to=pay_to,
        amount="0.010000",
        currency="USDC",
        resource_origin="https://conformance.invalid",
        controls=controls,
        issued_at=ISSUED_AT,
    )
    signer = pay_to if self_signed else SIGNER
    if verdict_override is None:
        envelope = build_decision_evidence(
            content,
            signing_key=PRIV_HEX,
            signer=signer,
            key_id=KEY_ID,
            source_version=SOURCE_VERSION,
        )
        envelope["generated_at"] = ISSUED_AT
        envelope["evidence"][0]["claimed_at"] = ISSUED_AT
        return envelope

    # A non-recomputable verdict cannot be produced by the emitter (it refuses to
    # sign one), so the negative is assembled by hand and signed over the
    # tampered content — exactly what an attacker would have to do.
    content["verdict"] = verdict_override
    a_hash = sha256_hex(content)
    d_ref = compute_decision_ref(
        artifact_hash=a_hash,
        policy_version=str(content["policy_version"]),
        verdict=verdict_override,
    )
    return {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "x402-payment-decision",
        "source": signer,
        "source_version": SOURCE_VERSION,
        "generated_at": ISSUED_AT,
        "attested_content": {"schema": content["schema"]},
        "evidence": [
            {
                "item_id": d_ref,
                "source": signer,
                "source_version": SOURCE_VERSION,
                "ledger_ref": f"x402-decision:{d_ref}",
                "content_hash": a_hash,
                "signer": signer,
                "signature": sign_evidence(a_hash, signer, key=PRIV_HEX),
                "claimed_at": ISSUED_AT,
                "key_id": KEY_ID,
            }
        ],
        "signing_algorithm": "ed25519",
        "payment_decision": content,
        "artifact_hash": a_hash,
        "decision_ref": d_ref,
        "key_id": KEY_ID,
    }


def decision_negative_vectors() -> dict:
    baseline = _decision_envelope()
    self_signed = _decision_envelope(self_signed=True)
    not_recomputable = _decision_envelope(verdict_override="ALLOW")
    # Force the mismatch: DENY the payment in controls while the record says ALLOW.
    not_recomputable["payment_decision"]["controls"]["policy"]["verdict"] = "VIOLATION"
    a_hash = sha256_hex(not_recomputable["payment_decision"])
    d_ref = compute_decision_ref(
        artifact_hash=a_hash,
        policy_version=str(not_recomputable["payment_decision"]["policy_version"]),
        verdict="ALLOW",
    )
    not_recomputable["artifact_hash"] = a_hash
    not_recomputable["decision_ref"] = d_ref
    ref = not_recomputable["evidence"][0]
    ref["content_hash"] = a_hash
    ref["item_id"] = d_ref
    ref["ledger_ref"] = f"x402-decision:{d_ref}"
    ref["signature"] = sign_evidence(a_hash, SIGNER, key=PRIV_HEX)

    return {
        "description": (
            "The two family negatives, as complete signed envelopes. Both are "
            "cryptographically valid — the signature verifies — and both MUST still be "
            "rejected. A content type proves its worth by what it rejects: a verifier that "
            "checks only the signature admits both of these."
        ),
        "generated_at": GENERATED_AT,
        "trust_store": {SIGNER: {"alg": "ed25519", "public_key": PUB_HEX}},
        "vectors": [
            {
                "id": "treasury-decision-baseline",
                "expect": "accept",
                "envelope": baseline,
                "note": "Signed by a policy identity distinct from the payment wallet; "
                "verdict recomputes from controls.",
            },
            {
                "id": "decision-signer-equals-runtime",
                "expect": "reject",
                "failure_mode": "signer_equals_runtime",
                "envelope": self_signed,
                "trust_store_override": {
                    "0x00000000000000000000000000000000c0ffee00": {
                        "alg": "ed25519",
                        "public_key": PUB_HEX,
                    }
                },
                "note": "The signer resolves to the actor's own payment wallet. The "
                "signature verifies and the verdict recomputes; admission is what fails. "
                "Self-approval is not a second opinion.",
            },
            {
                "id": "decision-verdict-not-recomputable",
                "expect": "reject",
                "failure_mode": "verdict_not_recomputable",
                "envelope": not_recomputable,
                "note": "controls.policy.verdict = VIOLATION, so f(controls) = DENY, while "
                "the record claims ALLOW. Signed over the tampered content, so the hash and "
                "the signature both check out — only recomputation catches it.",
            },
        ],
    }


def settlement_vectors() -> dict:
    decision_ref = _decision_envelope()["decision_ref"]
    facts = SettlementFacts(
        chain="eip155:84532",
        tx_hash="0x" + "ab" * 32,
        block_number=19_284_411,
        log_index=7,
    )
    content = build_settlement_ref_content(
        decision_ref=decision_ref, facts=facts, issued_at=ISSUED_AT
    )
    envelope = build_settlement_evidence(
        content,
        signing_key=PRIV_HEX,
        signer=SIGNER,
        key_id=KEY_ID,
        source_version=SOURCE_VERSION,
    )
    envelope["generated_at"] = ISSUED_AT
    envelope["evidence"][0]["claimed_at"] = ISSUED_AT
    encoded = canonical_bytes(content)

    return {
        "description": (
            "The settlement-ref@1 join record: a signed, off-chain statement that one "
            "decision authorized one settlement. Commits to five values and nothing else — "
            "no calldata digest and no precedence timestamp, both of which are "
            "unsatisfiable over an ERC-3009 settlement, and no payer address, which the "
            "join does not need."
        ),
        "generated_at": GENERATED_AT,
        "schema_id": content["schema"],
        "trust_store": {SIGNER: {"alg": "ed25519", "public_key": PUB_HEX}},
        "golden": {
            "content": content,
            "canonical_hex": encoded.hex(),
            "canonical_utf8": encoded.decode("utf-8"),
            "content_hash": hashlib.sha256(encoded).hexdigest(),
            "settlement_key": facts.settlement_key,
            "signing_message_canonical": canonical_bytes(
                {"content_hash": hashlib.sha256(encoded).hexdigest(), "signer": SIGNER}
            ).decode("utf-8"),
            "signature_hex": envelope["evidence"][0]["signature"],
            "public_key_hex": PUB_HEX,
            "envelope": envelope,
        },
        "settlement_key_definition": (
            "chain|tx_hash|log_index, '|' separated. This is the uniqueness key a "
            "downstream ledger enforces 'at most one settlement-ref per (period, key)' on. "
            "block_number is deliberately excluded: it is implied by the transaction hash, "
            "and including it would let a wrong-but-plausible height mint a second distinct "
            "key for one settlement."
        ),
        "reject": [
            {
                "name": "block-number-above-i64-max",
                "settlement": {
                    "chain": "eip155:84532",
                    "tx_hash": "0x" + "ab" * 32,
                    "block_number": 2**63,
                    "log_index": 0,
                },
                "reject_reason": "integer-out-of-range",
                "note": "Representable in Python, not in an i64. Bounded by schema so both "
                "sides reject rather than one accepting silently.",
            },
            {
                "name": "log-index-above-u64-max",
                "settlement": {
                    "chain": "eip155:84532",
                    "tx_hash": "0x" + "ab" * 32,
                    "block_number": 1,
                    "log_index": 2**64,
                },
                "reject_reason": "integer-out-of-range",
                "note": "Above u64::MAX as well as i64::MAX — rejected by the same bound.",
            },
            {
                "name": "negative-block-number",
                "settlement": {
                    "chain": "eip155:84532",
                    "tx_hash": "0x" + "ab" * 32,
                    "block_number": -1,
                    "log_index": 0,
                },
                "reject_reason": "integer-out-of-range",
                "note": "A block height is unsigned.",
            },
            {
                "name": "float-log-index",
                "settlement": {
                    "chain": "eip155:84532",
                    "tx_hash": "0x" + "ab" * 32,
                    "block_number": 1,
                    "log_index": 7.0,
                },
                "reject_reason": "float",
                "note": "Refused rather than truncated to 7.",
            },
            {
                "name": "boolean-log-index",
                "settlement": {
                    "chain": "eip155:84532",
                    "tx_hash": "0x" + "ab" * 32,
                    "block_number": 1,
                    "log_index": True,
                },
                "reject_reason": "integer-out-of-range",
                "note": "bool is an int subclass in Python; True is not a log index.",
            },
            {
                "name": "chain-not-caip2",
                "settlement": {
                    "chain": "base-sepolia",
                    "tx_hash": "0x" + "ab" * 32,
                    "block_number": 1,
                    "log_index": 0,
                },
                "reject_reason": "chain-not-caip2",
                "note": "A rail nickname is not a chain id. The mapping happens at capture "
                "time; the committed value is always CAIP-2.",
            },
            {
                "name": "tx-hash-not-evm",
                "settlement": {
                    "chain": "eip155:84532",
                    "tx_hash": "0xdeadbeef",
                    "block_number": 1,
                    "log_index": 0,
                },
                "reject_reason": "tx-hash-malformed",
                "note": "eip155 transaction hashes are 0x + 64 hex.",
            },
            {
                "name": "missing-log-index",
                "settlement": {
                    "chain": "eip155:84532",
                    "tx_hash": "0x" + "ab" * 32,
                    "block_number": 1,
                },
                "reject_reason": "incomplete",
                "note": "The settlement echo does not carry a log index, so an operator who "
                "skips the chain lookup lands here. Required, not optional: without it "
                "there is no key for the one-settlement-one-leg invariant.",
            },
        ],
        "normalisation": [
            {
                "name": "evm-tx-hash-case",
                "input": "0x" + "AB" * 32,
                "chain": "eip155:84532",
                "canonical": "0x" + "ab" * 32,
                "note": "Case is normalised, not merely accepted, so two operators "
                "exporting the same settlement produce byte-identical join records.",
            }
        ],
    }


def main() -> int:
    VECTORS.mkdir(parents=True, exist_ok=True)
    files = {
        "canonical-bytes.json": canonical_vectors(),
        "settlement-ref.json": settlement_vectors(),
        "decision-ref-negatives.json": decision_negative_vectors(),
    }
    for name, payload in files.items():
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        (VECTORS / name).write_text(text, encoding="utf-8")

    provenance = {
        "source_repo": "presidio-hardened-x402",
        "generator": "tests/conformance/treasury-binding/build_vectors.py",
        "generated_at": GENERATED_AT,
        "schema_ids": [
            "presidio-hardened/evidence-ref@1",
            "presidio-hardened-x402/payment-decision@1",
            "presidio-hardened-x402/settlement-ref@1",
        ],
        "test_key": {"private_key_hex": PRIV_HEX, "public_key_hex": PUB_HEX, "signer": SIGNER},
        "note": (
            "Authored here (not vendored) and vendored INTO the sibling Rust repository, "
            "where an equivalent test must reproduce every sha256 and accept every pinned "
            "signature. Regenerate with build_vectors.py; a hash that moves without a "
            "generator change means a vector was edited in place."
        ),
        "files": {
            name: hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() for name in files
        },
    }
    (HERE / "PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(files)} vector files + PROVENANCE.json to {HERE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
