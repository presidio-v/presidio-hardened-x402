"""Generate + self-validate the x402 payment-decision-ref conformance fixture.

Drops into giskard09/argentum-core examples/conformance/presidio/ (same shape as
action-ref-v1.fixture.json) and babyblueviper1's decision-ref-recompute slot:
    decision_ref = sha256(JCS({artifact_hash, artifact_type, policy_version, verdict}))
where artifact_hash = sha256(JCS(payment-decision@1 content)), and verdict = f(controls).
"""

import hashlib
import json
import os

# ruff: noqa: E501  -- fixture generator: long descriptive strings are intentional


def jcs(obj) -> str:
    # RFC 8785 for our string-only payloads: recursive key sort, compact, UTF-8.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --- f: pure precedence-combinator over the five recorded control verdicts ---
def f(controls: dict) -> str:
    if controls["pii"]["verdict"] == "PII_BLOCKED":
        return "DENY"
    if controls["trusted_wallet"]["verdict"] == "UNTRUSTED":
        return "DENY"
    if controls["policy"]["verdict"] == "VIOLATION":
        return "DENY"
    if controls["replay"]["verdict"] == "DUPLICATE":
        return "DENY"
    if controls["mpa"]["verdict"] == "DENIED":
        return "DENY"
    if controls["mpa"]["verdict"] in ("PENDING", "TIMEOUT"):
        return "REFER"
    return "ALLOW"


ARTIFACT_TYPE = "presidio-hardened-x402/payment-decision@1"
POLICY_VERSION = "presidio-x402.policy.v1"


def payment_decision(issued_at, verdict, controls, *, amount="10000"):
    return {
        "schema": ARTIFACT_TYPE,
        "issued_at": issued_at,
        "agent_id": "did:presidio:x402:agent-7f3a9c",
        "actor": {
            "payment_signer": "wallet:evm:0xA11ce00000000000000000000000000000000001",
            "binding": "x402",
            "network": "eip155:8453",
        },
        "payment": {
            "offer_hash": "sha256:" + sha256_hex("offer|" + issued_at),
            "details_hash": "sha256:" + sha256_hex("details|redacted|" + issued_at),
            "pay_to": "0x0273d0b906c9524dB2672318545aaDa1F478B1a1",
            "amount": amount,
            "currency": "USDC",
            "resource_origin": "https://api.merchant.example",
        },
        "controls": controls,
        "verdict": verdict,
    }


def decision_ref_preimage(artifact_hash, verdict):
    return {
        "artifact_hash": artifact_hash,
        "artifact_type": ARTIFACT_TYPE,
        "policy_version": POLICY_VERSION,
        "verdict": verdict,
    }


def build_vector(
    vid, description, *, issued_at, verdict, controls, signer, expect, failure_mode=None
):
    art = payment_decision(issued_at, verdict, controls)
    art_jcs = jcs(art)
    artifact_hash = sha256_hex(art_jcs)
    pre = decision_ref_preimage(artifact_hash, verdict)
    pre_jcs = jcs(pre)
    decision_ref = sha256_hex(pre_jcs)
    vec = {
        "id": vid,
        "description": description,
        "expect": expect,  # "accept" | "reject"
        "artifact": art,
        "artifact_hash": artifact_hash,
        "decision_ref_preimage_fields": [
            "artifact_hash",
            "artifact_type",
            "policy_version",
            "verdict",
        ],
        "decision_ref_preimage": pre,
        "jcs_payload": pre_jcs,
        "preimage_canonical_bytes_hex": pre_jcs.encode("utf-8").hex(),
        "decision_ref": decision_ref,
        # admission: who signed the evidence-ref envelope over this decision
        "signer": signer,  # {"key_id":..., "resolves_to": "policy-issuer" | "actor-runtime"}
        # semantic recompute: f over the recorded control verdicts
        "verdict_recomputed": f(controls),
    }
    if failure_mode:
        vec["failure_mode"] = failure_mode
    return vec


CTRL_ALLOW = {
    "pii": {"verdict": "PII_REDACTED", "entities": ["EMAIL_ADDRESS"], "mutated": True},
    "trusted_wallet": {"verdict": "TRUSTED"},
    "policy": {
        "verdict": "ALLOW",
        "policy_snapshot_hash": "sha256:" + sha256_hex("policy-snap-effective"),
        "limit_hash": "sha256:" + sha256_hex("limit"),
    },
    "replay": {"verdict": "FRESH", "fingerprint_hash": "sha256:" + sha256_hex("fp-1")},
    "mpa": {"verdict": "NOT_REQUIRED", "required": False},
}
# NEG-2: controls say policy VIOLATION (so f -> DENY) but the record claims ALLOW.
CTRL_VIOLATION = json.loads(json.dumps(CTRL_ALLOW))
CTRL_VIOLATION["policy"]["verdict"] = "VIOLATION"

POLICY_ISSUER = {
    "key_id": "presidio-v/presidio-evidence:trust-store:x402-policy-2026q3",
    "resolves_to": "policy-issuer",
}
ACTOR_RUNTIME = {
    "key_id": "wallet:evm:0xA11ce00000000000000000000000000000000001",
    "resolves_to": "actor-runtime",
}

vectors = [
    build_vector(
        "presidio-x402-decision-001",
        "Baseline ALLOW: an x402 payment-decision recorded before signing. PII redacted, "
        "wallet trusted, policy ALLOW, replay FRESH, MPA not required -> f(controls)=ALLOW. "
        "decision_ref recomputes from {artifact_hash, artifact_type, policy_version, verdict}; "
        "signed by a policy issuer distinct from the payment wallet.",
        issued_at="2026-06-30T22:00:00.000Z",
        verdict="ALLOW",
        controls=CTRL_ALLOW,
        signer=POLICY_ISSUER,
        expect="accept",
    ),
    build_vector(
        "presidio-x402-decision-signer-equals-runtime",
        "NEGATIVE (admission): identical decision content to -001, but the evidence-ref "
        "envelope is signed by the actor's own payment wallet. Self-approval is not a second "
        "opinion -> reject. decision_ref still recomputes mechanically; the failure is admission, "
        "not the hash.",
        issued_at="2026-06-30T22:00:00.000Z",
        verdict="ALLOW",
        controls=CTRL_ALLOW,
        signer=ACTOR_RUNTIME,
        expect="reject",
        failure_mode="signer_equals_runtime",
    ),
    build_vector(
        "presidio-x402-decision-verdict-not-recomputable",
        "NEGATIVE (recompute): the record claims verdict=ALLOW, but controls.policy.verdict="
        "VIOLATION, so f(controls)=DENY. A signed verdict that does not re-derive from its "
        "recorded control verdicts is void -> reject. decision_ref hashes fine; verdict != f(controls).",
        issued_at="2026-06-30T22:05:00.000Z",
        verdict="ALLOW",
        controls=CTRL_VIOLATION,
        signer=POLICY_ISSUER,
        expect="reject",
        failure_mode="verdict_not_recomputable",
    ),
]

# --- second block: pshkv's digest / forward-compat axis (x402#2332, autogen#7353) ---
# The first block tests admission + recompute (is a verdict *entitled* to its verdict).
# This block tests the digest axis: is the id sensitive to its own preimage, and does it
# fail closed on the unknown? Property vectors operate at the decision_ref preimage level
# (not standalone signed records); the two fail-closed vectors carry expect="reject".
BASE = vectors[0]
BASE_AH = BASE["artifact_hash"]
BASE_DR = BASE["decision_ref"]
STD_FIELDS = ["artifact_hash", "artifact_type", "policy_version", "verdict"]


def _pre(policy_version, verdict, *, extra=None):
    d = {
        "artifact_hash": BASE_AH,
        "artifact_type": ARTIFACT_TYPE,
        "policy_version": policy_version,
        "verdict": verdict,
    }
    if extra:
        d.update(extra)
    return d


def dfc_property(vid, description, assert_kind, pre, *, unsorted=None):
    pre_jcs = jcs(pre)
    v = {
        "id": vid,
        "axis": "digest",
        "assert": assert_kind,  # "decision_ref_differs" | "decision_ref_equals"
        "relative_to": "presidio-x402-decision-001",
        "note": "preimage-level property vector: exercises decision_ref canonicalisation/"
        "binding, not a standalone signed record.",
        "description": description,
        "baseline_decision_ref": BASE_DR,
        "decision_ref_preimage_fields": STD_FIELDS,
        "decision_ref_preimage": pre,
        "jcs_payload": pre_jcs,
        "preimage_canonical_bytes_hex": pre_jcs.encode("utf-8").hex(),
        "decision_ref": sha256_hex(pre_jcs),
    }
    if unsorted is not None:
        v["decision_ref_preimage_unsorted"] = unsorted
    return v


def dfc_failclosed(vid, description, assert_kind, pre, fields):
    v = {
        "id": vid,
        "axis": "forward_compat",
        "assert": assert_kind,  # "non_conformant" | "fail_closed"
        "expect": "reject",
        "description": description,
        "decision_ref_preimage": pre,
    }
    if fields is not None:
        v["decision_ref_preimage_fields"] = fields
    return v


digest_forward_compat_vectors = [
    dfc_property(
        "presidio-x402-decision-dfc-policy-version-binding",
        "Same artifact_hash as -001, policy_version bumped v1 -> v2. policy_version is in the "
        "preimage, so the same artifact under a different policy surface yields a DIFFERENT "
        "decision_ref. An older id cannot silently stand in for a decision taken under a new policy.",
        "decision_ref_differs",
        _pre("presidio-x402.policy.v2", "ALLOW"),
    ),
    dfc_property(
        "presidio-x402-decision-dfc-verdict-binding",
        "Same artifact_hash and policy_version as -001, verdict ALLOW -> DENY. The verdict is "
        "bound into decision_ref, so it cannot be swapped without the id moving. (Such a record "
        "would also fail the first-block recompute; here we isolate the digest-binding property.)",
        "decision_ref_differs",
        _pre(POLICY_VERSION, "DENY"),
    ),
    dfc_property(
        "presidio-x402-decision-dfc-canonicalisation-stable",
        "Byte-for-byte the same preimage content as -001, presented with the keys in scrambled "
        "order. JCS (RFC 8785) sorts keys before hashing, so the canonical bytes and the "
        "decision_ref are IDENTICAL to -001. Reordering is not tampering.",
        "decision_ref_equals",
        _pre(POLICY_VERSION, "ALLOW"),
        unsorted={
            "verdict": "ALLOW",
            "policy_version": POLICY_VERSION,
            "artifact_type": ARTIFACT_TYPE,
            "artifact_hash": BASE_AH,
        },
    ),
    dfc_failclosed(
        "presidio-x402-decision-dfc-missing-preimage-field-list",
        "The record ships a decision_ref_preimage but declares no decision_ref_preimage_fields. "
        "Without the self-describing field list a verifier cannot know the canonicalisation scope "
        "(which keys, in what set) -> it must fail closed, not guess.",
        "non_conformant",
        _pre(POLICY_VERSION, "ALLOW"),
        None,
    ),
    dfc_failclosed(
        "presidio-x402-decision-dfc-unknown-field-fail-closed",
        "A future policy version adds risk_tier to the preimage object but does NOT list it in "
        "decision_ref_preimage_fields. Declared fields != object keys, so an older verifier would "
        "hash a subset and silently accept a decision it cannot fully reconstruct -> fail closed. "
        "The self-describing field list exists precisely so the surface can grow without this.",
        "fail_closed",
        _pre(POLICY_VERSION, "ALLOW", extra={"risk_tier": "elevated"}),
        STD_FIELDS,
    ),
]

fixture = {
    "fixture_id": "presidio-x402-decision-ref-v1",
    "version": "v1",
    "spec": "plan/presidio-evidence-decision-ref-design.md",
    "hash_algo": "sha256",
    "preimage_format": "jcs-rfc8785-v1",
    "generated_at": "2026-06-30",
    "source": "presidio-hardened-x402 payment-decision (pre-signing); decision_ref shape per "
    "babyblueviper1/preaction-governance-conformance (autogen#7353, crewAI#4877).",
    "purpose": "decision_ref for x402 payment decisions: sha256(JCS({artifact_hash, artifact_type, "
    "policy_version, verdict})) where artifact_hash = sha256(JCS(payment-decision@1)) and "
    "verdict = f(controls), the precedence-combinator over the five recorded control verdicts. "
    "Leads with the two fail-closed negatives (signer != runtime; verdict not recomputable).",
    "reproduce_in_python": (
        "import hashlib, json\n"
        "def jcs(o): return json.dumps(o, sort_keys=True, separators=(',',':'), ensure_ascii=False)\n"
        "artifact_hash = hashlib.sha256(jcs(payment_decision).encode()).hexdigest()\n"
        "decision_ref = hashlib.sha256(jcs({'artifact_hash':artifact_hash,'artifact_type':t,'policy_version':p,'verdict':v}).encode()).hexdigest()"
    ),
    "f_precedence": ["pii", "trusted_wallet", "policy", "replay", "mpa"],
    "vectors": vectors,
    "digest_forward_compat_note": "Second block (x402#2332 / autogen#7353, pshkv's matrix): "
    "the digest & forward-compat axis. Property vectors (axis=digest) assert decision_ref_differs "
    "or decision_ref_equals at the preimage level; fail-closed vectors (axis=forward_compat) carry "
    "expect=reject. Conformance rule for the latter: decision_ref_preimage_fields must be present, "
    "non-empty, and set-equal to the preimage object's keys.",
    "digest_forward_compat_vectors": digest_forward_compat_vectors,
}

# ---- self-validate before emitting ----
errors = []
for v in vectors:
    # 1. decision_ref recomputes from its published preimage fields
    if sha256_hex(jcs(v["decision_ref_preimage"])) != v["decision_ref"]:
        errors.append(f"{v['id']}: decision_ref does not recompute")
    # 2. artifact_hash recomputes
    if sha256_hex(jcs(v["artifact"])) != v["artifact_hash"]:
        errors.append(f"{v['id']}: artifact_hash does not recompute")
    # 3. tamper-sensitivity: flipping verdict changes decision_ref
    tampered = dict(v["decision_ref_preimage"], verdict="DENY")
    if (
        sha256_hex(jcs(tampered)) == v["decision_ref"]
        and v["decision_ref_preimage"]["verdict"] != "DENY"
    ):
        errors.append(f"{v['id']}: NOT tamper-sensitive on verdict")
    # 4. the negatives must actually fail their check; the positive must pass both
    signer_ok = v["signer"]["resolves_to"] != "actor-runtime"
    recompute_ok = v["verdict_recomputed"] == v["artifact"]["verdict"]
    accepted = signer_ok and recompute_ok
    if v["expect"] == "accept" and not accepted:
        errors.append(
            f"{v['id']}: expected accept but checks fail (signer_ok={signer_ok}, recompute_ok={recompute_ok})"
        )
    if v["expect"] == "reject" and accepted:
        errors.append(f"{v['id']}: expected reject but both checks pass")

# ---- self-validate the digest / forward-compat block ----
for v in digest_forward_compat_vectors:
    a = v["assert"]
    pre = v["decision_ref_preimage"]
    if a == "decision_ref_differs":
        if sha256_hex(jcs(pre)) != v["decision_ref"]:
            errors.append(f"{v['id']}: decision_ref does not recompute")
        if v["decision_ref"] == v["baseline_decision_ref"]:
            errors.append(f"{v['id']}: expected a DIFFERENT decision_ref from baseline")
        if pre["artifact_hash"] != BASE_AH:
            errors.append(f"{v['id']}: should reuse baseline artifact_hash (same artifact)")
    elif a == "decision_ref_equals":
        if not (jcs(v["decision_ref_preimage_unsorted"]) == jcs(pre) == v["jcs_payload"]):
            errors.append(f"{v['id']}: scrambled input does not canonicalise to the same bytes")
        if not (sha256_hex(jcs(pre)) == v["decision_ref"] == v["baseline_decision_ref"]):
            errors.append(f"{v['id']}: expected the SAME decision_ref as baseline")
    elif a in ("non_conformant", "fail_closed"):
        if v["expect"] != "reject":
            errors.append(f"{v['id']}: fail-closed vector must expect=reject")
        fields = v.get("decision_ref_preimage_fields")
        conformant = bool(fields) and set(fields) == set(pre.keys())
        if conformant:
            errors.append(f"{v['id']}: expected non-conformant preimage but it is well-formed")
    else:
        errors.append(f"{v['id']}: unknown assert '{a}'")

print("=== self-validation ===")
print("OK" if not errors else "FAIL:\n  " + "\n  ".join(errors))
for v in vectors:
    print(
        f"  {v['id']:48} expect={v['expect']:6} verdict={v['artifact']['verdict']:5} "
        f"f={v['verdict_recomputed']:5} signer={v['signer']['resolves_to']:13} "
        f"decision_ref={v['decision_ref'][:16]}…"
    )
print("--- digest / forward-compat block ---")
for v in digest_forward_compat_vectors:
    dr = v.get("decision_ref", "—(reject)")[:16]
    print(f"  {v['id']:52} assert={v['assert']:20} decision_ref={dr}…")

out = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "presidio-x402-decision-ref-v1.fixture.json"
)
with open(out, "w") as fh:
    json.dump(fixture, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print(f"\nwrote fixture JSON -> {out}")
