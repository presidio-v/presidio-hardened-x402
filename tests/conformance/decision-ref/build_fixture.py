"""Generate + self-validate the x402 payment-decision-ref conformance fixture.

Drops into giskard09/argentum-core examples/conformance/presidio/ (same shape as
action-ref-v1.fixture.json) and babyblueviper1's decision-ref-recompute slot:
    decision_ref = sha256(JCS({artifact_hash, artifact_type, policy_version, verdict}))
where artifact_hash = sha256(JCS(payment-decision@1 content)), and verdict = f(controls).
"""

import hashlib
import json

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

print("=== self-validation ===")
print("OK" if not errors else "FAIL:\n  " + "\n  ".join(errors))
for v in vectors:
    print(
        f"  {v['id']:48} expect={v['expect']:6} verdict={v['artifact']['verdict']:5} "
        f"f={v['verdict_recomputed']:5} signer={v['signer']['resolves_to']:13} "
        f"decision_ref={v['decision_ref'][:16]}…"
    )

with open(
    "/private/tmp/claude-501/-Users-vstantch-projects-presidio-hardened-x402/9fadd1a0-1398-4383-8e14-12ded2f310ee/scratchpad/presidio-x402-decision-ref-v1.fixture.json",
    "w",
) as fh:
    json.dump(fixture, fh, indent=2, ensure_ascii=False)
print("\nwrote fixture JSON")
