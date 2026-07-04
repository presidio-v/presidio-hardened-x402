#!/usr/bin/env python3
"""recompute-layer — the `recompute_mismatch` conformance class.

Integrity checks (signature, digest, schema) prove a decision record is INTACT and
correctly signed. They do NOT prove the recorded verdict RE-DERIVES from the record's
own controls. This layer closes that gap for the concrete instance verdict = f(controls).

Four layers, boundaries load-bearing:
  integrity   -- the record was preserved
  signature   -- who signed it (admission: is the signer entitled to decide?)
  recompute   -- the verdict follows from the DECLARED controls   <-- this layer
  attestation -- the declared controls are the REAL controls      (separate, not here)

A record whose verdict does not re-derive is flagged under `recompute_mismatch` (name
agreed on x402-foundation/x402#2332; parallels a `_mismatch` integrity class). It is
never a substitute for another layer's verdict -- recompute is additive.

Run over the sibling decision-ref fixture, this DISCRIMINATES across layers:
  - presidio-x402-decision-001                      -> recompute AGREES
  - presidio-x402-decision-signer-equals-runtime    -> recompute AGREES (its failure is
      admission, a different layer -- recompute correctly does not flag it)
  - presidio-x402-decision-verdict-not-recomputable -> recompute_mismatch

Recompute checks derivation from the DECLARED controls; it cannot say the controls are
truthful. A recorder who lies about a control verdict gets a clean recompute over a
false premise -- that is an attestation failure, not a recompute one.

Provenance: proposed as an APS accountability-record layer (aeoess/aps-conformance-suite
PR #9); APS declined new failure-class vocabulary 2026-07-04 pending a contribution
policy, so the layer is homed here beside its concrete instance. Zero dependencies.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "..", "decision-ref", "presidio-x402-decision-ref-v1.fixture.json")

RECOMPUTE_MISMATCH = "recompute_mismatch"

# Control verdicts that force DENY, per control key (first-failure-wins).
HARD_FAIL = {
    "pii": {"PII_BLOCKED"},
    "trusted_wallet": {"UNTRUSTED"},
    "policy": {"VIOLATION"},
    "replay": {"DUPLICATE"},
    "mpa": {"DENIED"},
}
# mpa verdicts that force REFER (defer to a human / multi-party approver).
MPA_REFER = {"PENDING", "TIMEOUT"}
PRECEDENCE = ["pii", "trusted_wallet", "policy", "replay", "mpa"]

# The one vector this layer is meant to flag; the others fail elsewhere or not at all.
EXPECTED_FLAGGED = ["presidio-x402-decision-verdict-not-recomputable"]


def f_controls(controls: dict) -> str:
    """Precedence-combinator over the five recorded control verdicts.
    First failure wins; returns ALLOW / DENY / REFER."""
    for key in PRECEDENCE:
        verdict = controls.get(key, {}).get("verdict")
        if verdict in HARD_FAIL.get(key, set()):
            return "DENY"
        if key == "mpa" and verdict in MPA_REFER:
            return "REFER"
    return "ALLOW"


def recompute(vec: dict):
    """Return (recorded, recomputed, kind). kind is recompute_mismatch on a flag, else None."""
    recorded = vec["artifact"]["verdict"]
    recomputed = f_controls(vec["artifact"]["controls"])
    kind = None if recomputed == recorded else RECOMPUTE_MISMATCH
    return recorded, recomputed, kind


def main() -> int:
    with open(FIXTURE, encoding="utf-8") as fh:
        fixture = json.load(fh)
    print("recompute-layer -- verdict = f(controls), first-failure-wins\n")

    flagged = []
    for vec in fixture["vectors"]:
        recorded, recomputed, kind = recompute(vec)
        if kind is None:
            note = "recompute AGREES"
        else:
            note = f"recompute DISAGREES -> {kind}"
            flagged.append(vec["id"])
        layer = ""
        if vec.get("failure_mode") == "signer_equals_runtime":
            layer = "  (admission failure -- a different layer; recompute does not flag it)"
        print(f"  {vec['id']:48} recorded={recorded:6} f(controls)={recomputed:6} {note}{layer}")

    print()
    if flagged == EXPECTED_FLAGGED:
        print(f"recompute_mismatch flagged exactly {flagged} (discriminates; not always-fail)")
        return 0
    print(f"[!] UNEXPECTED: flagged={flagged}, expected={EXPECTED_FLAGGED}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
