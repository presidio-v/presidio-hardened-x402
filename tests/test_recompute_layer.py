"""Conformance test for the recompute-layer (`recompute_mismatch`).

Loads the standalone discriminator and asserts it flags exactly the decision-ref vector
whose verdict does not re-derive from its controls, while leaving the admission negative
(a different layer) unflagged. See tests/conformance/recompute-layer/README.md.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_DIR = Path(__file__).parent / "conformance" / "recompute-layer"
_CHECK = _DIR / "recompute_check.py"
_FIXTURE = (
    Path(__file__).parent
    / "conformance"
    / "decision-ref"
    / "presidio-x402-decision-ref-v1.fixture.json"
)

_spec = importlib.util.spec_from_file_location("recompute_check", _CHECK)
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

_VECTORS = json.loads(_FIXTURE.read_text(encoding="utf-8"))["vectors"]
_BY_ID = {v["id"]: v for v in _VECTORS}


def test_verdict_not_recomputable_flags_recompute_mismatch():
    v = _BY_ID["presidio-x402-decision-verdict-not-recomputable"]
    _, recomputed, kind = rc.recompute(v)
    assert recomputed == "DENY"
    assert kind == rc.RECOMPUTE_MISMATCH


@pytest.mark.parametrize(
    "vid",
    ["presidio-x402-decision-001", "presidio-x402-decision-signer-equals-runtime"],
)
def test_recompute_agrees_where_the_failure_is_not_derivation(vid):
    # recompute is one layer: it agrees on the baseline and on the admission negative
    # (whose failure signature, not derivation, is supposed to catch).
    _, _, kind = rc.recompute(_BY_ID[vid])
    assert kind is None


def test_layer_discriminates_and_check_exits_clean():
    flagged = [v["id"] for v in _VECTORS if rc.recompute(v)[2] is not None]
    assert flagged == ["presidio-x402-decision-verdict-not-recomputable"]
    assert rc.main() == 0
