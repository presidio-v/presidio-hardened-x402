# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Cyclomatic-complexity ratchet for ``src/``.

``software-audit/run_audit.py`` tracks max and mean complexity, but only against a
baseline that is refreshed by hand — so a function can grow for months between
refreshes without anything failing. This pins the numbers in CI instead.

The measurement deliberately mirrors ``software-audit/bench/bench_quality.py``
(``CC = 1 + branch-creating nodes``, same node set) so the two never disagree. If
that file's definition changes, change this one with it.

Two directions, both failures:

* **above** the pin — a regression; reduce the complexity, or raise the pin
  consciously and say why in the commit message.
* **below** the pin — the pin is stale; lower it so the recorded numbers stay
  truthful. This is what makes it a ratchet rather than a high-water mark.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"

# Anything not listed must stay at or below this.
CEILING_DEFAULT = 15

# Functions currently above the default, pinned at their measured value.
# Lower these as they are refactored; do not add to the list without a reason.
KNOWN_HIGH = {
    "core.py::ScreeningPipeline.apply": 50,
    "decision_ref.py::verify_decision_ref": 32,
    "mica.py::applicable_obligations": 20,
    "treasury_binding.py::verify_settlement_ref": 19,
    "treasury_binding.py::verify_bundle": 19,
    "capability.py::_parse_caveats": 19,
    "mpa.py::MPAEngine.request_approval": 18,
    "decision_ref.py::_validated_control_verdicts": 17,
    "capability.py::verify_chain": 17,
    "mpa.py::MPAEngine._request_single_approval": 16,
    "mica.py::verify_ref": 16,
}

# Must match bench_quality.py's _BRANCH_TYPES exactly.
_BRANCH_TYPES = (
    ast.If,
    ast.For,
    ast.While,
    ast.ExceptHandler,
    ast.With,
    ast.BoolOp,
    ast.IfExp,
)


def _complexity(node: ast.AST) -> int:
    return 1 + sum(1 for child in ast.walk(node) if isinstance(child, _BRANCH_TYPES))


def _collect(node: ast.AST, prefix: str, out: dict[str, int]) -> None:
    """Walk into classes and functions, keying by dotted qualified name.

    Bare ``function.__name__`` collides 22 ways across ``src/`` (``__init__``,
    ``write``, ``flush`` on sibling classes), and a collision would let one
    function's growth hide behind another's pin.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.ClassDef):
            _collect(child, f"{prefix}{child.name}.", out)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = f"{prefix}{child.name}"
            # The langchain/crewai adapters define their tool class twice — once
            # real, once as a stub in the `except ImportError` arm — so a key can
            # legitimately appear twice. Keep the higher value.
            out[key] = max(out.get(key, 0), _complexity(child))
            _collect(child, f"{key}.", out)
        else:
            _collect(child, prefix, out)


def _measure() -> dict[str, int]:
    measured: dict[str, int] = {}
    for path in sorted(SRC.rglob("*.py")):
        per_file: dict[str, int] = {}
        _collect(ast.parse(path.read_text(encoding="utf-8")), "", per_file)
        for qualname, value in per_file.items():
            measured[f"{path.name}::{qualname}"] = value
    return measured


@pytest.fixture(scope="module")
def measured() -> dict[str, int]:
    return _measure()


def test_no_function_exceeds_its_ceiling(measured):
    over = [
        (key, value, KNOWN_HIGH.get(key, CEILING_DEFAULT))
        for key, value in sorted(measured.items())
        if value > KNOWN_HIGH.get(key, CEILING_DEFAULT)
    ]
    assert not over, "cyclomatic complexity grew past its ceiling:\n" + "\n".join(
        f"  {key}: {value} > {ceiling}" for key, value, ceiling in over
    )


def test_pins_are_not_stale(measured):
    """A pin below the measured value means someone improved it without retuning."""
    slack = [
        (key, measured[key], pinned)
        for key, pinned in sorted(KNOWN_HIGH.items())
        if key in measured and measured[key] < pinned
    ]
    assert not slack, (
        "complexity improved — lower these pins so the recorded numbers stay true:\n"
        + "\n".join(f"  {key}: now {value}, pinned at {pinned}" for key, value, pinned in slack)
    )


def test_pinned_functions_still_exist(measured):
    """Catches renames and deletions leaving dead entries behind."""
    missing = sorted(key for key in KNOWN_HIGH if key not in measured)
    assert not missing, "pinned functions no longer found (renamed or removed?):\n" + "\n".join(
        f"  {key}" for key in missing
    )
