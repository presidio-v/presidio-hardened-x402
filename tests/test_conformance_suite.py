"""The partner conformance suite must pass against the development tree.

This is the same suite OEM partners run via ``python -m presidio_x402.conformance``
(SEMVER.md). Running it inside pytest keeps the runner itself covered and makes
any conformance regression a test failure, not just a separate CI step.

Note: the suite manages its own event loops (``asyncio.run`` per check), so this
test is deliberately synchronous.
"""

from __future__ import annotations

from presidio_x402.conformance import run_all
from presidio_x402.conformance.runner import CHECKS, main


def test_conformance_suite_passes():
    assert run_all() == 0, "partner conformance suite reported failures"


def test_conformance_suite_has_all_documented_checks():
    # SEMVER.md and the package docstring promise 7 checks; keep them honest.
    assert len(CHECKS) == 7
    names = [name for name, _ in CHECKS]
    assert len(set(names)) == len(names), "duplicate check names"


def test_main_exit_contract():
    assert main() == 0  # all green → exit code 0 (fail-closed: any failure → 1)
