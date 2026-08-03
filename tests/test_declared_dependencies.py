# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Packaging-contract tests for directly imported third-party modules.

A module that ``import``s a package the distribution does not declare works only
for as long as some *other* dependency happens to pull that package in. The
arrangement is invisible to the test suite, because a dev environment installs
strictly more than a core install does, and invisible to Dependabot, which reads
declared requirements.

These tests assert the declarations exist. They are deliberately metadata
assertions rather than functional ones: a functional test passes either way in
any environment where the package is present for unrelated reasons, which is
exactly the situation that let both of the gaps below survive.
"""

from __future__ import annotations

import importlib.metadata

import pytest

DIST = "presidio-hardened-x402"


def _requirements() -> list[str]:
    reqs = importlib.metadata.requires(DIST)
    if reqs is None:  # pragma: no cover - only when running against a broken install
        pytest.skip(f"{DIST} metadata unavailable; run against an installed distribution")
    return reqs


def _core_requirements() -> list[str]:
    """Requirements with no ``extra ==`` marker — what a bare install gets."""
    return [r for r in _requirements() if "extra ==" not in r]


def _named(requirements: list[str], name: str) -> list[str]:
    out = []
    for req in requirements:
        head = req.split(";")[0].strip()
        for sep in ("[", ">", "<", "=", "!", "~", " ", "("):
            head = head.split(sep)[0]
        if head.strip().lower().replace("_", "-") == name:
            out.append(req)
    return out


def test_packaging_is_a_core_dependency():
    """``packaging`` backs the import-time dependency-CVE audit.

    ``_on_import_audit`` compares installed versions against the
    ``_KNOWN_VULNERABLE`` floors using ``packaging.version``. Its import is
    guarded, and the fallback skips every comparison, so an absent ``packaging``
    disables the warning silently rather than raising. It previously resolved only
    as a 3-hop transitive of presidio-analyzer -> spaCy -> thinc/weasel.
    """
    assert _named(_core_requirements(), "packaging"), (
        "packaging must be a core dependency — __init__.py imports it directly, and "
        "without it the dependency-CVE audit fails open instead of loudly"
    )


def test_tomli_is_declared_for_pre_311():
    """``tomli`` backs TOML policy files on the lowest supported Python.

    stdlib ``tomllib`` is 3.11+ while ``requires-python`` is >=3.10, so
    ``load_policy_file`` on a ``.toml`` path needs ``tomli`` there. It must carry a
    ``python_version < "3.11"`` marker so 3.11+ installs do not take a needless
    dependency.
    """
    matches = _named(_core_requirements(), "tomli")
    assert matches, (
        "tomli must be declared — load_policy_file() imports it for TOML policy "
        "files, which the README documents, and stdlib tomllib is 3.11+"
    )
    assert any("python_version" in req and "3.11" in req for req in matches), (
        f"tomli must be marked for Python < 3.11, got: {matches}"
    )


def test_no_extra_only_dependency_backs_a_core_import():
    """Guard the general shape: core imports must not rest on extras.

    Both gaps above shared a cause — a module-scope import satisfied by something
    outside the core requirement set. This pins the two names that were fixed so a
    later edit cannot quietly demote either into an extra.
    """
    core = {
        req.split(";")[0].strip().split("[")[0].split(">")[0].split("<")[0].split("=")[0].strip()
        for req in _core_requirements()
    }
    for name in ("httpx", "packaging", "tomli"):
        assert name in core, f"{name} is imported directly and must stay a core requirement"
