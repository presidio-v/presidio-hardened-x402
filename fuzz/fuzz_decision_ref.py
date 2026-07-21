# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Atheris property fuzzer for :func:`presidio_x402.decision_ref.compute_decision_ref`.

``compute_decision_ref`` derives the thin, self-describing correlation id
``sha256(canonical_bytes({artifact_hash, artifact_type, policy_version, verdict}))``.
Its four preimage fields are all strings, so the canonical encoder never sees a
float and no exception should escape for any string inputs. This harness drives
it with arbitrary Unicode field values and asserts:

* determinism   — equal inputs give equal refs;
* shape         — the ref is 64 lowercase hex characters;
* injectivity   — two field tuples share a ref iff the tuples are equal, so
                  appending to any single field, or shifting a boundary character
                  from one field into the next, changes the ref;
* totality      — no exception escapes for any string inputs (a raise from the
                  canonical encoder over an all-string mapping is a real finding,
                  so it is deliberately not caught).
"""

from __future__ import annotations

import sys

import atheris

from presidio_x402.decision_ref import compute_decision_ref


def _hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _txt(fdp: atheris.FuzzedDataProvider) -> str:
    return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))


def _ref(fields: list[str]) -> str:
    # fields = [artifact_hash, policy_version, verdict, artifact_type]
    return compute_decision_ref(
        artifact_hash=fields[0],
        policy_version=fields[1],
        verdict=fields[2],
        artifact_type=fields[3],
    )


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris entrypoint contract)
    fdp = atheris.FuzzedDataProvider(data)
    fields = [_txt(fdp) for _ in range(4)]

    ref = _ref(fields)
    if not _hex64(ref):
        raise AssertionError(f"decision_ref is not 64 lowercase hex chars: {ref!r}")
    if ref != _ref(fields):
        raise AssertionError(f"non-deterministic decision_ref for {fields!r}")

    # Independent second preimage: shares a ref iff the field tuples are equal.
    other = [_txt(fdp) for _ in range(4)]
    if (_ref(other) == ref) != (other == fields):
        raise AssertionError(f"injectivity violated: {fields!r} vs {other!r}")

    # Single-field sensitivity: any change to any field changes the ref.
    idx = fdp.ConsumeIntInRange(0, 3)
    mutated = list(fields)
    mutated[idx] = mutated[idx] + "x"
    if _ref(mutated) == ref:
        raise AssertionError(f"field {idx} change did not change ref: {fields!r}")

    # Boundary shift between adjacent fields — the fields are delimited, so the
    # ref must change exactly when the (always different) tuples differ.
    j = fdp.ConsumeIntInRange(0, 3)
    if fields[j]:
        k = (j + 1) % 4
        shifted = list(fields)
        shifted[j] = fields[j][:-1]
        shifted[k] = fields[j][-1] + fields[k]
        if (_ref(shifted) == ref) != (shifted == fields):
            raise AssertionError(f"boundary-shift ambiguity: {fields!r} -> {shifted!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
