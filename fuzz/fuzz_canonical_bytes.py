"""Atheris property fuzzer for :func:`presidio_x402.mica.canonical_bytes`.

``canonical_bytes`` is the family strict-profile canonical JSON encoder (sorted
keys, ``(",", ":")`` separators, UTF-8, ``ensure_ascii=False``, floats rejected).
Every producer in the toolkit family must byte-match it, so its determinism and
injectivity are load-bearing. This harness drives it with arbitrary JSON-safe
payload trees (dict / list / str / int / bool / None, str keys only, bounded
depth) built from ``FuzzedDataProvider``, and asserts:

* determinism    — two encodings of one payload are byte-identical;
* round-trip     — ``json.loads(canonical_bytes(p).decode())`` reproduces ``p``;
* injectivity    — two payloads share canonical bytes iff they are equal in the
                   canonical JSON data model (type-aware: ``True`` is not ``1``);
* float guard    — a float anywhere raises exactly
                   :class:`~presidio_x402.mica.EvidenceError` and nothing else;
* normalisation  — NFC and NFD spellings of one string, being distinct
                   code-point sequences the encoder does not fold, never collapse
                   to equal bytes (a collapse would be a real canonicalisation
                   defect, so it is asserted rather than tolerated).
"""

from __future__ import annotations

import json
import sys
import unicodedata

import atheris

from presidio_x402.mica import EvidenceError, canonical_bytes

#: Bounded recursion depth for generated payload trees.
_MAX_DEPTH = 5


def _build(fdp: atheris.FuzzedDataProvider, depth: int) -> object:
    """Build one arbitrary, float-free, str-keyed JSON payload node."""
    # Only scalars are permitted at the leaf level (depth exhausted).
    max_choice = 5 if depth > 0 else 3
    choice = fdp.ConsumeIntInRange(0, max_choice)
    if choice == 0:
        return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))
    if choice == 1:
        return fdp.ConsumeInt(8)
    if choice == 2:
        return fdp.ConsumeBool()
    if choice == 3:
        return None
    if choice == 4:
        return [_build(fdp, depth - 1) for _ in range(fdp.ConsumeIntInRange(0, 4))]
    # Dict keys are restricted to strings — the documented domain. json.dumps
    # coerces non-str keys, which would break injectivity for reasons unrelated
    # to the encoder under test.
    return {
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 16)): _build(fdp, depth - 1)
        for _ in range(fdp.ConsumeIntInRange(0, 4))
    }


def _typed_eq(a: object, b: object) -> bool:
    """Equality in the canonical JSON data model (``True`` distinct from ``1``)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_typed_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_typed_eq(x, y) for x, y in zip(a, b, strict=False))
    return a == b


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris entrypoint contract)
    fdp = atheris.FuzzedDataProvider(data)
    payload = _build(fdp, _MAX_DEPTH)

    encoded = canonical_bytes(payload)
    if encoded != canonical_bytes(payload):
        raise AssertionError(f"non-deterministic encoding for {payload!r}")

    restored = json.loads(encoded.decode("utf-8"))
    if restored != payload:
        raise AssertionError(f"round-trip altered payload: {payload!r} -> {restored!r}")

    other = _build(fdp, _MAX_DEPTH)
    if (canonical_bytes(other) == encoded) != _typed_eq(other, payload):
        raise AssertionError(f"injectivity violated: {payload!r} vs {other!r}")

    # Distinct NFC/NFD spellings must not collapse to identical bytes.
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))
    nfc = unicodedata.normalize("NFC", text)
    nfd = unicodedata.normalize("NFD", text)
    if nfc != nfd and canonical_bytes(nfc) == canonical_bytes(nfd):
        raise AssertionError(f"NFC/NFD spellings collapsed to equal bytes: {text!r}")

    # A float anywhere must fail closed with EvidenceError — nothing else escapes.
    bad_float = fdp.ConsumeFloat()
    where = fdp.ConsumeIntInRange(0, 2)
    if where == 0:
        bad_payload: object = bad_float
    elif where == 1:
        bad_payload = {"amount": bad_float}
    else:
        bad_payload = [payload, [bad_float]]
    try:
        canonical_bytes(bad_payload)
    except EvidenceError:
        pass
    else:
        raise AssertionError(f"float payload did not raise EvidenceError: {bad_payload!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
