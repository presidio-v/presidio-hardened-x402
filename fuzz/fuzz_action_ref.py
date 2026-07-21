# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Atheris property fuzzer for the action-ref-v1 derivation.

Targets :func:`presidio_x402.action_ref.compute_action_ref` and
:func:`presidio_x402.action_ref.format_action_ref_timestamp`. ``compute_action_ref``
is ``sha256`` over the JCS canonicalisation of an NFC-normalised four-field
preimage (``agent_id``, ``action_type``, ``scope``, ``timestamp``);
``format_action_ref_timestamp`` renders the single conformant timestamp form.
Properties:

* ``format_action_ref_timestamp`` rejects a naive datetime with
  :class:`ValueError`, and its output for an aware datetime is always accepted by
  ``compute_action_ref`` (any rejection would be a real format/verify mismatch);
* ``compute_action_ref`` raises only :class:`ValueError` for a non-conformant
  timestamp string;
* on a conformant timestamp it is deterministic, returns 64 lowercase hex
  characters, and is injective over the *NFC-normalised* preimage — changing any
  field, or shifting a boundary character between fields, changes the ref exactly
  when the NFC-normalised preimage changes.
"""

from __future__ import annotations

import contextlib
import sys
import unicodedata
from datetime import datetime, timezone

import atheris

from presidio_x402.action_ref import compute_action_ref, format_action_ref_timestamp


def _hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _txt(fdp: atheris.FuzzedDataProvider) -> str:
    return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))


def _nfc_key(agent_id: str, action_type: str, scope: str, timestamp: str) -> tuple[str, ...]:
    """The NFC-normalised preimage tuple the ref is injective over."""
    return (
        unicodedata.normalize("NFC", agent_id),
        unicodedata.normalize("NFC", action_type),
        unicodedata.normalize("NFC", scope),
        timestamp,
    )


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris entrypoint contract)
    fdp = atheris.FuzzedDataProvider(data)

    agent_id = _txt(fdp)
    action_type = _txt(fdp)
    scope = _txt(fdp)

    # (a) An arbitrary timestamp string may only ever raise ValueError.
    raw_ts = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 32))
    with contextlib.suppress(ValueError):
        compute_action_ref(agent_id, action_type, scope, raw_ts)

    # A naive datetime must be rejected rather than silently assumed UTC.
    naive = datetime(2026, 7, 20, 12, 0, 0)
    try:
        format_action_ref_timestamp(naive)
    except ValueError:
        pass
    else:
        raise AssertionError("format_action_ref_timestamp accepted a naive datetime")

    # (b) A conformant timestamp built from a fuzzed aware datetime. Year bound to
    # a range where strftime("%Y") is always four digits, keeping the output
    # conformant across platforms.
    aware = datetime(
        fdp.ConsumeIntInRange(1000, 9999),
        fdp.ConsumeIntInRange(1, 12),
        fdp.ConsumeIntInRange(1, 28),
        fdp.ConsumeIntInRange(0, 23),
        fdp.ConsumeIntInRange(0, 59),
        fdp.ConsumeIntInRange(0, 59),
        fdp.ConsumeIntInRange(0, 999_999),
        tzinfo=timezone.utc,
    )
    ts = format_action_ref_timestamp(aware)

    # format -> compute contract: a formatted timestamp must never be rejected.
    ref = compute_action_ref(agent_id, action_type, scope, ts)
    if not _hex64(ref):
        raise AssertionError(f"action_ref is not 64 lowercase hex chars: {ref!r}")
    if ref != compute_action_ref(agent_id, action_type, scope, ts):
        raise AssertionError("non-deterministic action_ref")

    # Independent second preimage: shares a ref iff the NFC-normalised keys match.
    other = (_txt(fdp), _txt(fdp), _txt(fdp))
    ref2 = compute_action_ref(other[0], other[1], other[2], ts)
    same = _nfc_key(*other, ts) == _nfc_key(agent_id, action_type, scope, ts)
    if (ref2 == ref) != same:
        raise AssertionError(
            f"injectivity violated: {(agent_id, action_type, scope)!r} vs {other!r}"
        )

    base = [agent_id, action_type, scope]

    # Single-field sensitivity: an ASCII append never NFC-merges, so the ref changes.
    idx = fdp.ConsumeIntInRange(0, 2)
    mutated = list(base)
    mutated[idx] = mutated[idx] + "x"
    if compute_action_ref(mutated[0], mutated[1], mutated[2], ts) == ref:
        raise AssertionError(f"field {idx} change did not change ref: {base!r}")

    # Boundary shift between adjacent fields, checked against the NFC-normalised
    # keys so a legitimate combining-mark merge stays consistent (biconditional).
    j = fdp.ConsumeIntInRange(0, 2)
    if base[j]:
        k = (j + 1) % 3
        shifted = list(base)
        shifted[j] = base[j][:-1]
        shifted[k] = base[j][-1] + base[k]
        got_same = compute_action_ref(shifted[0], shifted[1], shifted[2], ts) == ref
        want_same = _nfc_key(*shifted, ts) == _nfc_key(*base, ts)
        if got_same != want_same:
            raise AssertionError(f"boundary-shift ambiguity: {base!r} -> {shifted!r}")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
