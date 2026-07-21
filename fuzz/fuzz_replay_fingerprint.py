# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PRESIDIO Group
"""Atheris property fuzzer for the x402 replay fingerprint canonicalisation.

Targets :func:`presidio_x402.replay_guard._canonical_amount` and
:func:`presidio_x402.replay_guard.compute_fingerprint` — the canonical decimal
normalisation and HMAC fingerprint that back cross-process replay detection. A
representation-level canonicalisation bug here is a replay-detection bypass, so
the properties are:

* ``_canonical_amount`` raises only :class:`ValueError` on bad input; on success
  it is idempotent, value-preserving (``Decimal(out) == Decimal(in)``), and maps
  equal decimal values to one string and unequal values to distinct strings;
* ``compute_fingerprint`` is deterministic, returns 64 lowercase hex characters,
  propagates only :class:`ValueError` (from the amount field), and is injective
  over its case/decimal-normalised field tuple — in particular, shifting a
  boundary character from one field into the next changes the fingerprint, since
  the fields are delimited rather than concatenated.

A fixed fingerprint key is pinned *before* importing the module so fingerprints
are cross-run deterministic and the unset-key ERROR log the module emits at
import time is silenced.
"""

from __future__ import annotations

import contextlib
import os
import sys
from decimal import Decimal

import atheris

# Pin a deterministic 64-hex-char (32-byte) key before importing replay_guard,
# whose module-level key load reads this env var exactly once. The import is
# deferred below the assignment on purpose (hence the E402 waiver).
os.environ["PRESIDIO_X402_FINGERPRINT_KEY"] = "00" * 32

from presidio_x402.replay_guard import _canonical_amount, compute_fingerprint  # noqa: E402


def _hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _valid_amount(fdp: atheris.FuzzedDataProvider) -> str:
    """A syntactically valid, non-negative decimal amount string."""
    return f"{fdp.ConsumeIntInRange(0, 10**12)}.{fdp.ConsumeIntInRange(0, 10**9)}"


def _check_canonical_amount(fdp: atheris.FuzzedDataProvider) -> None:
    a = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 32))
    b = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 32))
    try:
        ca = _canonical_amount(a)
    except ValueError:
        ca = None
    try:
        cb = _canonical_amount(b)
    except ValueError:
        cb = None

    if ca is not None:
        if _canonical_amount(ca) != ca:
            raise AssertionError(f"_canonical_amount not idempotent: {a!r} -> {ca!r}")
        if Decimal(ca) != Decimal(a):
            raise AssertionError(f"_canonical_amount changed value: {a!r} -> {ca!r}")
    if ca is not None and cb is not None:
        same_value = Decimal(a) == Decimal(b)
        if (ca == cb) != same_value:
            raise AssertionError(
                f"decimal equality not reflected in canonical form: "
                f"{a!r}->{ca!r}, {b!r}->{cb!r} (same_value={same_value})"
            )


def _effective_fields(
    url: str, pay_to: str, amount: str, currency: str, deadline: int, network: str
) -> tuple[object, ...]:
    """The normalised tuple the fingerprint is injective over (mirrors the module)."""
    return (
        url,
        pay_to.lower(),
        _canonical_amount(amount),
        currency.upper(),
        int(deadline),
        network.lower(),
    )


def _check_fingerprint(fdp: atheris.FuzzedDataProvider) -> None:
    url = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))
    pay_to = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))
    currency = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 8))
    network = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 12))
    deadline = fdp.ConsumeInt(4)

    # An arbitrary (usually invalid) amount may only ever raise ValueError.
    raw_amount = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 16))
    with contextlib.suppress(ValueError):
        compute_fingerprint(url, pay_to, raw_amount, currency, deadline, network)

    # A guaranteed-valid amount lets us exercise shape and injectivity.
    amount = _valid_amount(fdp)
    fp1 = compute_fingerprint(url, pay_to, amount, currency, deadline, network)
    if not _hex64(fp1):
        raise AssertionError(f"fingerprint is not 64 lowercase hex chars: {fp1!r}")
    if fp1 != compute_fingerprint(url, pay_to, amount, currency, deadline, network):
        raise AssertionError("non-deterministic fingerprint")

    eff1 = _effective_fields(url, pay_to, amount, currency, deadline, network)

    # Independent second payment: shares a fingerprint iff normalised tuples match.
    url2 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))
    pay_to2 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24))
    currency2 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 8))
    network2 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 12))
    deadline2 = fdp.ConsumeInt(4)
    amount2 = _valid_amount(fdp)
    fp2 = compute_fingerprint(url2, pay_to2, amount2, currency2, deadline2, network2)
    eff2 = _effective_fields(url2, pay_to2, amount2, currency2, deadline2, network2)
    if (fp1 == fp2) != (eff1 == eff2):
        raise AssertionError(f"fingerprint injectivity violated: eff1={eff1!r} eff2={eff2!r}")

    # Boundary shift: move the last char of the URL to the front of pay_to. The
    # normalised tuples differ (delimited fields), so the fingerprint must change.
    if url:
        url_s = url[:-1]
        pay_to_s = url[-1] + pay_to
        fp_s = compute_fingerprint(url_s, pay_to_s, amount, currency, deadline, network)
        eff_s = _effective_fields(url_s, pay_to_s, amount, currency, deadline, network)
        if (fp1 == fp_s) != (eff1 == eff_s):
            raise AssertionError(f"boundary-shift ambiguity: eff1={eff1!r} eff_s={eff_s!r}")


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris entrypoint contract)
    fdp = atheris.FuzzedDataProvider(data)
    _check_canonical_amount(fdp)
    _check_fingerprint(fdp)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
