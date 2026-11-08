"""The email scanner finds exactly the matches of EMAIL_PATTERN, in linear time.

0.14.1 anchored the regex with a lookbehind instead. That was linear but missed an address that
directly follows another one through a local-part character (GHSA-9pcv-26m2-4ch8).
"""

from __future__ import annotations

import random
import re
import time

import pytest

from presidio_x402.pii_filter import EMAIL_PATTERN, PIIFilter, _EmailScanner

REFERENCE = re.compile(EMAIL_PATTERN, re.IGNORECASE)
ALPHABET = "aZ09._%+-@-..@ xKſKİı,;<>\nmc"


def test_same_matches_as_the_regex():
    rnd = random.Random(20261108)  # noqa: S311 - reproducible test input, not a secret
    scanner = _EmailScanner()
    for _ in range(50_000):
        s = "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(0, 60)))
        assert [m.span() for m in scanner.finditer(s)] == [
            m.span() for m in REFERENCE.finditer(s)
        ], s


@pytest.mark.parametrize(
    "text",
    [
        "a@b.cc+victim@example.com",
        "x@y.io-victim@example.com",
        "a@b.cc_victim@example.com",
        "a@b.cc%victim@example.com",
    ],
)
def test_adjacent_addresses_are_both_redacted(text):
    redacted, entities = PIIFilter(mode="regex").scan_and_redact(text)
    assert "victim" not in redacted
    assert [e.entity_type for e in entities] == ["EMAIL_ADDRESS", "EMAIL_ADDRESS"]


@pytest.mark.parametrize(
    "text",
    [
        "a" * (1 << 18),
        "a@" + "a." * (1 << 17),
        "@" * (1 << 18),
        "x." * (1 << 17) + "@",
        "a@b" * 80_000,
    ],
)
def test_linear_time(text):
    start = time.perf_counter()
    list(_EmailScanner().finditer(text))
    assert time.perf_counter() - start < 1.0
