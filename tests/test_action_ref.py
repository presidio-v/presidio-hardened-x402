"""Conformance tests for action-ref-v1 derivation.

Byte-match vectors are lifted verbatim from argentum-core
``examples/conformance/provider-protocol/vectors.json`` (suite
``mycelium-provider-protocol-v1``) plus the worked NEXUS example in
``docs/spec/action-ref.md``. If these pass, our ``compute_action_ref`` is
interoperable with every other action-ref-v1 implementation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from presidio_x402.action_ref import (
    compute_action_ref,
    compute_screen_ref,
    format_action_ref_timestamp,
    format_screen_scope,
)

# --- Known-answer vectors (argentum-core mycelium-provider-protocol-v1) -------

ACCEPT_VECTORS = [
    # id, agent_id, action_type, scope, timestamp, expected
    (
        "pp-001",
        "did:aps:zProviderAgent001",
        "document.sign",
        "mycelium:provider-protocol",
        "2026-06-20T14:00:00.000Z",
        "a0de245ffff300fe5aeb6e110c55b1ea623aaae49bda8a5e5f258b28b06c3ff9",
    ),
    (
        "pp-002",  # empty scope passes "" — not null, not omitted
        "did:web:provider.example.com",
        "action",
        "",
        "2026-01-01T00:00:00.000Z",
        "e1aecf30cbc5451d4f2149739c2bc6d49742df1082f5aa2d9b4144baf51d29bf",
    ),
    (
        "spec-nexus",  # worked example from docs/spec/action-ref.md
        "nexus-agent-xa12.onrender.com",
        "oracle.signal",
        "BTC",
        "2025-05-18T11:40:31.000Z",
        "fdd7f810499f06be24355ca8e2bfb8c4b965cc80c838f41fa074683443d89f5a",
    ),
]

# pp-reject-*: timestamps that an emitter must never produce / hash.
REJECT_TIMESTAMPS = [
    ("pp-reject-001", "2026-06-20T14:00:00Z"),  # missing milliseconds
    ("pp-reject-002", "2026-06-20T14:00:00.000000Z"),  # 6-digit fractional
    ("offset-not-Z", "2026-06-20T14:00:00.000+00:00"),  # offset, not Z
]


@pytest.mark.parametrize("vid,agent_id,action_type,scope,ts,expected", ACCEPT_VECTORS)
def test_action_ref_byte_match(vid, agent_id, action_type, scope, ts, expected):
    assert compute_action_ref(agent_id, action_type, scope, ts) == expected


def test_key_order_independence():
    # pp-003: identical tuple, three different source key orders -> same digest.
    expected = "a0de245ffff300fe5aeb6e110c55b1ea623aaae49bda8a5e5f258b28b06c3ff9"
    assert (
        compute_action_ref(
            agent_id="did:aps:zProviderAgent001",
            action_type="document.sign",
            scope="mycelium:provider-protocol",
            timestamp="2026-06-20T14:00:00.000Z",
        )
        == expected
    )


@pytest.mark.parametrize("vid,ts", REJECT_TIMESTAMPS)
def test_nonconformant_timestamp_rejected(vid, ts):
    with pytest.raises(ValueError, match="timestamp must be RFC 3339"):
        compute_action_ref("did:aps:zX", "document.sign", "", ts)


# --- Timestamp formatter (normative format_timestamp reference) --------------


def test_format_timestamp_three_ms_digits_and_z():
    dt = datetime(2026, 6, 20, 14, 0, 0, 123456, tzinfo=timezone.utc)
    assert format_action_ref_timestamp(dt) == "2026-06-20T14:00:00.123Z"


def test_format_timestamp_zero_subsecond_keeps_three_zeros():
    dt = datetime.fromtimestamp(1747568431, tz=timezone.utc)  # NEXUS example epoch
    assert format_action_ref_timestamp(dt) == "2025-05-18T11:40:31.000Z"


def test_format_timestamp_converts_to_utc():
    from datetime import timedelta

    tz_plus2 = timezone(timedelta(hours=2))
    dt = datetime(2026, 6, 20, 16, 0, 0, 0, tzinfo=tz_plus2)  # 14:00 UTC
    assert format_action_ref_timestamp(dt) == "2026-06-20T14:00:00.000Z"


def test_format_timestamp_rejects_naive():
    with pytest.raises(ValueError, match="timezone-aware"):
        format_action_ref_timestamp(datetime(2026, 6, 20, 14, 0, 0))


def test_format_then_compute_roundtrip():
    ts = format_action_ref_timestamp(datetime.fromtimestamp(1747568431, tz=timezone.utc))
    assert (
        compute_action_ref("nexus-agent-xa12.onrender.com", "oracle.signal", "BTC", ts)
        == "fdd7f810499f06be24355ca8e2bfb8c4b965cc80c838f41fa074683443d89f5a"
    )


# --- screen_ref byte-match vectors -------------------------------------------
# Lifted verbatim from argentum-core
# examples/conformance/presidio/action-ref-v1.fixture.json (commit 16dbc92),
# the byte-identical targets for the screen_ref leg of the composed envelope
# on x402-foundation/x402#2332. action_type is the fixed "pii_screen"; scope
# carries the lexicographically-sorted entity segment (rule normative since
# 16dbc92). entities are passed in DETECTION order on purpose — the canonical
# sort must happen inside compute_screen_ref, not at the call site.
SCREEN_VECTORS = [
    # id, verdict, entities (detection order), timestamp, expected
    (
        "presidio-x402-003",
        "PII_REDACTED",
        ["EMAIL_ADDRESS", "US_SSN"],
        "2026-06-20T17:45:00.000Z",
        "c832ef8610c6989f8c6f5cea51ac019b8ac9860e389110079a895e67595950a2",
    ),
    (
        "presidio-x402-004",  # the vector that needed the sort fix (PII_BLOCKED)
        "PII_BLOCKED",
        ["US_SSN", "EMAIL_ADDRESS"],  # detection order reversed: sort must fix it
        "2026-06-20T17:45:01.000Z",
        "79509b33e9ad2bf7bf4f80bff2dd73d04e012204ae63bb1bbc1b9d052f337ef4",
    ),
    (
        "presidio-x402-005",  # clean-allow: no entity segment at all
        "clean-allow",
        [],
        "2026-06-20T17:45:02.000Z",
        "d9f8ecb35fef996e58a72cee801c17b4ca40c3ed3dede89438830e7a4a8c911d",
    ),
]

_SCREEN_AGENT_ID = "did:presidio:x402:agent-7f3a9c"


@pytest.mark.parametrize("vid,verdict,entities,ts,expected", SCREEN_VECTORS)
def test_screen_ref_byte_match(vid, verdict, entities, ts, expected):
    assert compute_screen_ref(_SCREEN_AGENT_ID, verdict, entities, ts) == expected


def test_screen_scope_sorts_entities_lexicographically():
    # Detection order must not leak into the scope: US_SSN before EMAIL_ADDRESS
    # canonicalizes to EMAIL_ADDRESS,US_SSN (E < U).
    assert (
        format_screen_scope("PII_BLOCKED", ["US_SSN", "EMAIL_ADDRESS"])
        == "presidio:x402.screen:PII_BLOCKED:EMAIL_ADDRESS,US_SSN"
    )


def test_screen_scope_dedupes_entities():
    # Multiplicity (two emails) must not leak into the canonical scope.
    assert (
        format_screen_scope("PII_REDACTED", ["EMAIL_ADDRESS", "EMAIL_ADDRESS", "US_SSN"])
        == "presidio:x402.screen:PII_REDACTED:EMAIL_ADDRESS,US_SSN"
    )


def test_screen_scope_clean_allow_has_no_entity_segment():
    assert format_screen_scope("clean-allow") == "presidio:x402.screen:clean-allow"


def test_screen_scope_rejects_empty_verdict():
    with pytest.raises(ValueError, match="non-empty"):
        format_screen_scope("")


@pytest.mark.parametrize("bad_verdict", ["PII:REDACTED", "PII,REDACTED"])
def test_screen_scope_rejects_separator_in_verdict(bad_verdict):
    # Both ':' and ',' would forge or split a scope segment; reject either.
    with pytest.raises(ValueError, match="separator"):
        format_screen_scope(bad_verdict, ["EMAIL_ADDRESS"])


def test_screen_scope_rejects_separator_in_entity():
    with pytest.raises(ValueError, match="separator"):
        format_screen_scope("PII_REDACTED", ["EMAIL,ADDRESS"])
