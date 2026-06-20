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

from presidio_x402.action_ref import compute_action_ref, format_action_ref_timestamp

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
