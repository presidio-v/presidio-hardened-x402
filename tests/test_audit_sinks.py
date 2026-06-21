"""v0.6.0 hardening: remote audit sinks (S3 / Splunk / Datadog) + fan-out.

Transports are injected fakes — no network, no boto3/httpx clients constructed.
Covers batching, flush of a partial batch, fail-safe retention (a ship failure
never propagates into the payment path), bounded-buffer drop, and fan-out.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from presidio_x402._types import AuditEvent
from presidio_x402.audit_sinks import (
    DatadogAuditWriter,
    MultiAuditWriter,
    S3AuditWriter,
    SplunkAuditWriter,
)


def _event(i: int = 0) -> AuditEvent:
    return AuditEvent(
        timestamp=datetime.now(tz=timezone.utc),
        event_type="PAYMENT_ALLOWED",
        resource_url=f"https://api.example.com/v1/data/{i}",
        amount_usd=0.01,
        network="base-sepolia",
        agent_id="test-agent",
        outcome="allowed",
    )


# --- fakes -----------------------------------------------------------------


class FakeS3:
    def __init__(self):
        self.puts: list[dict] = []

    def put_object(self, *, Bucket, Key, Body):  # noqa: N803 - boto3 PascalCase kwargs
        self.puts.append({"Bucket": Bucket, "Key": Key, "Body": Body})


class FakeResp:
    def __init__(self, ok=True):
        self._ok = ok

    def raise_for_status(self):
        if not self._ok:
            raise RuntimeError("HTTP error")


class FakeHttp:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls: list[dict] = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return FakeResp(self.ok)


# --- S3 --------------------------------------------------------------------


def test_s3_ships_on_full_batch_as_jsonl():
    s3 = FakeS3()
    w = S3AuditWriter(bucket="b", key_prefix="x402/", client=s3, batch_size=3)
    for i in range(3):
        w.write(_event(i))
    assert len(s3.puts) == 1
    body = s3.puts[0]["Body"].decode("utf-8")
    assert len(body.splitlines()) == 3
    assert s3.puts[0]["Key"].startswith("x402/") and s3.puts[0]["Key"].endswith(".jsonl")
    # each line is a valid audit dict
    assert all(json.loads(line)["event_type"] == "PAYMENT_ALLOWED" for line in body.splitlines())


def test_s3_flush_ships_partial_batch():
    s3 = FakeS3()
    w = S3AuditWriter(bucket="b", client=s3, batch_size=100)
    w.write(_event())
    assert s3.puts == []  # below batch size, nothing shipped yet
    w.flush()
    assert len(s3.puts) == 1


# --- Splunk / Datadog ------------------------------------------------------


def test_splunk_posts_hec_events_with_auth():
    http = FakeHttp()
    w = SplunkAuditWriter(
        "https://hec:8088/services/collector", "TOKEN", client=http, batch_size=2
    )
    w.write(_event(0))
    w.write(_event(1))
    assert len(http.calls) == 1
    call = http.calls[0]
    assert call["headers"]["Authorization"] == "Splunk TOKEN"
    lines = call["content"].splitlines()
    assert len(lines) == 2 and all("event" in json.loads(line) for line in lines)


def test_splunk_rejects_plaintext_hec_url():
    with pytest.raises(ValueError, match="https://"):
        SplunkAuditWriter("http://hec:8088/services/collector", "TOKEN", client=FakeHttp())


def test_datadog_posts_json_array_with_site_and_key():
    http = FakeHttp()
    w = DatadogAuditWriter("DDKEY", site="datadoghq.eu", client=http, batch_size=1)
    w.write(_event())
    call = http.calls[0]
    assert "datadoghq.eu" in call["url"]
    assert call["headers"]["DD-API-KEY"] == "DDKEY"
    assert isinstance(call["json"], list) and call["json"][0]["ddsource"] == "presidio-x402"


def test_datadog_rejects_site_url_injection():
    with pytest.raises(ValueError, match="hostname"):
        DatadogAuditWriter("DDKEY", site="datadoghq.com@evil.example", client=FakeHttp())


# --- fail-safe + bounded buffer --------------------------------------------


def test_ship_failure_is_retained_not_raised():
    http = FakeHttp(ok=False)
    w = SplunkAuditWriter("https://hec/x", "T", client=http, batch_size=1)
    # write triggers a flush that fails — must NOT raise into the caller
    w.write(_event())
    assert len(w._buffer) == 1  # retained for retry
    # transport recovers; next flush drains the buffer
    http.ok = True
    w.flush()
    assert w._buffer == []


def test_bounded_buffer_drops_oldest_under_sustained_failure():
    http = FakeHttp(ok=False)
    w = SplunkAuditWriter("https://hec/x", "T", client=http, batch_size=1, max_buffer=2)
    for i in range(5):
        w.write(_event(i))
    assert len(w._buffer) <= 2  # capped despite 5 writes, never raised


# --- fan-out ---------------------------------------------------------------


def test_multi_writer_fans_out_and_isolates_failure():
    s3 = FakeS3()
    good = S3AuditWriter(bucket="b", client=s3, batch_size=1)

    class Raising:
        def write(self, event):
            raise RuntimeError("boom")

        def flush(self):
            raise RuntimeError("boom")

    multi = MultiAuditWriter(Raising(), good)
    multi.write(_event())  # raising writer must not stop the good one
    multi.flush()
    assert len(s3.puts) == 1


def test_multi_writer_requires_at_least_one():
    with pytest.raises(ValueError):
        MultiAuditWriter()
