"""Tests for AuditLog — tamper-evident audit event emission."""

from __future__ import annotations

import io
import json
from datetime import timezone

import pytest

from presidio_x402._types import AuditEvent
from presidio_x402.audit_log import AuditLog, NullAuditWriter, StreamAuditWriter


class TestNullAuditWriter:
    def test_write_does_not_raise(self):
        writer = NullAuditWriter()
        from datetime import datetime

        event = AuditEvent(
            timestamp=datetime.now(tz=timezone.utc),
            event_type="PAYMENT_ALLOWED",
            resource_url="https://api.example.com",
            amount_usd=0.01,
            network="base-mainnet",
            agent_id=None,
            outcome="allowed",
        )
        writer.write(event)  # should not raise


class TestStreamAuditWriter:
    def test_writes_json_line(self):
        buf = io.StringIO()
        writer = StreamAuditWriter(stream=buf)
        from datetime import datetime

        event = AuditEvent(
            timestamp=datetime.now(tz=timezone.utc),
            event_type="PAYMENT_ALLOWED",
            resource_url="https://api.example.com",
            amount_usd=0.02,
            network="base-mainnet",
            agent_id="agent-1",
            outcome="allowed",
        )
        writer.write(event)
        buf.seek(0)
        line = buf.readline()
        parsed = json.loads(line)
        assert parsed["event_type"] == "PAYMENT_ALLOWED"
        assert parsed["resource_url"] == "https://api.example.com"
        assert parsed["amount_usd"] == pytest.approx(0.02)

    def test_multiple_events_multiple_lines(self):
        buf = io.StringIO()
        writer = StreamAuditWriter(stream=buf)
        log = AuditLog(writer=writer)

        log.emit("PAYMENT_ALLOWED", resource_url="https://a.example.com", outcome="allowed")
        log.emit("POLICY_BLOCKED", resource_url="https://b.example.com", outcome="blocked")

        buf.seek(0)
        lines = [ln for ln in buf.readlines() if ln.strip()]
        assert len(lines) == 2
        events = [json.loads(ln) for ln in lines]
        assert events[0]["event_type"] == "PAYMENT_ALLOWED"
        assert events[1]["event_type"] == "POLICY_BLOCKED"


class TestAuditLogChaining:
    def test_first_entry_has_null_prev_hmac(self):
        buf = io.StringIO()
        log = AuditLog(writer=StreamAuditWriter(buf))
        log.emit("PAYMENT_ALLOWED", resource_url="https://api.example.com", outcome="allowed")
        buf.seek(0)
        entry = json.loads(buf.readline())
        assert entry["prev_entry_hmac"] is None

    def test_second_entry_has_non_null_prev_hmac(self):
        buf = io.StringIO()
        log = AuditLog(writer=StreamAuditWriter(buf))
        log.emit("PAYMENT_ALLOWED", resource_url="https://api.example.com", outcome="allowed")
        log.emit("PAYMENT_ALLOWED", resource_url="https://api.example.com", outcome="allowed")
        buf.seek(0)
        lines = [ln for ln in buf.readlines() if ln.strip()]
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert first["prev_entry_hmac"] is None
        assert second["prev_entry_hmac"] is not None
        assert isinstance(second["prev_entry_hmac"], str)
        assert len(second["prev_entry_hmac"]) == 64  # SHA-256 hex

    def test_chain_hmacs_are_distinct(self):
        buf = io.StringIO()
        log = AuditLog(writer=StreamAuditWriter(buf))
        for _ in range(3):
            log.emit(
                "PAYMENT_ALLOWED", resource_url="https://api.example.com", outcome="allowed"
            )
        buf.seek(0)
        lines = [ln for ln in buf.readlines() if ln.strip()]
        hmacs = [json.loads(ln)["prev_entry_hmac"] for ln in lines]
        # First is None, rest are distinct hex strings
        assert hmacs[0] is None
        assert hmacs[1] != hmacs[2]


class TestAuditLogFields:
    def test_emitted_event_has_all_required_fields(self):
        buf = io.StringIO()
        log = AuditLog(writer=StreamAuditWriter(buf), agent_id="test-agent")
        log.emit(
            "PII_REDACTED",
            resource_url="https://api.example.com/user/<EMAIL_ADDRESS>",
            amount_usd=0.05,
            network="base-sepolia",
            outcome="allowed",
            pii_entities_found=["EMAIL_ADDRESS"],
        )
        buf.seek(0)
        entry = json.loads(buf.readline())
        assert entry["event_type"] == "PII_REDACTED"
        assert entry["resource_url"] == "https://api.example.com/user/<EMAIL_ADDRESS>"
        assert entry["amount_usd"] == pytest.approx(0.05)
        assert entry["network"] == "base-sepolia"
        assert entry["agent_id"] == "test-agent"
        assert entry["outcome"] == "allowed"
        assert "EMAIL_ADDRESS" in entry["pii_entities_found"]

    def test_emit_returns_audit_event(self):
        log = AuditLog()
        event = log.emit(
            "PAYMENT_ALLOWED", resource_url="https://api.example.com", outcome="allowed"
        )
        assert isinstance(event, AuditEvent)
        assert event.event_type == "PAYMENT_ALLOWED"

    def test_agent_id_from_init_is_embedded(self):
        buf = io.StringIO()
        log = AuditLog(writer=StreamAuditWriter(buf), agent_id="my-agent")
        log.emit("PAYMENT_ALLOWED", resource_url="https://api.example.com", outcome="allowed")
        buf.seek(0)
        entry = json.loads(buf.readline())
        assert entry["agent_id"] == "my-agent"

    def test_agent_id_override_per_emit(self):
        buf = io.StringIO()
        log = AuditLog(writer=StreamAuditWriter(buf), agent_id="default-agent")
        log.emit(
            "PAYMENT_ALLOWED",
            resource_url="https://api.example.com",
            outcome="allowed",
            agent_id="override-agent",
        )
        buf.seek(0)
        entry = json.loads(buf.readline())
        assert entry["agent_id"] == "override-agent"
