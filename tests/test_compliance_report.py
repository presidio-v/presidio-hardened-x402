"""Tests for compliance_report.py."""

from __future__ import annotations

import io
import json
import tempfile

import pytest

from presidio_x402.audit_log import AuditLog, StreamAuditWriter
from presidio_x402.compliance_report import ComplianceReport


def _build_log(events: list[dict]) -> str:
    """Build a JSON-L string from a list of event dicts."""
    return "\n".join(json.dumps(e) for e in events) + "\n"


def _make_event(**overrides) -> dict:
    base = {
        "timestamp": "2026-04-01T12:00:00+00:00",
        "event_type": "PAYMENT_ALLOWED",
        "resource_url": "https://api.example.com/data",
        "amount_usd": 0.01,
        "network": "base-mainnet",
        "agent_id": "agent-1",
        "outcome": "allowed",
        "pii_entities_found": [],
        "policy_limit_usd": None,
        "replay_fingerprint": None,
        "error_message": None,
        "prev_entry_hmac": None,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# from_events (no file I/O)
# ---------------------------------------------------------------------------

class TestFromEvents:
    def test_empty(self):
        report = ComplianceReport.from_events([])
        assert report.allowed_count() == 0
        assert report.blocked_count() == 0
        assert report.total_spend_usd() == 0.0

    def test_allowed_spend(self):
        from presidio_x402.compliance_report import _parse_event
        ev1 = _parse_event(_make_event(amount_usd=0.05))
        ev2 = _parse_event(_make_event(amount_usd=0.10))
        report = ComplianceReport.from_events([ev1, ev2])
        assert report.allowed_count() == 2
        assert abs(report.total_spend_usd() - 0.15) < 1e-9

    def test_blocked_events(self):
        from presidio_x402.compliance_report import _parse_event
        pii_blocked = _parse_event(_make_event(
            event_type="PII_BLOCKED", outcome="blocked", amount_usd=0.0,
        ))
        policy_blocked = _parse_event(_make_event(
            event_type="POLICY_BLOCKED", outcome="blocked", amount_usd=0.0,
        ))
        report = ComplianceReport.from_events([pii_blocked, policy_blocked])
        assert report.blocked_count() == 2
        assert report.allowed_count() == 0

    def test_pii_entity_counts(self):
        from presidio_x402.compliance_report import _parse_event
        ev1 = _parse_event(_make_event(pii_entities_found=["EMAIL_ADDRESS", "US_SSN"]))
        ev2 = _parse_event(_make_event(pii_entities_found=["EMAIL_ADDRESS"]))
        report = ComplianceReport.from_events([ev1, ev2])
        counts = report.pii_entity_counts()
        assert counts["EMAIL_ADDRESS"] == 2
        assert counts["US_SSN"] == 1

    def test_entries_for_agent(self):
        from presidio_x402.compliance_report import _parse_event
        a1 = _parse_event(_make_event(agent_id="alice"))
        a2 = _parse_event(_make_event(agent_id="alice"))
        b1 = _parse_event(_make_event(agent_id="bob"))
        report = ComplianceReport.from_events([a1, a2, b1])
        alice_events = report.entries_for_agent("alice")
        assert len(alice_events) == 2
        assert all(e.agent_id == "alice" for e in alice_events)

    def test_agent_summaries(self):
        from presidio_x402.compliance_report import _parse_event
        payment = _parse_event(_make_event(agent_id="alice", amount_usd=0.05))
        redacted = _parse_event(_make_event(
            agent_id="alice", event_type="PII_REDACTED", outcome="allowed", amount_usd=0.0,
        ))
        blocked = _parse_event(_make_event(
            agent_id="alice", event_type="POLICY_BLOCKED", outcome="blocked", amount_usd=0.0,
        ))
        report = ComplianceReport.from_events([payment, redacted, blocked])
        sums = report.agent_summaries()
        alice = sums["alice"]
        assert alice.total_payments == 1
        assert abs(alice.total_usd - 0.05) < 1e-9
        assert alice.pii_redacted == 1
        assert alice.blocked_policy == 1

    def test_summary_str(self):
        report = ComplianceReport.from_events([])
        s = report.summary()
        assert "Compliance Report" in s
        assert "allowed" in s.lower()


# ---------------------------------------------------------------------------
# from_jsonl (file I/O)
# ---------------------------------------------------------------------------

class TestFromJsonl:
    def test_round_trip_via_audit_log(self):
        """Write events via AuditLog, read via ComplianceReport."""
        buf = io.StringIO()
        log = AuditLog(writer=StreamAuditWriter(buf), agent_id="test-agent")
        log.emit("PAYMENT_ALLOWED", resource_url="https://api.example.com/v1", outcome="allowed",
                 amount_usd=0.03, network="base-mainnet")
        log.emit("PII_BLOCKED", resource_url="https://api.example.com/v1", outcome="blocked",
                 pii_entities_found=["EMAIL_ADDRESS"])

        jsonl = buf.getvalue()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(jsonl)
            tmp_path = f.name

        report = ComplianceReport.from_jsonl(tmp_path)
        assert len(report.events) == 2
        assert report.allowed_count() == 1
        assert report.blocked_count() == 1
        assert abs(report.total_spend_usd() - 0.03) < 1e-9

    def test_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"valid": true}\nnot valid json\n')
            tmp_path = f.name
        with pytest.raises(ValueError, match="Invalid JSON"):
            ComplianceReport.from_jsonl(tmp_path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            tmp_path = f.name
        report = ComplianceReport.from_jsonl(tmp_path)
        assert len(report.events) == 0

    def test_blank_lines_ignored(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("\n" + json.dumps(_make_event()) + "\n\n")
            tmp_path = f.name
        report = ComplianceReport.from_jsonl(tmp_path)
        assert len(report.events) == 1

    def test_save_json(self, tmp_path):
        report = ComplianceReport.from_events([])
        out = tmp_path / "report.json"
        report.save_json(out)
        data = json.loads(out.read_text())
        assert data["total_events"] == 0
        assert "chain_ok" in data

    def test_to_dict_structure(self):
        report = ComplianceReport.from_events([])
        d = report.to_dict()
        for key in ("total_events", "allowed", "blocked", "total_spend_usd",
                    "chain_ok", "chain_warnings", "pii_entity_counts", "agent_summaries"):
            assert key in d

    def test_parse_event_invalid_timestamp(self):
        """_parse_event should fall back to now() for unparseable timestamps."""
        from presidio_x402.compliance_report import _parse_event
        ev = _parse_event(_make_event(timestamp="not-a-date"))
        assert ev.timestamp is not None

    def test_parse_event_naive_timestamp(self):
        """_parse_event should make naive timestamps timezone-aware."""
        from presidio_x402.compliance_report import _parse_event
        ev = _parse_event(_make_event(timestamp="2026-04-01T12:00:00"))
        assert ev.timestamp.tzinfo is not None

    def test_replay_and_error_agent_summary(self):
        from presidio_x402.compliance_report import _parse_event
        replay = _parse_event(_make_event(
            agent_id="agent-1", event_type="REPLAY_BLOCKED", outcome="blocked", amount_usd=0.0,
        ))
        error = _parse_event(_make_event(
            agent_id="agent-1", event_type="PAYMENT_ERROR", outcome="blocked", amount_usd=0.0,
        ))
        report = ComplianceReport.from_events([replay, error])
        sums = report.agent_summaries()
        s = sums["agent-1"]
        assert s.blocked_replay == 1
        assert s.payment_errors == 1

    def test_summary_with_pii_events(self):
        from presidio_x402.compliance_report import _parse_event
        ev = _parse_event(_make_event(pii_entities_found=["PERSON", "EMAIL_ADDRESS"]))
        report = ComplianceReport.from_events([ev])
        s = report.summary()
        assert "PERSON" in s or "EMAIL_ADDRESS" in s

    def test_entries_for_agent_none(self):
        from presidio_x402.compliance_report import _parse_event
        ev = _parse_event(_make_event(agent_id=None))
        report = ComplianceReport.from_events([ev])
        assert len(report.entries_for_agent("nobody")) == 0
