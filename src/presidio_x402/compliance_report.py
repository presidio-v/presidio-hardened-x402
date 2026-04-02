"""SOC2/GDPR-friendly compliance report generator for x402 audit logs.

Reads a JSON-L audit log produced by :class:`~presidio_x402.audit_log.AuditLog`
and produces:

* A per-agent spending summary
* A PII detection summary (entity types seen, redaction vs. block counts)
* A data-subject reference report (GDPR Art. 17 support — which audit entries
  mention a given ``agent_id``)
* An HMAC-chain integrity report

Usage::

    from presidio_x402.compliance_report import ComplianceReport

    report = ComplianceReport.from_jsonl("/var/log/x402-audit.jsonl")
    print(report.summary())
    report.save_json("/tmp/compliance-2026-04.json")

    # GDPR data-subject lookup
    entries = report.entries_for_agent("agent-alice")
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._types import AuditEvent
from .audit_log import _CHAIN_KEY  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Entry parsing
# ---------------------------------------------------------------------------

def _parse_event(raw: dict[str, Any]) -> AuditEvent:
    from datetime import datetime, timezone

    ts_raw = raw.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_raw)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        ts = datetime.now(tz=timezone.utc)

    return AuditEvent(
        timestamp=ts,
        event_type=raw.get("event_type", "UNKNOWN"),
        resource_url=raw.get("resource_url", ""),
        amount_usd=float(raw.get("amount_usd", 0.0)),
        network=raw.get("network", ""),
        agent_id=raw.get("agent_id"),
        outcome=raw.get("outcome", ""),
        pii_entities_found=raw.get("pii_entities_found") or [],
        policy_limit_usd=raw.get("policy_limit_usd"),
        replay_fingerprint=raw.get("replay_fingerprint"),
        error_message=raw.get("error_message"),
        prev_entry_hmac=raw.get("prev_entry_hmac"),
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class AgentSummary:
    agent_id: str | None
    total_payments: int = 0
    total_usd: float = 0.0
    blocked_pii: int = 0
    blocked_policy: int = 0
    blocked_replay: int = 0
    pii_redacted: int = 0
    payment_errors: int = 0


@dataclass
class ComplianceReport:
    """Structured compliance report derived from an x402 audit log."""

    events: list[AuditEvent] = field(default_factory=list)
    """All parsed audit events in log order."""

    chain_ok: bool = True
    """True if every HMAC link in the chain is intact (no gaps or tampering detected).
    Always True for in-process logs (chain key is per-process); False for tampered files."""

    chain_warnings: list[str] = field(default_factory=list)
    """Human-readable warnings about chain integrity issues."""

    # ---------------------------------------------------------------------------
    # Constructors
    # ---------------------------------------------------------------------------

    @classmethod
    def from_jsonl(cls, path: str | Path) -> ComplianceReport:
        """Parse a JSON-L audit log file into a :class:`ComplianceReport`."""
        path = Path(path)
        raws: list[dict[str, Any]] = []
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raws.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON on line {lineno} of {path}: {exc}") from exc

        events = [_parse_event(r) for r in raws]
        report = cls(events=events)
        report._check_chain(raws)
        return report

    @classmethod
    def from_events(cls, events: list[AuditEvent]) -> ComplianceReport:
        """Build a report directly from a list of AuditEvent objects."""
        return cls(events=events)

    # ---------------------------------------------------------------------------
    # Chain integrity
    # ---------------------------------------------------------------------------

    def _check_chain(self, raws: list[dict[str, Any]]) -> None:
        """Verify HMAC chain integrity.

        Note: chain keys are per-process secrets, so cross-process verification
        will always fail. This check is meaningful only when the log was written
        by the same process (e.g., in integration tests or when verifying a
        single-session log).
        """
        prev_hmac: str | None = None
        for i, raw in enumerate(raws):
            declared_prev = raw.get("prev_entry_hmac")
            if declared_prev != prev_hmac:
                self.chain_ok = False
                self.chain_warnings.append(
                    f"Entry {i}: prev_entry_hmac mismatch "
                    f"(expected {prev_hmac!r}, got {declared_prev!r})"
                )
            # Compute expected HMAC of this entry for the next entry
            entry_json = json.dumps(dict(raw), default=str)
            prev_hmac = hmac.new(_CHAIN_KEY, entry_json.encode(), hashlib.sha256).hexdigest()

    # ---------------------------------------------------------------------------
    # Analysis helpers
    # ---------------------------------------------------------------------------

    def agent_summaries(self) -> dict[str | None, AgentSummary]:
        """Return per-agent spending and security summaries."""
        summaries: dict[str | None, AgentSummary] = {}
        for ev in self.events:
            aid = ev.agent_id
            if aid not in summaries:
                summaries[aid] = AgentSummary(agent_id=aid)
            s = summaries[aid]
            if ev.event_type == "PAYMENT_ALLOWED":
                s.total_payments += 1
                s.total_usd += ev.amount_usd
            elif ev.event_type == "PII_BLOCKED":
                s.blocked_pii += 1
            elif ev.event_type == "PII_REDACTED":
                s.pii_redacted += 1
            elif ev.event_type == "POLICY_BLOCKED":
                s.blocked_policy += 1
            elif ev.event_type == "REPLAY_BLOCKED":
                s.blocked_replay += 1
            elif ev.event_type == "PAYMENT_ERROR":
                s.payment_errors += 1
        return summaries

    def pii_entity_counts(self) -> dict[str, int]:
        """Count occurrences of each PII entity type across all events."""
        counts: dict[str, int] = {}
        for ev in self.events:
            for etype in ev.pii_entities_found:
                counts[etype] = counts.get(etype, 0) + 1
        return counts

    def entries_for_agent(self, agent_id: str) -> list[AuditEvent]:
        """Return all audit entries that reference *agent_id*.

        Supports GDPR Art. 17 data-subject access requests.
        """
        return [ev for ev in self.events if ev.agent_id == agent_id]

    def blocked_count(self) -> int:
        """Total number of blocked payment attempts (any block reason)."""
        return sum(
            1 for ev in self.events
            if ev.outcome == "blocked"
        )

    def allowed_count(self) -> int:
        """Total number of allowed payment attempts."""
        return sum(1 for ev in self.events if ev.outcome == "allowed")

    def total_spend_usd(self) -> float:
        """Total USD spent across all PAYMENT_ALLOWED events."""
        return sum(ev.amount_usd for ev in self.events if ev.event_type == "PAYMENT_ALLOWED")

    # ---------------------------------------------------------------------------
    # Output
    # ---------------------------------------------------------------------------

    def summary(self) -> str:
        """Human-readable text summary for console output."""
        agent_sums = self.agent_summaries()
        pii_counts = self.pii_entity_counts()

        lines = [
            "=== presidio-hardened-x402 Compliance Report ===",
            f"  Total events:   {len(self.events)}",
            f"  Payments allowed: {self.allowed_count()}  (${self.total_spend_usd():.4f} USD)",
            f"  Payments blocked: {self.blocked_count()}",
            f"  Chain integrity:  {'OK' if self.chain_ok else 'WARNINGS'}",
        ]
        if self.chain_warnings:
            for w in self.chain_warnings:
                lines.append(f"    ⚠ {w}")

        lines.append("\n--- PII entities detected ---")
        if pii_counts:
            for etype, count in sorted(pii_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {etype:<22} {count}")
        else:
            lines.append("  (none)")

        lines.append("\n--- Per-agent summary ---")
        for aid, s in sorted(agent_sums.items(), key=lambda x: -(x[1].total_usd)):
            lines.append(
                f"  agent={aid or '(none)'}  payments={s.total_payments}"
                f"  spent=${s.total_usd:.4f}"
                f"  pii_redacted={s.pii_redacted}"
                f"  blocked(pii={s.blocked_pii},policy={s.blocked_policy}"
                f",replay={s.blocked_replay})"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Structured dict for JSON serialization."""
        return {
            "total_events": len(self.events),
            "allowed": self.allowed_count(),
            "blocked": self.blocked_count(),
            "total_spend_usd": round(self.total_spend_usd(), 6),
            "chain_ok": self.chain_ok,
            "chain_warnings": self.chain_warnings,
            "pii_entity_counts": self.pii_entity_counts(),
            "agent_summaries": [
                {
                    "agent_id": s.agent_id,
                    "total_payments": s.total_payments,
                    "total_usd": round(s.total_usd, 6),
                    "pii_redacted": s.pii_redacted,
                    "blocked_pii": s.blocked_pii,
                    "blocked_policy": s.blocked_policy,
                    "blocked_replay": s.blocked_replay,
                    "payment_errors": s.payment_errors,
                }
                for s in self.agent_summaries().values()
            ],
        }

    def save_json(self, path: str | Path) -> None:
        """Write the report to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
