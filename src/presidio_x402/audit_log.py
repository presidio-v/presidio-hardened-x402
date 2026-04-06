"""Structured, tamper-evident audit logging for x402 payment events.

Emits JSON-L (newline-delimited JSON) audit events for every payment attempt.
Each entry is HMAC-SHA256 chained to the previous entry to detect tampering
or deletion of log entries.

.. note:: Chain-integrity scope

   The HMAC chain key (``_CHAIN_KEY``) is generated fresh on every process
   start. Tamper-detection via ``prev_entry_hmac`` is therefore only guaranteed
   **within a single process lifetime**. Entries written in separate runs are
   not chained together. For persistent cross-session integrity, persist the
   chain key to a restricted file and load it on startup.

Built-in writers:
  - :class:`NullAuditWriter` — discards events (useful for testing)
  - :class:`StreamAuditWriter` — writes JSON-L to any file-like object (stdout,
    file handle, etc.)
  - :class:`FileAuditWriter` — appends JSON-L to a file path

Usage::

    from presidio_x402.audit_log import AuditLog, FileAuditWriter
    from presidio_x402._types import AuditEvent

    log = AuditLog(writer=FileAuditWriter("/var/log/x402-audit.jsonl"))
    log.emit("PAYMENT_ALLOWED", event_data)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sys
import threading
from datetime import datetime, timezone
from typing import IO

from ._types import AuditEvent, AuditWriter

logger = logging.getLogger("presidio_x402.audit_log")

_CHAIN_KEY = secrets.token_bytes(32)


def _hmac_entry(content: str) -> str:
    return hmac.new(_CHAIN_KEY, content.encode(), hashlib.sha256).hexdigest()


def _event_to_dict(event: AuditEvent) -> dict:
    return {
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "resource_url": event.resource_url,
        "amount_usd": event.amount_usd,
        "network": event.network,
        "agent_id": event.agent_id,
        "outcome": event.outcome,
        "pii_entities_found": event.pii_entities_found,
        "policy_limit_usd": event.policy_limit_usd,
        "replay_fingerprint": event.replay_fingerprint,
        "error_message": event.error_message,
        "prev_entry_hmac": event.prev_entry_hmac,
    }


class NullAuditWriter:
    """Discards all audit events. Useful in tests or when auditing is disabled."""

    def write(self, event: AuditEvent) -> None:
        pass


class StreamAuditWriter:
    """Writes JSON-L audit events to a file-like stream (e.g., ``sys.stdout``)."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream or sys.stdout
        self._lock = threading.Lock()

    def write(self, event: AuditEvent) -> None:
        line = json.dumps(_event_to_dict(event), default=str)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


class FileAuditWriter:
    """Appends JSON-L audit events to a file path."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    def write(self, event: AuditEvent) -> None:
        line = json.dumps(_event_to_dict(event), default=str)
        with self._lock, open(self._path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


class AuditLog:
    """Emits tamper-evident, HMAC-chained JSON-L audit events.

    Each emitted entry contains a ``prev_entry_hmac`` field that is the HMAC of
    the previous entry's JSON content. This allows offline verification that no
    entries were deleted or reordered.

    Parameters
    ----------
    writer:
        An :class:`~presidio_x402._types.AuditWriter` instance. Defaults to
        :class:`NullAuditWriter` (no-op). Pass a :class:`StreamAuditWriter` or
        :class:`FileAuditWriter` for production use.
    agent_id:
        Optional agent identifier to embed in every event.
    """

    def __init__(
        self,
        writer: AuditWriter | None = None,
        *,
        agent_id: str | None = None,
    ) -> None:
        self._writer = writer or NullAuditWriter()
        self._agent_id = agent_id
        self._prev_hmac: str | None = None
        self._lock = threading.Lock()

    def emit(
        self,
        event_type: str,
        *,
        resource_url: str,
        amount_usd: float = 0.0,
        network: str = "",
        outcome: str,
        pii_entities_found: list[str] | None = None,
        policy_limit_usd: float | None = None,
        replay_fingerprint: str | None = None,
        error_message: str | None = None,
        agent_id: str | None = None,
    ) -> AuditEvent:
        """Create and emit an :class:`~presidio_x402._types.AuditEvent`.

        Returns the emitted event (useful for testing).
        """
        with self._lock:
            event = AuditEvent(
                timestamp=datetime.now(tz=timezone.utc),
                event_type=event_type,
                resource_url=resource_url,
                amount_usd=amount_usd,
                network=network,
                agent_id=agent_id or self._agent_id,
                outcome=outcome,
                pii_entities_found=pii_entities_found or [],
                policy_limit_usd=policy_limit_usd,
                replay_fingerprint=replay_fingerprint,
                error_message=error_message,
                prev_entry_hmac=self._prev_hmac,
            )
            try:
                self._writer.write(event)
            except Exception:
                logger.exception("Audit writer failed to write event")
            # Update chain regardless of write success to maintain chain integrity
            entry_json = json.dumps(_event_to_dict(event), default=str)
            self._prev_hmac = _hmac_entry(entry_json)

        return event
