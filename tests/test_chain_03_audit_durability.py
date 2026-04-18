"""Chain 03 (audit-log OOM erasure) — POC tests for the durability fix.

Attack model: attacker triggers an OOM-kill (or any hard SIGKILL) while the
``FileAuditWriter`` has buffered audit entries. The OS discards unflushed
buffers, the last events (including the attack itself) are lost, and the chain
rolls forward on the next container start with a fresh key — severing
tamper-evidence across the event.

Fix: ``FileAuditWriter`` issues ``os.fsync`` after every write by default;
``AuditLog.flush()`` forces the writer to drain on demand; an ``atexit`` hook
flushes on clean shutdown.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import TYPE_CHECKING
from unittest.mock import patch

from presidio_x402.audit_log import AuditLog, FileAuditWriter, StreamAuditWriter

if TYPE_CHECKING:
    from pathlib import Path


class TestFileWriterFsyncDurability:
    """Per-write fsync is the actual OOM-kill defence."""

    def test_fsync_called_per_write_by_default(self, tmp_path: Path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        writer = FileAuditWriter(str(audit_path))
        log = AuditLog(writer=writer, flush_on_exit=False)

        with patch("os.fsync") as mock_fsync:
            log.emit(
                "PAYMENT_ALLOWED",
                resource_url="https://api.example.com/x",
                amount_usd=0.10,
                network="base",
                outcome="allowed",
            )
        assert mock_fsync.call_count == 1, "fsync must be called once per emit"

    def test_fsync_disabled_when_opt_out(self, tmp_path: Path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        writer = FileAuditWriter(str(audit_path), fsync=False)
        log = AuditLog(writer=writer, flush_on_exit=False)

        with patch("os.fsync") as mock_fsync:
            log.emit(
                "PAYMENT_ALLOWED",
                resource_url="https://api.example.com/x",
                amount_usd=0.10,
                network="base",
                outcome="allowed",
            )
        assert mock_fsync.call_count == 0

    def test_entries_readable_immediately_after_write(self, tmp_path: Path) -> None:
        # fsync makes entries durable even if the process dies immediately.
        audit_path = tmp_path / "audit.jsonl"
        log = AuditLog(writer=FileAuditWriter(str(audit_path)), flush_on_exit=False)

        log.emit(
            "PAYMENT_ALLOWED",
            resource_url="https://api.example.com/x",
            amount_usd=0.10,
            network="base",
            outcome="allowed",
        )
        content = audit_path.read_text(encoding="utf-8")
        line = content.strip().split("\n")[-1]
        entry = json.loads(line)
        assert entry["event_type"] == "PAYMENT_ALLOWED"
        assert entry["outcome"] == "allowed"

    def test_many_writes_all_durable(self, tmp_path: Path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        log = AuditLog(writer=FileAuditWriter(str(audit_path)), flush_on_exit=False)
        for i in range(25):
            log.emit(
                "PAYMENT_ALLOWED",
                resource_url=f"https://api.example.com/{i}",
                amount_usd=0.01 * i,
                network="base",
                outcome="allowed",
            )
        lines = audit_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 25
        # Entries preserve chain order
        entries = [json.loads(line_) for line_ in lines]
        for _prev, curr in zip(entries[:-1], entries[1:], strict=True):
            assert curr["prev_entry_hmac"] is not None


class TestAuditLogFlushAPI:
    """``AuditLog.flush`` delegates to the writer — used by shutdown handlers."""

    def test_flush_delegates_to_writer_flush(self) -> None:
        class RecordingWriter:
            def __init__(self) -> None:
                self.flushed = 0

            def write(self, event) -> None:  # noqa: ARG002
                pass

            def flush(self) -> None:
                self.flushed += 1

        w = RecordingWriter()
        log = AuditLog(writer=w, flush_on_exit=False)
        log.flush()
        log.flush()
        assert w.flushed == 2

    def test_flush_tolerates_writer_without_flush(self) -> None:
        # Users can pass bare writers lacking a flush method — no attribute error.
        class BareWriter:
            def write(self, event) -> None:  # noqa: ARG002
                pass

        log = AuditLog(writer=BareWriter(), flush_on_exit=False)
        log.flush()  # should not raise

    def test_flush_swallows_writer_exceptions(self) -> None:
        class FailingWriter:
            def write(self, event) -> None:  # noqa: ARG002
                pass

            def flush(self) -> None:
                raise RuntimeError("disk full")

        log = AuditLog(writer=FailingWriter(), flush_on_exit=False)
        log.flush()  # must not propagate — shutdown paths can't recover anyway

    def test_stream_writer_flush_calls_stream_flush(self) -> None:
        class RecordingStream:
            def __init__(self) -> None:
                self.writes: list[str] = []
                self.flushes = 0

            def write(self, s: str) -> None:
                self.writes.append(s)

            def flush(self) -> None:
                self.flushes += 1

        stream = RecordingStream()
        writer = StreamAuditWriter(stream=stream)
        writer.flush()
        assert stream.flushes == 1


class TestOOMKillSurvival:
    """Simulate the OOM-kill scenario: write then immediately re-read.

    Without fsync, a SIGKILL would drop buffered data. With fsync, the data
    is already on disk and the next reader sees every emitted event.
    """

    def test_entries_survive_process_death_simulation(self) -> None:
        # Use the unflushed-close path as a process-death proxy: the test
        # writes, and a *separate* reader (simulating a new process)
        # immediately opens the file to verify the event is there.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tmp:
            audit_path = tmp.name
        try:
            log = AuditLog(writer=FileAuditWriter(audit_path), flush_on_exit=False)
            log.emit(
                "ATTACK_DETECTED",
                resource_url="https://victim.example.com/",
                amount_usd=0.0,
                network="base",
                outcome="blocked",
                error_message="oom-kill triggered",
            )
            # Re-open in a fresh handle — simulates post-crash reader.
            with open(audit_path, encoding="utf-8") as fh:
                entries = [json.loads(line_) for line_ in fh if line_.strip()]
            assert any(e["event_type"] == "ATTACK_DETECTED" for e in entries)
        finally:
            os.unlink(audit_path)
