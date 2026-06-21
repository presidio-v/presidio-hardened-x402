"""Import-time dependency audit diagnostics."""

from __future__ import annotations

import importlib.metadata
import logging

import presidio_x402


def test_import_audit_reports_missing_low_and_unparseable_versions(monkeypatch, caplog):
    def fake_version(package: str) -> str:
        if package == "httpx":
            raise importlib.metadata.PackageNotFoundError(package)
        if package == "presidio-analyzer":
            return "0.1"
        if package == "cryptography":
            return "not-a-version"
        return "9.9.9"

    monkeypatch.setattr(importlib.metadata, "version", fake_version)

    with caplog.at_level(logging.DEBUG, logger="presidio_x402"):
        presidio_x402._on_import_audit()

    messages = [record.getMessage() for record in caplog.records]
    assert any("httpx is not installed" in message for message in messages)
    assert any(
        "presidio-analyzer==0.1 is below minimum-safe version" in message for message in messages
    )
    assert any(
        "Dependency version unparseable: cryptography==not-a-version" in message
        for message in messages
    )
    assert any("Dependency OK: langchain-core==9.9.9" in message for message in messages)


def test_import_audit_logs_all_clear_when_dependencies_meet_floors(monkeypatch, caplog):
    monkeypatch.setattr(importlib.metadata, "version", lambda package: "99.0.0")

    with caplog.at_level(logging.INFO, logger="presidio_x402"):
        presidio_x402._on_import_audit()

    assert any(
        "[PRESIDIO AUDIT] All x402 dependencies present at minimum-safe versions"
        in record.getMessage()
        for record in caplog.records
    )


def test_import_audit_fails_closed_on_unexpected_metadata_error(monkeypatch, caplog):
    def broken_version(package: str) -> str:
        raise RuntimeError(f"metadata backend failed for {package}")

    monkeypatch.setattr(importlib.metadata, "version", broken_version)

    with caplog.at_level(logging.DEBUG, logger="presidio_x402"):
        presidio_x402._on_import_audit()

    assert any("Dependency audit skipped" in record.getMessage() for record in caplog.records)
