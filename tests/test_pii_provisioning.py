"""Tests for the v0.7.0 provisioning-metadata PII entities.

These are opt-in (kept out of the default active set) so the SLO broker can redact
workload context before it reaches a third-party compute provider, without changing
default PII behaviour for existing callers.
"""

from __future__ import annotations

from presidio_x402.pii_filter import PROVISIONING_ENTITIES, PIIFilter


def _types(filt: PIIFilter, text: str) -> set[str]:
    _, entities = filt.scan_and_redact(text)
    return {e.entity_type for e in entities}


def test_provisioning_entities_are_off_by_default():
    # Default filter must not flag provisioning markers (back-compat).
    default = PIIFilter()
    found = _types(default, "run ml-training on CONFIDENTIAL data: SELECT x FROM accounts")
    assert "WORKLOAD_CLASS" not in found
    assert "DATA_CLASSIFICATION" not in found
    assert "QUERY_PATTERN" not in found


def test_data_classification_redacted_when_opted_in():
    filt = PIIFilter(entities=["DATA_CLASSIFICATION"])
    redacted, entities = filt.scan_and_redact("tier=CONFIDENTIAL workload")
    assert any(e.entity_type == "DATA_CLASSIFICATION" for e in entities)
    assert "CONFIDENTIAL" not in redacted


def test_workload_class_redacted_when_opted_in():
    assert "WORKLOAD_CLASS" in _types(
        PIIFilter(entities=["WORKLOAD_CLASS"]), "job: ml-training nightly"
    )


def test_query_pattern_redacted_when_opted_in():
    assert "QUERY_PATTERN" in _types(
        PIIFilter(entities=["QUERY_PATTERN"]),
        "SELECT ssn, balance FROM customers WHERE region='eu'",
    )


def test_provisioning_and_structural_compose():
    filt = PIIFilter(entities=["EMAIL_ADDRESS", "DATA_CLASSIFICATION"])
    redacted, entities = filt.scan_and_redact("owner alice@example.com tier SECRET")
    kinds = {e.entity_type for e in entities}
    assert kinds == {"EMAIL_ADDRESS", "DATA_CLASSIFICATION"}
    assert "alice@example.com" not in redacted and "SECRET" not in redacted


def test_full_provisioning_set_selectable_via_constant():
    filt = PIIFilter(entities=list(PROVISIONING_ENTITIES))
    found = _types(filt, "ml-training over RESTRICTED rows: DELETE FROM logs WHERE old")
    assert {"WORKLOAD_CLASS", "DATA_CLASSIFICATION", "QUERY_PATTERN"} <= found
