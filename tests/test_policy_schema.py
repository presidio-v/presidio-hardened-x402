"""Tests for the policy-as-code JSON Schema validator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from presidio_x402.x402_policy_schema import (
    PolicyValidationError,
    load_policy_file,
    validate_policy,
)

# ---------------------------------------------------------------------------
# validate_policy — valid inputs
# ---------------------------------------------------------------------------


class TestValidatePolicyValid:
    def test_empty_dict_is_valid(self):
        """An empty dict should be valid — all fields are optional."""
        validate_policy({})

    def test_full_policy_is_valid(self):
        validate_policy(
            {
                "max_per_call_usd": 0.10,
                "daily_limit_usd": 5.0,
                "per_endpoint": {"https://api.example.com": 1.0},
                "window_seconds": 86400,
                "agent_id": "agent-v1",
            }
        )

    def test_per_endpoint_empty_is_valid(self):
        validate_policy({"per_endpoint": {}})

    def test_zero_limits_are_valid(self):
        validate_policy({"max_per_call_usd": 0, "daily_limit_usd": 0})

    def test_mpa_config_is_valid(self):
        validate_policy(
            {
                "max_per_call_usd": 0.10,
                "mpa": {
                    "threshold": 2,
                    "min_amount_usd": 1.00,
                    "timeout_seconds": 30,
                    "approvers": [
                        {
                            "approver_id": "alice",
                            "mode": "webhook",
                            "webhook_url": "https://a.internal",
                        },
                        {
                            "approver_id": "bob",
                            "mode": "webhook",
                            "webhook_url": "https://b.internal",
                        },
                        {"approver_id": "charlie", "mode": "crypto"},
                    ],
                },
            }
        )

    def test_mpa_minimal_is_valid(self):
        validate_policy(
            {
                "mpa": {
                    "threshold": 1,
                    "approvers": [{"approver_id": "alice", "mode": "webhook"}],
                }
            }
        )


# ---------------------------------------------------------------------------
# validate_policy — invalid inputs
# ---------------------------------------------------------------------------


class TestValidatePolicyInvalid:
    def test_negative_max_per_call_raises(self):
        with pytest.raises(PolicyValidationError, match="max_per_call_usd"):
            validate_policy({"max_per_call_usd": -0.01})

    def test_negative_daily_limit_raises(self):
        with pytest.raises(PolicyValidationError, match="daily_limit_usd"):
            validate_policy({"daily_limit_usd": -1.0})

    def test_window_seconds_zero_raises(self):
        with pytest.raises(PolicyValidationError, match="window_seconds"):
            validate_policy({"window_seconds": 0})

    def test_window_seconds_string_raises(self):
        with pytest.raises(PolicyValidationError, match="window_seconds"):
            validate_policy({"window_seconds": "86400"})

    def test_additional_properties_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"unknown_field": 123})

    def test_mpa_missing_threshold_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"mpa": {"approvers": [{"approver_id": "alice", "mode": "webhook"}]}})

    def test_mpa_missing_approvers_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"mpa": {"threshold": 1}})

    def test_mpa_empty_approvers_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"mpa": {"threshold": 1, "approvers": []}})

    def test_mpa_invalid_mode_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy(
                {
                    "mpa": {
                        "threshold": 1,
                        "approvers": [{"approver_id": "alice", "mode": "invalid"}],
                    }
                }
            )

    def test_per_endpoint_non_numeric_value_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"per_endpoint": {"https://api.example.com": "not-a-number"}})

    def test_policy_validation_error_has_errors_list(self):
        with pytest.raises(PolicyValidationError) as exc_info:
            validate_policy({"max_per_call_usd": -1, "daily_limit_usd": -1})
        assert len(exc_info.value.errors) >= 2


# ---------------------------------------------------------------------------
# load_policy_file — JSON
# ---------------------------------------------------------------------------


class TestLoadPolicyFileJSON:
    def test_load_valid_json(self):
        data = {"max_per_call_usd": 0.10, "daily_limit_usd": 5.0, "agent_id": "agent-1"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        policy = load_policy_file(path)
        assert policy.max_per_call_usd == pytest.approx(0.10)
        assert policy.daily_limit_usd == pytest.approx(5.0)
        assert policy.agent_id == "agent-1"

    def test_invalid_json_raises(self):
        data = {"max_per_call_usd": -1}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        with pytest.raises(PolicyValidationError):
            load_policy_file(path)

    def test_json_with_mpa_strips_mpa_key(self):
        """MPA config is validated but not passed to PolicyConfig."""
        data = {
            "max_per_call_usd": 0.05,
            "mpa": {
                "threshold": 1,
                "approvers": [{"approver_id": "alice", "mode": "webhook"}],
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name

        policy = load_policy_file(path)
        assert policy.max_per_call_usd == pytest.approx(0.05)


# ---------------------------------------------------------------------------
# load_policy_file — TOML
# ---------------------------------------------------------------------------


class TestLoadPolicyFileTOML:
    def test_load_valid_toml(self):
        toml_content = (
            "max_per_call_usd = 0.10\n"
            "daily_limit_usd = 5.0\n"
            "window_seconds = 86400\n"
            'agent_id = "toml-agent"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            path = f.name

        policy = load_policy_file(path)
        assert policy.max_per_call_usd == pytest.approx(0.10)
        assert policy.agent_id == "toml-agent"

    def test_invalid_toml_raises(self):
        toml_content = "max_per_call_usd = -0.50\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            path = f.name

        with pytest.raises(PolicyValidationError):
            load_policy_file(path)

    def test_toml_per_endpoint(self):
        toml_content = 'max_per_call_usd = 0.10\n[per_endpoint]\n"https://premium-api.io" = 0.50\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            path = f.name

        policy = load_policy_file(path)
        assert "https://premium-api.io" in policy.per_endpoint
        assert policy.per_endpoint["https://premium-api.io"] == pytest.approx(0.50)


# ---------------------------------------------------------------------------
# load_policy_file — unsupported format
# ---------------------------------------------------------------------------


class TestLoadPolicyFileFormat:
    def test_unsupported_extension_raises(self):
        with pytest.raises(ValueError, match="Unsupported policy file format"):
            load_policy_file("policy.yaml")

    def test_path_object_is_accepted(self):
        data = {"max_per_call_usd": 0.05}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = Path(f.name)

        policy = load_policy_file(path)
        assert policy.max_per_call_usd == pytest.approx(0.05)


# ---------------------------------------------------------------------------
# Schema file exists and is valid JSON
# ---------------------------------------------------------------------------


class TestSchemaFile:
    def test_schema_file_exists(self):
        import presidio_x402

        schema_path = Path(presidio_x402.__file__).parent / "x402-policy-schema.json"
        assert schema_path.exists(), f"Schema file not found: {schema_path}"

    def test_schema_file_is_valid_json(self):
        import presidio_x402

        schema_path = Path(presidio_x402.__file__).parent / "x402-policy-schema.json"
        with schema_path.open() as f:
            schema = json.load(f)
        assert schema.get("title") == "X402PolicyConfig"
        assert "$schema" in schema
