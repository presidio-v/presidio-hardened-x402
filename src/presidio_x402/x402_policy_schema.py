"""Policy-as-code schema validator for x402 spending policies.

Validates policy configuration dicts against ``x402-policy-schema.json``
(IETF draft candidate) and loads :class:`~presidio_x402.policy_engine.PolicyConfig`
from TOML or JSON policy files.

Requires the ``schema`` optional extra for validation::

    pip install "presidio-hardened-x402[schema]"

Usage::

    from presidio_x402.x402_policy_schema import validate_policy, load_policy_file

    # Validate a dict in-memory
    validate_policy({
        "max_per_call_usd": 0.10,
        "daily_limit_usd": 5.0,
        "agent_id": "my-agent",
    })

    # Load and validate from a TOML file
    policy = load_policy_file("policy.toml")

    # Load and validate from a JSON file
    policy = load_policy_file("policy.json")

Example TOML policy file::

    max_per_call_usd = 0.10
    daily_limit_usd  = 5.00
    window_seconds   = 86400
    agent_id         = "my-agent"

    [per_endpoint]
    "https://premium-api.io" = 0.50

    [mpa]
    threshold      = 2
    min_amount_usd = 1.00
    timeout_seconds = 30

    [[mpa.approvers]]
    approver_id = "alice"
    mode        = "webhook"
    webhook_url = "https://approvals.internal/alice"

    [[mpa.approvers]]
    approver_id = "bob"
    mode        = "webhook"
    webhook_url = "https://approvals.internal/bob"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .policy_engine import PolicyConfig

_SCHEMA: dict | None = None


def _get_schema() -> dict:
    """Load the bundled x402-policy-schema.json (cached after first read)."""
    global _SCHEMA
    if _SCHEMA is None:
        schema_path = Path(__file__).parent / "x402-policy-schema.json"
        with schema_path.open() as f:
            _SCHEMA = json.load(f)
    return _SCHEMA


class PolicyValidationError(ValueError):
    """Raised when a policy dict fails JSON Schema validation.

    Attributes
    ----------
    errors:
        List of human-readable error strings (one per validation failure).
    """

    def __init__(self, message: str, errors: list[str]) -> None:
        super().__init__(message)
        self.errors = errors


def validate_policy(data: dict[str, Any]) -> None:
    """Validate a policy dict against the x402 policy JSON Schema.

    Parameters
    ----------
    data:
        Policy configuration dict (e.g., loaded from TOML or JSON).

    Raises
    ------
    PolicyValidationError
        If the dict does not conform to the schema.
    ImportError
        If ``jsonschema`` is not installed.
    """
    try:
        import jsonschema
        import jsonschema.validators
    except ImportError as exc:
        raise ImportError(
            "jsonschema is required for policy schema validation. "
            "Install with: pip install 'presidio-hardened-x402[schema]'"
        ) from exc

    schema = _get_schema()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    if errors:
        messages = [
            f"  - {'.'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
            for e in errors
        ]
        raise PolicyValidationError(
            f"Policy validation failed ({len(errors)} error(s)):\n" + "\n".join(messages),
            errors=[
                f"{'.'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
                for e in errors
            ],
        )


def load_policy_file(path: str | Path) -> PolicyConfig:
    """Load and validate a policy from a TOML or JSON file.

    Parameters
    ----------
    path:
        Path to a ``.toml`` or ``.json`` policy file.

    Returns
    -------
    PolicyConfig
        Validated and parsed policy configuration. The ``mpa`` key (if present)
        is consumed during validation but not reflected in :class:`PolicyConfig`
        directly — pass the ``mpa_engine`` parameter to :class:`HardenedX402Client`
        separately.

    Raises
    ------
    PolicyValidationError
        If the file does not conform to the schema.
    ValueError
        If the file extension is not ``.toml`` or ``.json``.
    ImportError
        If ``jsonschema`` or (for TOML) ``tomllib``/``tomli`` is not installed.
    """
    path = Path(path)
    if path.suffix == ".toml":
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomllib  # type: ignore[no-redef]
            except ImportError:
                try:
                    import tomli as tomllib  # type: ignore[no-redef]
                except ImportError as exc:
                    raise ImportError(
                        "tomllib (Python 3.11+) or tomli is required for TOML policy files. "
                        "Install with: pip install tomli"
                    ) from exc
        with path.open("rb") as f:
            data: dict[str, Any] = tomllib.load(f)
    elif path.suffix == ".json":
        with path.open() as f:
            data = json.load(f)
    else:
        raise ValueError(f"Unsupported policy file format: {path.suffix!r}. Use .toml or .json")

    validate_policy(data)
    # Strip MPA config before constructing PolicyConfig (handled separately via MPAEngine)
    policy_data = {k: v for k, v in data.items() if k != "mpa"}
    return PolicyConfig.from_dict(policy_data)
