"""Loading and validation of endpoint definitions.

Endpoint definitions live in ``config/endpoints.json``. Each entry
describes one API resource to test: its path template, HTTP method,
expected authorization policy and the response fields used during
analysis.

Field lists (identity, ownership, resource-id and sensitive fields)
are PROVISIONAL expectations. They are hints for the analyser, not
ground truth, and must be verified against real responses during
integration testing in the Kali lab.

Adding a new endpoint requires only a new JSON entry; the engine,
analyser and reporting layers work from these definitions and do not
need code changes.
"""

import json
from dataclasses import dataclass
from pathlib import Path

ALLOWED_METHODS = ("GET",)
DECISIONS = ("ALLOW", "DENY")
REQUIRED_KEYS = (
    "endpoint_id",
    "name",
    "method",
    "path",
    "requires_authentication",
    "resource_type",
    "resource_id_variable",
    "policy",
)
FIELD_LIST_KEYS = (
    "identity_fields",
    "ownership_fields",
    "resource_id_fields",
    "sensitive_fields",
)


class EndpointConfigError(Exception):
    """Raised when endpoints.json is missing, unreadable or invalid."""


@dataclass(frozen=True)
class EndpointPolicy:
    """Expected authorization behaviour for one endpoint.

    Values are "ALLOW" or "DENY" and are compared by the classifier
    against what actually happened - never hardcoded in code.
    """

    own_resource: str
    cross_account: str
    unauthenticated: str


@dataclass(frozen=True)
class EndpointDefinition:
    """One testable API endpoint."""

    endpoint_id: str
    name: str
    method: str
    path: str
    requires_authentication: bool
    resource_type: str
    resource_id_variable: str
    policy: EndpointPolicy
    identity_fields: tuple = ()
    ownership_fields: tuple = ()
    resource_id_fields: tuple = ()
    sensitive_fields: tuple = ()


def _validate_decision(endpoint_id: str, key: str, value) -> str:
    if not isinstance(value, str) or value.upper() not in DECISIONS:
        raise EndpointConfigError(
            f"Endpoint {endpoint_id!r}: policy.{key} must be one of "
            f"{DECISIONS}, got {value!r}."
        )
    return value.upper()


def _validate_field_list(endpoint_id: str, key: str, value) -> tuple:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise EndpointConfigError(
            f"Endpoint {endpoint_id!r}: {key} must be a list of field names."
        )
    return tuple(value)


def parse_endpoint(entry: dict) -> EndpointDefinition:
    """Validate one endpoints.json entry and build a definition object."""
    if not isinstance(entry, dict):
        raise EndpointConfigError("Each endpoint entry must be a JSON object.")

    missing = [key for key in REQUIRED_KEYS if key not in entry]
    if missing:
        raise EndpointConfigError(
            f"Endpoint entry is missing required keys: {', '.join(missing)}."
        )

    endpoint_id = entry["endpoint_id"]
    if not isinstance(endpoint_id, str) or not endpoint_id:
        raise EndpointConfigError("Endpoint 'endpoint_id' must be a non-empty string.")

    method = entry["method"]
    if method.upper() not in ALLOWED_METHODS:
        raise EndpointConfigError(
            f"Endpoint {endpoint_id!r}: method {method!r} is not supported. "
            f"Supported methods: {', '.join(ALLOWED_METHODS)}."
        )

    path = entry["path"]
    if not isinstance(path, str) or not path.startswith("/"):
        raise EndpointConfigError(
            f"Endpoint {endpoint_id!r}: 'path' must start with '/'."
        )

    resource_id_variable = entry["resource_id_variable"]
    placeholder = "{" + resource_id_variable + "}"
    if placeholder not in path:
        raise EndpointConfigError(
            f"Endpoint {endpoint_id!r}: path must contain the placeholder "
            f"{placeholder!r} for 'resource_id_variable'."
        )
    # Stray braces would break path formatting at request time.
    if path.count("{") != 1 or path.count("}") != 1:
        raise EndpointConfigError(
            f"Endpoint {endpoint_id!r}: path contains unexpected braces; "
            f"only the {placeholder!r} placeholder is allowed."
        )

    raw_policy = entry["policy"]
    if not isinstance(raw_policy, dict):
        raise EndpointConfigError(
            f"Endpoint {endpoint_id!r}: 'policy' must be an object with "
            "own_resource, cross_account and unauthenticated decisions."
        )
    for key in ("own_resource", "cross_account", "unauthenticated"):
        if key not in raw_policy:
            raise EndpointConfigError(
                f"Endpoint {endpoint_id!r}: policy is missing {key!r}."
            )
    policy = EndpointPolicy(
        own_resource=_validate_decision(endpoint_id, "own_resource", raw_policy["own_resource"]),
        cross_account=_validate_decision(endpoint_id, "cross_account", raw_policy["cross_account"]),
        unauthenticated=_validate_decision(endpoint_id, "unauthenticated", raw_policy["unauthenticated"]),
    )

    return EndpointDefinition(
        endpoint_id=endpoint_id,
        name=entry["name"],
        method=method.upper(),
        path=path,
        requires_authentication=bool(entry["requires_authentication"]),
        resource_type=entry["resource_type"],
        resource_id_variable=resource_id_variable,
        policy=policy,
        identity_fields=_validate_field_list(endpoint_id, "identity_fields", entry.get("identity_fields")),
        ownership_fields=_validate_field_list(endpoint_id, "ownership_fields", entry.get("ownership_fields")),
        resource_id_fields=_validate_field_list(endpoint_id, "resource_id_fields", entry.get("resource_id_fields")),
        sensitive_fields=_validate_field_list(endpoint_id, "sensitive_fields", entry.get("sensitive_fields")),
    )


def load_endpoints(config_path: Path) -> list[EndpointDefinition]:
    """Load and validate all endpoint definitions from a JSON file.

    Raises:
        EndpointConfigError: if the file is missing, not valid JSON or
            contains invalid entries.
    """
    if not config_path.is_file():
        raise EndpointConfigError(
            f"Endpoint configuration file not found: {config_path}"
        )

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise EndpointConfigError(
            f"Endpoint configuration is not valid JSON: {exc}"
        ) from None

    entries = raw.get("endpoints") if isinstance(raw, dict) else None
    if not isinstance(entries, list) or not entries:
        raise EndpointConfigError(
            "Endpoint configuration must contain a non-empty 'endpoints' list."
        )

    endpoints = [parse_endpoint(entry) for entry in entries]

    seen = set()
    for endpoint in endpoints:
        if endpoint.endpoint_id in seen:
            raise EndpointConfigError(
                f"Duplicate endpoint_id {endpoint.endpoint_id!r} in configuration."
            )
        seen.add(endpoint.endpoint_id)

    return endpoints
