"""Secure runtime configuration for APIShield.

Loads environment variables from the process environment and, when
present, a ``.env`` file located in the project root. Only variable
NAMES are reported in error messages; values (tokens, resource IDs)
are never logged, printed or stored.
"""

import os
from dataclasses import dataclass
from pathlib import Path

# Project root: the directory that contains main.py. All runtime paths
# are resolved relative to it so the project stays portable between the
# development machine and the Kali VM.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

ENV_FILE = PROJECT_ROOT / ".env"

REQUIRED_VARIABLES = (
    "APISHIELD_BASE_URL",
    "APISHIELD_USER_A_TOKEN",
    "APISHIELD_USER_B_TOKEN",
    "APISHIELD_USER_A_VEHICLE_ID",
    "APISHIELD_USER_B_VEHICLE_ID",
)


class ConfigurationError(Exception):
    """Raised when the runtime configuration is missing or unusable."""


@dataclass(frozen=True)
class RuntimeConfig:
    """Validated runtime configuration.

    Attributes hold live secret values (tokens, resource identifiers).
    The dataclass defines a custom ``__repr__`` so secrets can never
    leak through logs, tracebacks or debug output.
    """

    base_url: str
    user_a_token: str
    user_b_token: str
    user_a_vehicle_id: str
    user_b_vehicle_id: str

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "RuntimeConfig(<secrets withheld>)"


def parse_env_file(path: Path) -> dict:
    """Parse a ``.env`` style file into a dictionary.

    Supports blank lines, ``#`` comments, optional ``export`` prefixes
    and single/double quoted values. Malformed lines are ignored rather
    than raising, so a partially edited file never crashes the tool.
    """
    values = {}
    if not path.is_file():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key:
            values[key] = value
    return values


def load_environment() -> dict:
    """Return the effective environment for APIShield.

    Process environment variables always take precedence over values
    read from the ``.env`` file, matching standard 12-factor behaviour.
    """
    return {**parse_env_file(ENV_FILE), **_filtered_environ()}


def _filtered_environ() -> dict:
    """Copy only APISHIELD_* variables from the process environment."""
    return {k: v for k, v in os.environ.items() if k.startswith("APISHIELD_")}


def load_config() -> RuntimeConfig:
    """Load and validate the runtime configuration.

    Raises:
        ConfigurationError: if any required variable is missing or
            empty. The error message lists variable names only.
    """
    env = load_environment()

    missing = [name for name in REQUIRED_VARIABLES if not env.get(name)]
    if missing:
        raise ConfigurationError(
            "Missing or empty environment variables: " + ", ".join(missing)
            + ". Copy .env.example to .env and provide values for each variable."
        )

    return RuntimeConfig(
        base_url=env["APISHIELD_BASE_URL"],
        user_a_token=env["APISHIELD_USER_A_TOKEN"],
        user_b_token=env["APISHIELD_USER_B_TOKEN"],
        user_a_vehicle_id=env["APISHIELD_USER_A_VEHICLE_ID"],
        user_b_vehicle_id=env["APISHIELD_USER_B_VEHICLE_ID"],
    )
