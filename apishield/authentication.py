"""Authentication identities for the differential test matrix.

Identities are referenced throughout the tool by their LABEL ("user_a",
"user_b", "anonymous") so tokens never appear in logs, the database or
reports. The token itself is only ever used to build an Authorization
header inside the request handler.
"""

from dataclasses import dataclass

from .config import RuntimeConfig

USER_A = "user_a"
USER_B = "user_b"
ANONYMOUS = "anonymous"


@dataclass(frozen=True)
class Identity:
    """A test identity.

    ``token`` is None for the anonymous identity, which is used as the
    unauthenticated control case (B05).
    """

    label: str
    token: str | None = None
    resource_id: str | None = None

    @property
    def is_authenticated(self) -> bool:
        return self.token is not None

    def __repr__(self) -> str:
        return f"Identity(label={self.label!r}, authenticated={self.is_authenticated})"


class IdentityRegistry:
    """Holds the identities available for a test run."""

    def __init__(self, config: RuntimeConfig):
        self._identities = {
            USER_A: Identity(
                label=USER_A,
                token=config.user_a_token,
                resource_id=config.user_a_vehicle_id,
            ),
            USER_B: Identity(
                label=USER_B,
                token=config.user_b_token,
                resource_id=config.user_b_vehicle_id,
            ),
            # Unauthenticated control identity: no token, no resource.
            ANONYMOUS: Identity(label=ANONYMOUS),
        }

    def get(self, label: str) -> Identity:
        try:
            return self._identities[label]
        except KeyError:
            raise KeyError(
                f"Unknown identity label {label!r}. "
                f"Available: {sorted(self._identities)}"
            ) from None

    @property
    def labels(self) -> list[str]:
        return list(self._identities)
