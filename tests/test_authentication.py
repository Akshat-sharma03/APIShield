"""Unit tests for the authentication identity registry."""

import pytest

from apishield.authentication import (
    ANONYMOUS,
    USER_A,
    USER_B,
    Identity,
    IdentityRegistry,
)
from apishield.config import RuntimeConfig


@pytest.fixture
def runtime_config():
    return RuntimeConfig(
        base_url="http://127.0.0.1:8888",
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_vehicle_id="veh-a",
        user_b_vehicle_id="veh-b",
    )


class TestIdentity:
    def test_authenticated_identity_properties(self):
        identity = Identity(label="user_a", token="t", resource_id="r")
        assert identity.is_authenticated
        assert identity.resource_id == "r"

    def test_anonymous_identity_is_unauthenticated(self):
        identity = Identity(label="anonymous")
        assert not identity.is_authenticated
        assert identity.token is None

    def test_repr_contains_no_token(self):
        identity = Identity(label="user_a", token="secret-token-value")
        assert "secret-token-value" not in repr(identity)
        assert "user_a" in repr(identity)


class TestIdentityRegistry:
    def test_provides_three_identities(self, runtime_config):
        registry = IdentityRegistry(runtime_config)
        assert sorted(registry.labels) == [ANONYMOUS, USER_A, USER_B]

    def test_binds_resource_ids_to_owners(self, runtime_config):
        registry = IdentityRegistry(runtime_config)
        assert registry.get(USER_A).resource_id == "veh-a"
        assert registry.get(USER_B).resource_id == "veh-b"

    def test_anonymous_has_no_resource(self, runtime_config):
        registry = IdentityRegistry(runtime_config)
        assert registry.get(ANONYMOUS).resource_id is None

    def test_unknown_label_raises_keyerror(self, runtime_config):
        registry = IdentityRegistry(runtime_config)
        with pytest.raises(KeyError, match="Unknown identity label"):
            registry.get("user_c")
