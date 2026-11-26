"""Unit tests for the endpoint configuration loader."""

import json

import pytest

from apishield.endpoint_loader import (
    EndpointConfigError,
    EndpointDefinition,
    load_endpoints,
    parse_endpoint,
)


def valid_entry():
    return {
        "endpoint_id": "vehicle_location",
        "name": "Vehicle Location",
        "method": "GET",
        "path": "/identity/api/v2/vehicle/{vehicle_id}/location",
        "requires_authentication": True,
        "resource_type": "vehicle",
        "resource_id_variable": "vehicle_id",
        "policy": {
            "own_resource": "ALLOW",
            "cross_account": "DENY",
            "unauthenticated": "DENY",
        },
        "identity_fields": ["fullName"],
        "ownership_fields": ["carId"],
        "sensitive_fields": ["latitude"],
    }


class TestValidEntries:
    def test_parses_valid_entry(self):
        endpoint = parse_endpoint(valid_entry())
        assert isinstance(endpoint, EndpointDefinition)
        assert endpoint.endpoint_id == "vehicle_location"
        assert endpoint.method == "GET"
        assert endpoint.policy.cross_account == "DENY"
        assert endpoint.sensitive_fields == ("latitude",)

    def test_field_lists_are_optional(self):
        entry = valid_entry()
        del entry["identity_fields"]
        del entry["ownership_fields"]
        del entry["sensitive_fields"]
        endpoint = parse_endpoint(entry)
        assert endpoint.identity_fields == ()

    def test_policy_decisions_are_normalised(self):
        entry = valid_entry()
        entry["policy"]["cross_account"] = "deny"
        endpoint = parse_endpoint(entry)
        assert endpoint.policy.cross_account == "DENY"


class TestInvalidEntries:
    @pytest.mark.parametrize("missing_key", [
        "endpoint_id", "name", "method", "path", "requires_authentication",
        "resource_type", "resource_id_variable", "policy",
    ])
    def test_missing_required_key_is_rejected(self, missing_key):
        entry = valid_entry()
        del entry[missing_key]
        with pytest.raises(EndpointConfigError, match="missing required keys"):
            parse_endpoint(entry)

    def test_non_get_method_is_rejected(self):
        entry = valid_entry()
        entry["method"] = "POST"
        with pytest.raises(EndpointConfigError, match="not supported"):
            parse_endpoint(entry)

    def test_relative_path_is_rejected(self):
        entry = valid_entry()
        entry["path"] = "api/v2/vehicle/{vehicle_id}"
        with pytest.raises(EndpointConfigError, match="must start with"):
            parse_endpoint(entry)

    def test_placeholder_mismatch_is_rejected(self):
        entry = valid_entry()
        entry["path"] = "/api/v2/vehicle/{id}/location"
        with pytest.raises(EndpointConfigError, match="placeholder"):
            parse_endpoint(entry)

    def test_stray_braces_in_path_are_rejected(self):
        # Extra placeholders would crash path formatting at request time.
        entry = valid_entry()
        entry["path"] = "/api/v2/vehicle/{vehicle_id}/location/{other}"
        with pytest.raises(EndpointConfigError, match="unexpected braces"):
            parse_endpoint(entry)

    def test_invalid_policy_decision_is_rejected(self):
        entry = valid_entry()
        entry["policy"]["cross_account"] = "MAYBE"
        with pytest.raises(EndpointConfigError, match="cross_account"):
            parse_endpoint(entry)

    def test_missing_policy_key_is_rejected(self):
        entry = valid_entry()
        del entry["policy"]["unauthenticated"]
        with pytest.raises(EndpointConfigError, match="unauthenticated"):
            parse_endpoint(entry)

    def test_non_string_field_list_is_rejected(self):
        entry = valid_entry()
        entry["sensitive_fields"] = "latitude"
        with pytest.raises(EndpointConfigError, match="sensitive_fields"):
            parse_endpoint(entry)

    def test_non_object_entry_is_rejected(self):
        with pytest.raises(EndpointConfigError, match="JSON object"):
            parse_endpoint(["not", "an", "object"])


class TestLoadEndpoints:
    def test_loads_real_configuration(self, project_root):
        endpoints = load_endpoints(project_root / "config" / "endpoints.json")
        assert len(endpoints) == 1
        assert endpoints[0].endpoint_id == "vehicle_location"

    def test_missing_file_is_rejected(self, tmp_path):
        with pytest.raises(EndpointConfigError, match="not found"):
            load_endpoints(tmp_path / "absent.json")

    def test_invalid_json_is_rejected(self, tmp_path):
        config = tmp_path / "endpoints.json"
        config.write_text("{ not json", encoding="utf-8")
        with pytest.raises(EndpointConfigError, match="not valid JSON"):
            load_endpoints(config)

    def test_empty_endpoint_list_is_rejected(self, tmp_path):
        config = tmp_path / "endpoints.json"
        config.write_text(json.dumps({"endpoints": []}), encoding="utf-8")
        with pytest.raises(EndpointConfigError, match="non-empty"):
            load_endpoints(config)

    def test_duplicate_endpoint_ids_are_rejected(self, tmp_path):
        config = tmp_path / "endpoints.json"
        config.write_text(
            json.dumps({"endpoints": [valid_entry(), valid_entry()]}),
            encoding="utf-8",
        )
        with pytest.raises(EndpointConfigError, match="Duplicate"):
            load_endpoints(config)

    def test_notes_key_is_ignored(self, tmp_path):
        config = tmp_path / "endpoints.json"
        payload = {"_notes": "provisional fields", "endpoints": [valid_entry()]}
        config.write_text(json.dumps(payload), encoding="utf-8")
        endpoints = load_endpoints(config)
        assert len(endpoints) == 1
