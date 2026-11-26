"""Unit tests for the response analyzer.

These tests use synthetic response bodies that mimic the SHAPE of a
vehicle-location API response. They contain made-up values only.
The analyzer must produce factual observations (field names and
booleans) without ever embedding field values in its results.
"""

from apishield.endpoint_loader import EndpointDefinition, EndpointPolicy
from apishield.request_handler import ResponseRecord
from apishield.response_analyzer import (
    analyze_response,
    compare_with_baseline,
    find_field_values,
)


def make_endpoint() -> EndpointDefinition:
    policy = EndpointPolicy(own_resource="ALLOW", cross_account="DENY",
                            unauthenticated="DENY")
    return EndpointDefinition(
        endpoint_id="vehicle_location",
        name="Vehicle Location",
        method="GET",
        path="/identity/api/v2/vehicle/{vehicle_id}/location",
        requires_authentication=True,
        resource_type="vehicle",
        resource_id_variable="vehicle_id",
        policy=policy,
        identity_fields=("fullName", "email"),
        ownership_fields=("carId",),
        resource_id_fields=("vehicleId",),
        sensitive_fields=("latitude", "longitude"),
    )


def make_record(json_body=None, status_code=200, **kwargs) -> ResponseRecord:
    defaults = dict(
        url="http://127.0.0.1:8888/identity/api/v2/vehicle/veh-1/location",
        status_code=status_code,
        content_type="application/json" if json_body is not None else None,
        body_bytes=100 if json_body is not None else 0,
        json_body=json_body,
    )
    defaults.update(kwargs)
    return ResponseRecord(**defaults)


OWNER_B_BODY = {
    "vehicleId": "veh-b",
    "carId": "car-b",
    "fullName": "User B Name",
    "email": "userb@apishield.local",
    "vehicleLocation": [
        {"latitude": 12.34, "longitude": 56.78, "id": "loc-1"},
    ],
}


class TestFindFieldValues:
    def test_finds_top_level_fields(self):
        assert find_field_values({"a": 1}, "a") == [1]

    def test_finds_nested_fields(self):
        body = {"vehicleLocation": [{"latitude": 12.34}]}
        assert find_field_values(body, "latitude") == [12.34]

    def test_finds_multiple_occurrences(self):
        body = {"latitude": 1.0, "items": [{"latitude": 2.0}, {"latitude": 3.0}]}
        assert find_field_values(body, "latitude") == [1.0, 2.0, 3.0]

    def test_absent_field_returns_empty(self):
        assert find_field_values({"a": 1}, "b") == []


class TestAnalyzeResponse:
    def test_successful_response_with_all_fields(self):
        record = make_record(OWNER_B_BODY)
        analysis = analyze_response(record, make_endpoint(), "veh-b")

        assert analysis.status_success
        assert analysis.access_obtained
        assert analysis.identity_fields_present == ["fullName", "email"]
        assert analysis.ownership_fields_present == ["carId"]
        assert analysis.resource_id_fields_present == ["vehicleId"]
        assert analysis.sensitive_fields_present == ["latitude", "longitude"]
        assert analysis.resource_id_matches_request is True

    def test_resource_id_mismatch_is_detected(self):
        record = make_record(OWNER_B_BODY)
        analysis = analyze_response(record, make_endpoint(), "veh-a")
        assert analysis.resource_id_matches_request is False

    def test_analysis_contains_no_field_values(self):
        record = make_record(OWNER_B_BODY)
        analysis = analyze_response(record, make_endpoint(), "veh-b")
        rendered = repr(analysis)
        assert "User B Name" not in rendered
        assert "12.34" not in rendered
        assert "veh-b" not in rendered
        assert "userb@apishield.local" not in rendered

    def test_unauthorized_response(self):
        record = make_record({"message": "Unauthorized"}, status_code=401)
        analysis = analyze_response(record, make_endpoint(), "veh-b")
        assert not analysis.status_success
        assert not analysis.access_obtained
        assert analysis.identity_fields_present == []

    def test_transport_error_response(self):
        record = make_record(None, status_code=None, transport_error="timeout")
        analysis = analyze_response(record, make_endpoint(), "veh-b")
        assert analysis.transport_error == "timeout"
        assert not analysis.status_success
        assert not analysis.access_obtained

    def test_non_json_body(self):
        record = make_record(None, status_code=200, body_bytes=50,
                             content_type="text/html")
        analysis = analyze_response(record, make_endpoint(), "veh-b")
        assert not analysis.json_parsed
        # 200 with body content is factually "access obtained" even
        # when the body is not JSON; the classifier interprets it.
        assert analysis.access_obtained

    def test_json_parse_error_is_recorded(self):
        record = make_record(None, status_code=200, json_parse_error=True)
        analysis = analyze_response(record, make_endpoint(), "veh-b")
        assert analysis.json_parse_error
        assert not analysis.json_parsed

    def test_empty_200_body_is_not_access(self):
        record = make_record(None, status_code=200, body_bytes=0)
        analysis = analyze_response(record, make_endpoint(), "veh-b")
        assert not analysis.access_obtained

    def test_provisional_fields_absent_is_recorded_not_error(self):
        # Fields are hints: their absence is just an empty list.
        record = make_record({"unrelated": "data"})
        analysis = analyze_response(record, make_endpoint(), None)
        assert analysis.identity_fields_present == []
        assert analysis.sensitive_fields_present == []

    def test_non_dict_json_body(self):
        record = make_record([1, 2, 3])
        analysis = analyze_response(record, make_endpoint(), "veh-b")
        assert analysis.json_parsed
        assert not analysis.json_is_object
        assert analysis.identity_fields_present == []


class TestCompareWithBaseline:
    def test_identical_body_matches_baseline(self):
        baseline = make_record(OWNER_B_BODY)
        cross = make_record(dict(OWNER_B_BODY))
        comparison = compare_with_baseline(
            cross, baseline, "B03", "B02", "user_a", "user_b",
            make_endpoint(), "veh-b")

        assert comparison.both_bodies_parsed
        assert comparison.matches_owner_baseline is True
        assert comparison.identity_matches_resource_owner is True
        assert comparison.resource_id_matches_request is True
        assert comparison.sensitive_fields_present == ["latitude", "longitude"]

    def test_different_identity_does_not_match(self):
        cross_body = dict(OWNER_B_BODY)
        cross_body["email"] = "usera@apishield.local"
        cross = make_record(cross_body)
        baseline = make_record(OWNER_B_BODY)
        comparison = compare_with_baseline(
            cross, baseline, "B03", "B02", "user_a", "user_b",
            make_endpoint(), "veh-b")

        assert comparison.matches_owner_baseline is False
        assert comparison.identity_matches_resource_owner is False

    def test_missing_baseline_body_leaves_unknowns(self):
        baseline = make_record(None, status_code=403)
        cross = make_record(OWNER_B_BODY)
        comparison = compare_with_baseline(
            cross, baseline, "B03", "B02", "user_a", "user_b",
            make_endpoint(), "veh-b")

        assert comparison.both_bodies_parsed is None
        assert comparison.matches_owner_baseline is None
        assert comparison.identity_matches_resource_owner is None

    def test_no_identity_fields_gives_none(self):
        endpoint = make_endpoint()
        # Endpoint with no identity fields configured.
        object.__setattr__(endpoint, "identity_fields", ())
        body = {"vehicleId": "veh-b"}
        comparison = compare_with_baseline(
            make_record(body), make_record(dict(body)),
            "B03", "B02", "user_a", "user_b", endpoint, "veh-b")
        assert comparison.identity_matches_resource_owner is None

    def test_null_identity_values_do_not_match(self):
        # Regression: matching nulls carry no evidence of exposure.
        body = {"email": None, "vehicleId": "veh-b"}
        comparison = compare_with_baseline(
            make_record(dict(body)), make_record(dict(body)),
            "B03", "B02", "user_a", "user_b", make_endpoint(), "veh-b")
        assert comparison.identity_matches_resource_owner is None

    def test_comparison_contains_no_field_values(self):
        comparison = compare_with_baseline(
            make_record(dict(OWNER_B_BODY)), make_record(OWNER_B_BODY),
            "B03", "B02", "user_a", "user_b", make_endpoint(), "veh-b")
        rendered = repr(comparison)
        assert "User B Name" not in rendered
        assert "12.34" not in rendered
        assert "veh-b" not in rendered
