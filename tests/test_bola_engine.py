"""Unit tests for the BOLA differential engine.

All HTTP traffic is mocked with the ``responses`` library. The mock
bodies are SYNTHETIC: they mimic the shape of a vehicle-location API
purely to exercise the engine's request matrix and comparison logic.
They do not represent real crAPI results, which can only be obtained
by running integration tests inside the Kali lab.
"""

import json

import requests
import responses as responses_lib

from apishield.authentication import IdentityRegistry
from apishield.bola_engine import BolaEngine, BUDGET_EXHAUSTED_REASON
from apishield.config import RuntimeConfig
from apishield.endpoint_loader import EndpointDefinition, EndpointPolicy
from apishield.request_handler import RequestBudget, RequestHandler

BASE_URL = "http://127.0.0.1:8888"
PATH = "/identity/api/v2/vehicle/{vehicle_id}/location"


def make_endpoint(cross_account="DENY") -> EndpointDefinition:
    policy = EndpointPolicy(own_resource="ALLOW", cross_account=cross_account,
                            unauthenticated="DENY")
    return EndpointDefinition(
        endpoint_id="vehicle_location",
        name="Vehicle Location",
        method="GET",
        path=PATH,
        requires_authentication=True,
        resource_type="vehicle",
        resource_id_variable="vehicle_id",
        policy=policy,
        identity_fields=("fullName", "email"),
        ownership_fields=("carId",),
        resource_id_fields=("vehicleId",),
        sensitive_fields=("latitude", "longitude"),
    )


def make_registry() -> IdentityRegistry:
    config = RuntimeConfig(
        base_url=BASE_URL,
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_vehicle_id="veh-a",
        user_b_vehicle_id="veh-b",
    )
    return IdentityRegistry(config)


# Synthetic response bodies (made-up values, shape only).
BODY_A = {
    "vehicleId": "veh-a", "carId": "car-a",
    "fullName": "User A Name", "email": "usera@apishield.local",
    "vehicleLocation": [{"latitude": 11.11, "longitude": 22.22}],
}
BODY_B = {
    "vehicleId": "veh-b", "carId": "car-b",
    "fullName": "User B Name", "email": "userb@apishield.local",
    "vehicleLocation": [{"latitude": 33.33, "longitude": 44.44}],
}


JSON_HEADERS = {"Content-Type": "application/json"}


def register_lab_responses():
    """Register mocked behaviour for the five-case matrix.

    The mock deliberately serves each requester's own data on their own
    resource, and (for cross-account probes) the OWNER's data - the
    classic shape of an object-level authorization flaw. This is a
    test fixture, not an assumed real-world result.
    """
    url_a = f"{BASE_URL}/identity/api/v2/vehicle/veh-a/location"
    url_b = f"{BASE_URL}/identity/api/v2/vehicle/veh-b/location"

    responses_lib.get(url_a, json=BODY_A)

    # Anonymous requests to B's resource are rejected; authenticated
    # requests return B's data.
    def vehicle_b_callback(request):
        if "Authorization" not in request.headers:
            return 401, JSON_HEADERS, json.dumps({"message": "Invalid Token"})
        return 200, JSON_HEADERS, json.dumps(BODY_B)

    responses_lib.add_callback(
        responses_lib.GET, url_b, callback=vehicle_b_callback,
    )


class TestCaseMatrix:
    @responses_lib.activate
    def test_executes_all_five_cases_in_order(self):
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        assert [c.case_id for c in result.case_results] == ["B01", "B02", "B03", "B04", "B05"]
        assert all(c.executed for c in result.case_results)
        assert result.budget_used == 5
        assert not result.budget_exhausted
        assert result.skipped_count == 0

    @responses_lib.activate
    def test_requests_use_correct_tokens_and_resource_ids(self):
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        engine.run_scan(make_endpoint())

        calls = responses_lib.calls
        assert len(calls) == 5

        expected = [
            ("Bearer token-a", "veh-a"),  # B01
            ("Bearer token-b", "veh-b"),  # B02
            ("Bearer token-a", "veh-b"),  # B03
            ("Bearer token-b", "veh-a"),  # B04
            (None, "veh-b"),              # B05 anonymous
        ]
        for call, (auth, veh) in zip(calls, expected):
            assert veh in call.request.url
            if auth is None:
                assert "Authorization" not in call.request.headers
            else:
                assert call.request.headers.get("Authorization") == auth

    @responses_lib.activate
    def test_expected_decisions_come_from_policy_not_code(self):
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        by_id = {c.case_id: c for c in result.case_results}
        assert by_id["B01"].expected_decision == "ALLOW"
        assert by_id["B02"].expected_decision == "ALLOW"
        assert by_id["B03"].expected_decision == "DENY"
        assert by_id["B04"].expected_decision == "DENY"
        assert by_id["B05"].expected_decision == "DENY"

    @responses_lib.activate
    def test_alternative_policy_is_respected(self):
        # A permissive policy changes the expected decisions only;
        # observed behaviour is untouched.
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint(cross_account="ALLOW"))

        by_id = {c.case_id: c for c in result.case_results}
        assert by_id["B03"].expected_decision == "ALLOW"
        assert by_id["B04"].expected_decision == "ALLOW"

    @responses_lib.activate
    def test_factual_observations_match_mock_behaviour(self):
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        by_id = {c.case_id: c for c in result.case_results}
        assert by_id["B01"].status_code == 200
        assert by_id["B03"].status_code == 200
        assert by_id["B05"].status_code == 401
        assert by_id["B05"].analysis.access_obtained is False
        assert by_id["B03"].analysis.access_obtained is True


class TestDifferentialComparisons:
    @responses_lib.activate
    def test_cross_account_cases_compared_with_owner_baseline(self):
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        # B03, B04 and the anonymous control B05 are each compared
        # against the owning user's baseline.
        assert len(result.comparisons) == 3
        by_cross = {c.cross_case_id: c for c in result.comparisons}
        assert by_cross["B03"].baseline_case_id == "B02"
        assert by_cross["B04"].baseline_case_id == "B01"
        assert by_cross["B05"].baseline_case_id == "B02"

    @responses_lib.activate
    def test_unauthenticated_control_data_is_compared(self):
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        b05 = {c.cross_case_id: c for c in result.comparisons}["B05"]
        # The mock rejects anonymous requests, so no owner data is seen.
        assert b05.matches_owner_baseline is False

    @responses_lib.activate
    def test_owner_data_similarity_is_observed(self):
        # The mock returns the owner's body to cross-account requesters,
        # so the comparison must show the owner's data being returned.
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        b03 = {c.cross_case_id: c for c in result.comparisons}["B03"]
        assert b03.matches_owner_baseline is True
        assert b03.identity_matches_resource_owner is True
        assert b03.sensitive_fields_present == ["latitude", "longitude"]

    @responses_lib.activate
    def test_cross_account_denial_is_observed(self):
        # Mock a correctly protected API: cross-account gets 403,
        # unauthenticated gets 401.
        def protected_callback(request):
            auth = request.headers.get("Authorization", "")
            if not auth:
                return 401, JSON_HEADERS, json.dumps({"message": "Invalid Token"})
            if auth == "Bearer token-a" and request.url.endswith("veh-b/location"):
                return 403, JSON_HEADERS, json.dumps({"message": "Access Denied"})
            if auth == "Bearer token-b" and request.url.endswith("veh-a/location"):
                return 403, JSON_HEADERS, json.dumps({"message": "Access Denied"})
            if request.url.endswith("veh-b/location"):
                return 200, JSON_HEADERS, json.dumps(BODY_B)
            return 200, JSON_HEADERS, json.dumps(BODY_A)

        for veh in ("veh-a", "veh-b"):
            url = f"{BASE_URL}/identity/api/v2/vehicle/{veh}/location"
            responses_lib.add_callback(responses_lib.GET, url,
                                       callback=protected_callback)

        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        by_id = {c.case_id: c for c in result.case_results}
        assert by_id["B03"].status_code == 403
        assert by_id["B03"].analysis.access_obtained is False

        b03 = {c.cross_case_id: c for c in result.comparisons}["B03"]
        assert b03.matches_owner_baseline is False
        assert b03.identity_matches_resource_owner is None


class TestBudgetHandling:
    @responses_lib.activate
    def test_budget_exhaustion_skips_remaining_cases(self):
        register_lab_responses()
        budget = RequestBudget(max_requests=2)
        engine = BolaEngine(make_registry(),
                            RequestHandler(BASE_URL, budget=budget))
        result = engine.run_scan(make_endpoint())

        executed = [c.case_id for c in result.case_results if c.executed]
        skipped = [c.case_id for c in result.case_results if not c.executed]
        assert executed == ["B01", "B02"]
        assert skipped == ["B03", "B04", "B05"]
        assert all(c.skipped_reason == BUDGET_EXHAUSTED_REASON
                   for c in result.case_results if not c.executed)
        assert result.budget_exhausted
        assert result.budget_used == 2
        assert result.skipped_count == 3
        # No comparisons possible without the cross-account cases.
        assert result.comparisons == []

    @responses_lib.activate
    def test_budget_is_shared_across_scans(self):
        # One budget object spans both endpoints in a single scan run.
        register_lab_responses()
        budget = RequestBudget(max_requests=3)
        engine = BolaEngine(make_registry(),
                            RequestHandler(BASE_URL, budget=budget))
        first = engine.run_scan(make_endpoint())
        second = engine.run_scan(make_endpoint())

        assert first.budget_used == 3
        assert first.budget_exhausted
        assert second.skipped_count == 5


class TestTransportFailures:
    @responses_lib.activate
    def test_transport_errors_do_not_crash_scan(self):
        responses_lib.get(
            f"{BASE_URL}/identity/api/v2/vehicle/veh-a/location",
            body=requests.exceptions.ConnectionError("refused"),
        )
        responses_lib.get(
            f"{BASE_URL}/identity/api/v2/vehicle/veh-b/location",
            body=requests.exceptions.ConnectionError("refused"),
        )
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        assert all(c.executed for c in result.case_results)
        assert all(c.transport_error == "connection_error"
                   for c in result.case_results)
        assert result.comparisons == []


class TestResultSafety:
    @responses_lib.activate
    def test_results_contain_no_tokens_or_values(self):
        register_lab_responses()
        engine = BolaEngine(make_registry(), RequestHandler(BASE_URL))
        result = engine.run_scan(make_endpoint())

        rendered = repr(result)
        assert "token-a" not in rendered
        assert "token-b" not in rendered
        assert "User A Name" not in rendered
        assert "33.33" not in rendered
