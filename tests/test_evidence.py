"""Unit tests for the redacted evidence layer.

Evidence bundles are built from a fully mocked engine scan, then
inspected to prove that no secrets or sensitive values can reach the
serialised output that phase 5 will persist.
"""

import json

import responses as responses_lib

from apishield.bola_engine import BolaEngine
from apishield.classifier import classify_scan
from apishield.evidence import (
    build_scan_evidence,
    fingerprint_identifier,
)
from apishield.request_handler import RequestBudget, RequestHandler

from test_bola_engine import BASE_URL, BODY_A, BODY_B, make_endpoint, make_registry

# Raw values that must NEVER appear in evidence output.
FORBIDDEN_RAW_VALUES = [
    "token-a", "token-b",                  # bearer tokens
    "veh-a", "veh-b",                      # raw resource identifiers
    "User A Name", "User B Name",          # names
    "usera@apishield.local",               # emails
    "11.11", "22.22", "33.33", "44.44",    # coordinates
]


def run_mocked_scan(budget_max=50):
    """Run a scan against a mocked BOLA-shaped lab and return
    (scan_result, classification, endpoint)."""
    url_a = f"{BASE_URL}/identity/api/v2/vehicle/veh-a/location"
    url_b = f"{BASE_URL}/identity/api/v2/vehicle/veh-b/location"
    responses_lib.get(url_a, json=BODY_A)

    def vehicle_b_callback(request):
        if "Authorization" not in request.headers:
            return 401, {"Content-Type": "application/json"}, \
                json.dumps({"message": "Invalid Token"})
        return 200, {"Content-Type": "application/json"}, json.dumps(BODY_B)

    responses_lib.add_callback(responses_lib.GET, url_b,
                               callback=vehicle_b_callback)

    endpoint = make_endpoint()
    engine = BolaEngine(make_registry(),
                        RequestHandler(BASE_URL, budget=RequestBudget(budget_max)))
    scan = engine.run_scan(endpoint)
    classification = classify_scan(scan)
    return scan, classification, endpoint


class TestFingerprint:
    def test_fingerprint_is_short_and_hex(self):
        fp = fingerprint_identifier("veh-b")
        assert len(fp) == 12
        int(fp, 16)  # must be hexadecimal

    def test_fingerprint_is_deterministic(self):
        assert fingerprint_identifier("veh-b") == fingerprint_identifier("veh-b")

    def test_different_ids_give_different_fingerprints(self):
        assert fingerprint_identifier("veh-a") != fingerprint_identifier("veh-b")

    def test_fingerprint_does_not_reveal_value(self):
        fp = fingerprint_identifier("veh-b")
        assert "veh-b" not in fp


class TestEvidenceRedaction:
    @responses_lib.activate
    def test_serialised_evidence_contains_no_secrets_or_values(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")
        rendered = json.dumps(bundle.to_dict())

        for forbidden in FORBIDDEN_RAW_VALUES:
            assert forbidden not in rendered, (
                f"Evidence leaked sensitive value {forbidden!r}")

    @responses_lib.activate
    def test_evidence_uses_fingerprints_for_resource_ids(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        by_id = {case.case_id: case for case in bundle.cases}
        # All cases reference B's resource via the same fingerprint...
        assert by_id["B02"].resource_id_fingerprint == \
            by_id["B03"].resource_id_fingerprint
        # ...which is a hash, not the raw identifier.
        assert by_id["B02"].resource_id_fingerprint == \
            fingerprint_identifier("veh-b")
        assert by_id["B02"].resource_id_fingerprint != \
            by_id["B01"].resource_id_fingerprint

    @responses_lib.activate
    def test_sensitive_fields_stored_as_names_only(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        b03 = {case.case_id: case for case in bundle.cases}["B03"]
        assert b03.sensitive_fields_present == ["latitude", "longitude"]
        # Values (the numbers themselves) are covered by the forbidden
        # values check in the serialisation test.

    @responses_lib.activate
    def test_tokens_never_enter_evidence_objects(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")
        rendered = repr(bundle)
        assert "token-a" not in rendered
        assert "token-b" not in rendered


class TestEvidenceContent:
    @responses_lib.activate
    def test_bundle_records_scenario_policy_and_classification(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        assert bundle.run_id == "run-123"
        assert bundle.endpoint_id == "vehicle_location"
        assert bundle.method == "GET"
        assert bundle.path == endpoint.path
        assert bundle.policy == {
            "own_resource": "ALLOW",
            "cross_account": "DENY",
            "unauthenticated": "DENY",
        }
        assert bundle.overall_classification == classification.overall
        assert bundle.budget_used == 5
        assert not bundle.budget_exhausted
        assert len(bundle.cases) == 5
        assert bundle.started_at and bundle.finished_at

    @responses_lib.activate
    def test_case_evidence_is_complete(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        b03 = {case.case_id: case for case in bundle.cases}["B03"]
        assert b03.requester_label == "user_a"
        assert b03.owner_label == "user_b"
        assert b03.expected_decision == "DENY"
        assert b03.status_code == 200
        assert b03.access_obtained is True
        assert b03.classification == "CONFIRMED"
        assert b03.reason
        assert b03.classified_at
        assert b03.elapsed_ms is not None

    @responses_lib.activate
    def test_comparison_evidence_present_for_cross_account(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        b03 = {case.case_id: case for case in bundle.cases}["B03"]
        assert b03.comparison is not None
        assert b03.comparison.baseline_case_id == "B02"
        assert b03.comparison.identity_matches_resource_owner is True

        b01 = {case.case_id: case for case in bundle.cases}["B01"]
        assert b01.comparison is None  # baselines are not compared

    @responses_lib.activate
    def test_serialisation_round_trip(self):
        scan, classification, endpoint = run_mocked_scan()
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        data = bundle.to_dict()
        assert json.loads(json.dumps(data)) == data
        assert data["cases"][0]["case_id"] == "B01"
        assert isinstance(data["policy"], dict)


class TestEvidenceForDegradedScans:
    @responses_lib.activate
    def test_budget_exhausted_cases_have_minimal_evidence(self):
        # Only two requests allowed: B03-B05 are skipped.
        scan, classification, endpoint = run_mocked_scan(budget_max=2)
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        by_id = {case.case_id: case for case in bundle.cases}
        assert by_id["B03"].status_code is None
        assert by_id["B03"].classification == "INCONCLUSIVE"
        assert "skipped" in by_id["B03"].reason.lower()
        assert bundle.budget_exhausted is True
        assert bundle.overall_classification == "INCONCLUSIVE"

    @responses_lib.activate
    def test_fingerprints_present_even_for_skipped_cases(self):
        # Correlation remains possible for skipped cases.
        scan, classification, endpoint = run_mocked_scan(budget_max=2)
        bundle = build_scan_evidence(scan, classification, endpoint, "run-123")

        by_id = {case.case_id: case for case in bundle.cases}
        assert by_id["B03"].resource_id_fingerprint == \
            fingerprint_identifier("veh-b")
