"""Unit tests for the classification engine.

The classifier is tested with hand-built CaseResult/analysis objects
(no HTTP at all) so every branch of the decision logic is exercised
deterministically. Mocked-HTTP end-to-end behaviour is covered in
test_bola_engine.py.
"""

from apishield.bola_engine import BUDGET_EXHAUSTED_REASON, CaseResult
from apishield.classifier import (
    CONFIRMED,
    INCONCLUSIVE,
    NO_ISSUE,
    SUSPECTED,
    classify_case,
    classify_scan,
)
from apishield.response_analyzer import DifferentialComparison, ResponseAnalysis


def make_analysis(**overrides) -> ResponseAnalysis:
    defaults = dict(
        status_code=200,
        transport_error=None,
        status_success=True,
        body_bytes=100,
        truncated=False,
        json_parsed=True,
        json_is_object=True,
        json_parse_error=False,
    )
    defaults.update(overrides)
    return ResponseAnalysis(**defaults)


def make_case(case_id="B03", requester="user_a", owner="user_b",
              expected="DENY", executed=True, analysis=None,
              **overrides) -> CaseResult:
    defaults = dict(
        case_id=case_id,
        description=f"case {case_id}",
        requester_label=requester,
        owner_label=owner,
        expected_decision=expected,
        executed=executed,
        status_code=200 if executed else None,
        transport_error=None,
    )
    defaults.update(overrides)
    if analysis is not None:
        defaults["analysis"] = analysis
    return CaseResult(**defaults)


def make_comparison(case_id="B03", baseline="B02", requester="user_a",
                    owner="user_b", **overrides) -> DifferentialComparison:
    defaults = dict(
        cross_case_id=case_id,
        baseline_case_id=baseline,
        requester_label=requester,
        owner_label=owner,
        baseline_available=True,
        both_bodies_parsed=True,
        matches_owner_baseline=None,
        identity_matches_resource_owner=None,
        resource_id_matches_request=None,
    )
    defaults.update(overrides)
    return DifferentialComparison(**defaults)


class TestConfirmed:
    def test_confirmed_via_identity_match(self):
        case = make_case(analysis=make_analysis(access_obtained=True))
        comparison = make_comparison(identity_matches_resource_owner=True)
        result = classify_case(case, comparison)
        assert result.classification == CONFIRMED
        assert "identity" in result.reason.lower()

    def test_confirmed_via_baseline_body_match(self):
        case = make_case(analysis=make_analysis(
            access_obtained=True,
            identity_fields_present=["email"],
            ownership_fields_present=["carId"],
        ))
        comparison = make_comparison(matches_owner_baseline=True)
        assert classify_case(case, comparison).classification == CONFIRMED

    def test_identical_empty_bodies_do_not_confirm(self):
        # Regression: 200 {} for both baseline and cross-account request
        # must not be CONFIRMED - an empty object exposes nothing.
        case = make_case(analysis=make_analysis(access_obtained=True))
        comparison = make_comparison(matches_owner_baseline=True)
        assert classify_case(case, comparison).classification == SUSPECTED

    def test_confirmed_via_resource_id_and_sensitive_fields(self):
        case = make_case(analysis=make_analysis(
            access_obtained=True,
            sensitive_fields_present=["latitude", "longitude"],
        ))
        comparison = make_comparison(resource_id_matches_request=True)
        assert classify_case(case, comparison).classification == CONFIRMED

    def test_confirmed_via_resource_id_and_ownership_fields(self):
        case = make_case(analysis=make_analysis(
            access_obtained=True,
            ownership_fields_present=["carId"],
        ))
        comparison = make_comparison(resource_id_matches_request=True)
        assert classify_case(case, comparison).classification == CONFIRMED

    def test_http_200_alone_never_confirms(self):
        # 200 with content but no verifiable differential evidence.
        case = make_case(analysis=make_analysis(access_obtained=True))
        comparison = make_comparison(
            both_bodies_parsed=True,
            matches_owner_baseline=False,
            identity_matches_resource_owner=False,
            resource_id_matches_request=False,
            sensitive_fields_present=[],
        )
        assert classify_case(case, comparison).classification == SUSPECTED
        # And with no comparison at all:
        assert classify_case(case, None).classification == INCONCLUSIVE


class TestSuspected:
    def test_access_without_verification_is_suspected(self):
        case = make_case(analysis=make_analysis(access_obtained=True))
        comparison = make_comparison(
            matches_owner_baseline=False,
            identity_matches_resource_owner=False,
            resource_id_matches_request=False,
        )
        result = classify_case(case, comparison)
        assert result.classification == SUSPECTED
        assert "could not be verified" in result.reason

    def test_resource_id_match_without_context_is_suspected(self):
        # Object id matches but no sensitive/ownership context present.
        case = make_case(analysis=make_analysis(access_obtained=True))
        comparison = make_comparison(
            resource_id_matches_request=True,
            matches_owner_baseline=False,
            identity_matches_resource_owner=False,
        )
        assert classify_case(case, comparison).classification == SUSPECTED


class TestNoIssue:
    def test_own_resource_access_as_expected(self):
        case = make_case(
            case_id="B01", requester="user_a", owner="user_a",
            expected="ALLOW", analysis=make_analysis(access_obtained=True),
        )
        result = classify_case(case, None)
        assert result.classification == NO_ISSUE

    def test_denied_cross_account_access(self):
        case = make_case(analysis=make_analysis(
            access_obtained=False, status_code=403, status_success=False,
        ))
        result = classify_case(case, None)
        assert result.classification == NO_ISSUE
        assert "matching the DENY policy" in result.reason

    def test_unauthenticated_request_rejected(self):
        case = make_case(
            case_id="B05", requester="anonymous", owner="user_b",
            analysis=make_analysis(access_obtained=False, status_code=401,
                                   status_success=False),
        )
        result = classify_case(case, None)
        assert result.classification == NO_ISSUE
        assert "Unauthenticated" in result.reason

    def test_denied_cross_account_returns_empty_body(self):
        # 200 with an empty body is still "no content obtained".
        case = make_case(analysis=make_analysis(
            access_obtained=False, status_code=200, body_bytes=0,
        ))
        assert classify_case(case, None).classification == NO_ISSUE


class TestInconclusive:
    def test_transport_failure_is_inconclusive(self):
        case = make_case(
            analysis=make_analysis(status_code=None, status_success=False,
                                   transport_error="connection_error"),
            transport_error="connection_error",
        )
        result = classify_case(case, None)
        assert result.classification == INCONCLUSIVE
        assert "transport" in result.reason.lower()

    def test_skipped_case_is_inconclusive(self):
        case = make_case(
            executed=False, skipped_reason=BUDGET_EXHAUSTED_REASON,
            status_code=None, analysis=None,
        )
        result = classify_case(case, None)
        assert result.classification == INCONCLUSIVE
        assert "skipped" in result.reason

    def test_failed_baseline_is_inconclusive(self):
        # Own-resource access denied: ownership context is unusable.
        case = make_case(
            case_id="B01", requester="user_a", owner="user_a",
            expected="ALLOW",
            analysis=make_analysis(access_obtained=False, status_code=403,
                                   status_success=False),
        )
        assert classify_case(case, None).classification == INCONCLUSIVE

    def test_access_without_baseline_comparison_is_inconclusive(self):
        case = make_case(analysis=make_analysis(access_obtained=True))
        result = classify_case(case, None)
        assert result.classification == INCONCLUSIVE
        assert "no owner baseline" in result.reason

    def test_non_json_bodies_comparison_is_flagged(self):
        case = make_case(analysis=make_analysis(
            access_obtained=True, json_parsed=False, json_is_object=False,
        ))
        comparison = make_comparison(both_bodies_parsed=False)
        result = classify_case(case, comparison)
        assert result.classification == SUSPECTED
        assert "not JSON objects" in result.reason


class TestScanAggregation:
    def _scan_stub(self, cases, comparisons):
        from types import SimpleNamespace
        return SimpleNamespace(
            endpoint_id="vehicle_location",
            case_results=cases,
            comparisons=comparisons,
        )

    def test_overall_is_worst_governed_case(self):
        confirmed = make_case(case_id="B03", analysis=make_analysis(
            access_obtained=True, sensitive_fields_present=["latitude"]))
        denied = make_case(
            case_id="B04",
            analysis=make_analysis(access_obtained=False, status_code=403,
                                   status_success=False),
        )
        baseline = make_case(
            case_id="B01", requester="user_a", owner="user_a",
            expected="ALLOW", analysis=make_analysis(access_obtained=True),
        )
        scan = self._scan_stub(
            [baseline, confirmed, denied],
            [make_comparison(case_id="B03",
                             identity_matches_resource_owner=True)],
        )
        classification = classify_scan(scan)
        assert classification.overall == CONFIRMED
        assert "CONFIRMED" in classification.summary
        assert classification.confirmed_case_ids == ["B03"]

    def test_overall_no_issue_when_all_probes_denied(self):
        b03 = make_case(analysis=make_analysis(access_obtained=False,
                                               status_code=403,
                                               status_success=False))
        b04 = make_case(analysis=make_analysis(access_obtained=False,
                                               status_code=403,
                                               status_success=False))
        scan = self._scan_stub([b03, b04], [])
        assert classify_scan(scan).overall == NO_ISSUE

    def test_overall_inconclusive_when_all_transport_fail(self):
        cases = [make_case(
            analysis=make_analysis(status_code=None, status_success=False,
                                   transport_error="timeout"),
            transport_error="timeout",
        ) for _ in range(2)]
        scan = self._scan_stub(cases, [])
        assert classify_scan(scan).overall == INCONCLUSIVE

    def test_baseline_cases_do_not_drive_overall(self):
        # A failing baseline alone must not create a security finding.
        baseline = make_case(
            case_id="B01", requester="user_a", owner="user_a",
            expected="ALLOW",
            analysis=make_analysis(access_obtained=False, status_code=500,
                                   status_success=False),
        )
        denied = make_case(analysis=make_analysis(access_obtained=False,
                                                  status_code=403,
                                                  status_success=False))
        scan = self._scan_stub([baseline, denied], [])
        classification = classify_scan(scan)
        assert classification.overall == NO_ISSUE

    def test_classification_is_deterministic(self):
        case = make_case(analysis=make_analysis(access_obtained=True))
        comparison = make_comparison(identity_matches_resource_owner=True)
        first = classify_case(case, comparison)
        second = classify_case(case, comparison)
        assert first.classification == second.classification
        assert first.reason == second.reason
