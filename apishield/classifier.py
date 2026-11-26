"""Classification of BOLA test outcomes.

The classifier consumes the factual observations produced by the
engine (case results and differential comparisons) and compares them
against the endpoint's configured policy. It never looks at raw
response bodies, tokens or coordinates - only at the redacted,
boolean observations recorded in phase 3.

Classifications:
  CONFIRMED     Cross-account access succeeded despite a DENY policy
                AND the response demonstrably exposes the resource
                owner's protected information or ownership context.
  SUSPECTED     Access succeeded despite a DENY policy, but ownership
                or data exposure could not be verified.
  INCONCLUSIVE  The endpoint was unreachable, a case was skipped, the
                baseline failed, or evidence is ambiguous.
  NO_ISSUE      Observed behaviour matches the configured policy.

Core principle: HTTP 200 alone is NEVER sufficient to confirm BOLA.
Confirmation requires differential evidence - the cross-account
response matching the resource owner's baseline, carrying the owner's
identity fields, or returning the requested object together with
ownership/sensitive context.
"""

from dataclasses import dataclass, field

from .bola_engine import CaseResult, ScanResult
from .response_analyzer import DifferentialComparison

CONFIRMED = "CONFIRMED"
SUSPECTED = "SUSPECTED"
INCONCLUSIVE = "INCONCLUSIVE"
NO_ISSUE = "NO_ISSUE"

# Worst-first ordering used when aggregating cases into an overall
# result for an endpoint.
SEVERITY_ORDER = {
    NO_ISSUE: 0,
    INCONCLUSIVE: 1,
    SUSPECTED: 2,
    CONFIRMED: 3,
}


@dataclass
class CaseClassification:
    """Classification of a single test case, with its explanation."""

    case_id: str
    requester_label: str
    owner_label: str
    expected_decision: str
    classification: str
    reason: str


@dataclass
class ScanClassification:
    """Classifications for a whole scan plus the overall verdict."""

    endpoint_id: str
    overall: str
    summary: str
    case_classifications: list[CaseClassification] = field(default_factory=list)

    @property
    def confirmed_case_ids(self) -> list[str]:
        return [c.case_id for c in self.case_classifications
                if c.classification == CONFIRMED]


def classify_case(case: CaseResult,
                  comparison: DifferentialComparison | None) -> CaseClassification:
    """Classify one test case against the expected policy decision."""
    reason = _classify_reason(case, comparison)
    classification = _classify_decision(case, comparison)
    return CaseClassification(
        case_id=case.case_id,
        requester_label=case.requester_label,
        owner_label=case.owner_label,
        expected_decision=case.expected_decision,
        classification=classification,
        reason=reason,
    )


def _classify_decision(case: CaseResult,
                       comparison: DifferentialComparison | None) -> str:
    if not case.executed or case.transport_error:
        return INCONCLUSIVE
    if case.expected_decision == "ALLOW":
        # Baseline cases: policy expects legitimate access.
        return NO_ISSUE if case.analysis.access_obtained else INCONCLUSIVE

    # Policy expects DENY.
    if not case.analysis.access_obtained:
        return NO_ISSUE

    # Access was obtained despite a DENY policy. Verification level
    # decides between CONFIRMED, SUSPECTED and INCONCLUSIVE.
    if comparison is None:
        return INCONCLUSIVE

    if _exposes_owner_data(case, comparison):
        return CONFIRMED
    return SUSPECTED


def _exposes_owner_data(case: CaseResult,
                        comparison: DifferentialComparison) -> bool:
    """Differential evidence that the owner's data was exposed.

    Any single strong indicator is sufficient:
      * identity fields in the response carry the owner's values;
      * the response body is identical to the owner's baseline AND the
        body contains recognisable object content (an identical pair
        of empty bodies is not evidence of exposure);
      * the requested object identifier is returned together with
        ownership or sensitive field context.
    """
    analysis = case.analysis
    has_content = bool(
        analysis and (
            analysis.identity_fields_present
            or analysis.ownership_fields_present
            or analysis.resource_id_fields_present
            or analysis.sensitive_fields_present
        )
    )

    if comparison.identity_matches_resource_owner is True:
        return True
    if comparison.matches_owner_baseline is True and has_content:
        return True
    if comparison.resource_id_matches_request is True:
        if analysis and (analysis.sensitive_fields_present
                         or analysis.ownership_fields_present):
            return True
    return False


def _classify_reason(case: CaseResult,
                     comparison: DifferentialComparison | None) -> str:
    if not case.executed:
        return (f"Case skipped ({case.skipped_reason}); outcome could not "
                "be established.")
    if case.transport_error:
        return (f"Request failed at transport level ({case.transport_error}); "
                "endpoint availability could not be established.")
    if case.expected_decision == "ALLOW":
        if case.analysis.access_obtained:
            return (f"Legitimate own-resource access returned content as the "
                    f"policy expects ({case.status_code}).")
        return (f"Baseline own-resource request did not return content "
                f"(status {case.status_code}); ownership context for this "
                "resource could not be established.")

    # Expected DENY from here on.
    if not case.analysis.access_obtained:
        who = "Unauthenticated request" if case.requester_label == "anonymous" \
            else "Cross-account request"
        verb = "rejected" if case.status_code in (401, 403) else "returned no content"
        return (f"{who} was {verb} (status {case.status_code}), matching the "
                "DENY policy.")

    if comparison is None:
        return ("Access was obtained despite a DENY policy, but no owner "
                "baseline is available to verify what was exposed.")

    if comparison.identity_matches_resource_owner is True:
        return ("Access obtained despite DENY policy; the response carries "
                "the resource owner's identity fields, verified against the "
                "owner's own baseline.")
    if comparison.matches_owner_baseline is True:
        return ("Access obtained despite DENY policy; the response is "
                "identical to the resource owner's own baseline response.")
    if _exposes_owner_data(case, comparison):
        return ("Access obtained despite DENY policy; the requested object "
                "identifier is returned together with ownership or "
                "sensitive field context.")
    if comparison.both_bodies_parsed is False:
        return ("Access was obtained despite a DENY policy, but the "
                "response bodies could not be compared (not JSON objects).")
    return ("Access was obtained despite a DENY policy (HTTP "
            f"{case.status_code}), but ownership of the returned data "
            "could not be verified against the owner baseline.")


def classify_scan(scan: ScanResult) -> ScanClassification:
    """Classify every case in a scan and derive the overall verdict.

    The overall verdict is the worst classification among the cases
    governed by a DENY policy (cross-account and unauthenticated
    probes). Baseline cases inform INCONCLUSIVE outcomes but cannot
    by themselves produce a finding.
    """
    comparisons = {c.cross_case_id: c for c in scan.comparisons}
    case_classifications = [
        classify_case(case, comparisons.get(case.case_id))
        for case in scan.case_results
    ]

    governed = [c for c in case_classifications if c.expected_decision == "DENY"]
    if not governed:
        return ScanClassification(
            endpoint_id=scan.endpoint_id,
            overall=NO_ISSUE,
            summary="No cases governed by a DENY policy were executed.",
            case_classifications=case_classifications,
        )

    worst = max(governed, key=lambda c: SEVERITY_ORDER[c.classification])
    overall = worst.classification

    worst_cases = [c for c in governed if c.classification == overall]
    summary = (f"{len(worst_cases)} of {len(governed)} policy-governed "
               f"probes classified {overall}. {worst_cases[0].reason}")

    return ScanClassification(
        endpoint_id=scan.endpoint_id,
        overall=overall,
        summary=summary,
        case_classifications=case_classifications,
    )
