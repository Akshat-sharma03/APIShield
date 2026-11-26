"""Structured, redacted evidence records for scan outcomes.

Evidence records are the bridge between the in-memory scan results
and the persistence/reporting layers (phase 5). They deliberately
contain only:
  * scenario labels (case id, requester/owner labels);
  * the expected policy decision;
  * factual observations (status codes, booleans, field NAMES);
  * comparison outcomes (booleans, field names);
  * classification and reason;
  * timestamps and budget information.

Redaction rules enforced by construction:
  * no bearer tokens, credentials or Authorization material;
  * no raw response bodies;
  * no personal data (names, emails, VINs) or location coordinates;
  * resource identifiers are stored only as short SHA-256 fingerprints
    so records can be correlated across cases and runs without
    revealing the real identifiers.
"""

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

FINGERPRINT_LENGTH = 12

# Remediation guidance is evidence-driven and generic: it describes
# how to fix the class of flaw observed, never a fabricated detail
# about the target's codebase.
REMEDIATION_GUIDANCE = {
    "CONFIRMED": (
        "Implement server-side object-level authorization on the affected "
        "endpoint. Every request must verify that the authenticated user "
        "owns (or is otherwise authorised to access) the referenced object "
        "before any data is returned. Do not rely on authentication alone, "
        "on non-guessable identifiers, or on client-side checks. Return "
        "403 Forbidden (or 404) when the object exists but belongs to "
        "another user. Regression-test with cross-account requests, and "
        "remove or restrict sensitive fields (such as location data) in "
        "responses where they are not required. Reference: OWASP API "
        "Security Top 10 2023, API1 Broken Object Level Authorization."
    ),
    "SUSPECTED": (
        "Manually verify the ownership of the data returned by the "
        "cross-account requests for this case, then either confirm and "
        "remediate as a Broken Object Level Authorization issue (enforce "
        "object-level authorization server-side) or document why the "
        "observed access is acceptable. Re-run APIShield after the "
        "endpoint configuration has been validated against real responses."
    ),
}


def remediation_guidance(classification: str) -> str | None:
    """Return remediation text for a classification, or None."""
    return REMEDIATION_GUIDANCE.get(classification)


def fingerprint_identifier(value: str) -> str:
    """Return a short stable hash of an identifier.

    Fingerprints allow evidence records to reference "the same object"
    across cases, baselines and runs without storing the actual
    identifier (which could be a UUID or VIN in a real deployment).
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:FINGERPRINT_LENGTH]


@dataclass
class ComparisonEvidence:
    """Redacted record of one differential comparison."""

    cross_case_id: str
    baseline_case_id: str
    requester_label: str
    owner_label: str
    both_bodies_parsed: bool | None
    matches_owner_baseline: bool | None
    identity_matches_resource_owner: bool | None
    resource_id_matches_request: bool | None
    sensitive_fields_present: list[str] = field(default_factory=list)


@dataclass
class CaseEvidence:
    """Redacted evidence for one test case."""

    case_id: str
    description: str
    endpoint_id: str
    requester_label: str
    owner_label: str
    expected_decision: str
    resource_id_fingerprint: str | None
    classification: str
    reason: str
    classified_at: str
    # Factual observations.
    status_code: int | None = None
    transport_error: str | None = None
    elapsed_ms: int | None = None
    body_bytes: int = 0
    truncated: bool = False
    access_obtained: bool = False
    # Field presence (names only, never values).
    identity_fields_present: list[str] = field(default_factory=list)
    ownership_fields_present: list[str] = field(default_factory=list)
    resource_id_fields_present: list[str] = field(default_factory=list)
    sensitive_fields_present: list[str] = field(default_factory=list)
    resource_id_matches_request: bool | None = None
    # Differential evidence, when a baseline was available.
    comparison: ComparisonEvidence | None = None


@dataclass
class ScanEvidence:
    """Complete redacted evidence bundle for one endpoint scan."""

    run_id: str
    endpoint_id: str
    endpoint_name: str
    method: str
    path: str
    policy: dict
    started_at: str
    finished_at: str
    overall_classification: str
    summary: str
    budget_used: int
    budget_max: int
    budget_exhausted: bool
    cases: list[CaseEvidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON-serialisable representation of the whole bundle."""
        return asdict(self)


def build_case_evidence(case_result, case_classification, comparison,
                        endpoint_id: str, classified_at: str) -> CaseEvidence:
    """Build the evidence record for one classified case.

    Args:
        case_result: engine CaseResult (duck-typed; contains only
            redacted observations and field names).
        case_classification: classifier CaseClassification.
        comparison: matching DifferentialComparison or None.
        endpoint_id: endpoint this case belongs to.
        classified_at: ISO timestamp shared by all cases of the run.
    """
    analysis = case_result.analysis
    comparison_evidence = None
    if comparison is not None:
        comparison_evidence = ComparisonEvidence(
            cross_case_id=comparison.cross_case_id,
            baseline_case_id=comparison.baseline_case_id,
            requester_label=comparison.requester_label,
            owner_label=comparison.owner_label,
            both_bodies_parsed=comparison.both_bodies_parsed,
            matches_owner_baseline=comparison.matches_owner_baseline,
            identity_matches_resource_owner=comparison.identity_matches_resource_owner,
            resource_id_matches_request=comparison.resource_id_matches_request,
            sensitive_fields_present=list(comparison.sensitive_fields_present),
        )

    return CaseEvidence(
        case_id=case_result.case_id,
        description=case_result.description,
        endpoint_id=endpoint_id,
        requester_label=case_result.requester_label,
        owner_label=case_result.owner_label,
        expected_decision=case_result.expected_decision,
        resource_id_fingerprint=case_result.resource_id_fingerprint,
        classification=case_classification.classification,
        reason=case_classification.reason,
        classified_at=classified_at,
        status_code=case_result.status_code,
        transport_error=case_result.transport_error,
        elapsed_ms=case_result.elapsed_ms,
        body_bytes=case_result.body_bytes,
        truncated=case_result.truncated,
        access_obtained=analysis.access_obtained if analysis else False,
        identity_fields_present=list(analysis.identity_fields_present) if analysis else [],
        ownership_fields_present=list(analysis.ownership_fields_present) if analysis else [],
        resource_id_fields_present=list(analysis.resource_id_fields_present) if analysis else [],
        sensitive_fields_present=list(analysis.sensitive_fields_present) if analysis else [],
        resource_id_matches_request=analysis.resource_id_matches_request if analysis else None,
        comparison=comparison_evidence,
    )


def build_scan_evidence(scan_result, scan_classification, endpoint,
                         run_id: str) -> ScanEvidence:
    """Build the complete evidence bundle for one scan.

    Args:
        scan_result: engine ScanResult.
        scan_classification: classifier ScanClassification.
        endpoint: the EndpointDefinition that was scanned.
        run_id: identifier of this scan run (shared across endpoints).
    """
    comparisons = {c.cross_case_id: c for c in scan_result.comparisons}
    classifications = {c.case_id: c for c in scan_classification.case_classifications}
    classified_at = datetime.now(timezone.utc).isoformat()

    cases = [
        build_case_evidence(
            case_result=case,
            case_classification=classifications[case.case_id],
            comparison=comparisons.get(case.case_id),
            endpoint_id=scan_result.endpoint_id,
            classified_at=classified_at,
        )
        for case in scan_result.case_results
    ]

    return ScanEvidence(
        run_id=run_id,
        endpoint_id=scan_result.endpoint_id,
        endpoint_name=scan_result.endpoint_name,
        method=endpoint.method,
        path=endpoint.path,
        policy={
            "own_resource": endpoint.policy.own_resource,
            "cross_account": endpoint.policy.cross_account,
            "unauthenticated": endpoint.policy.unauthenticated,
        },
        started_at=scan_result.started_at,
        finished_at=scan_result.finished_at,
        overall_classification=scan_classification.overall,
        summary=scan_classification.summary,
        budget_used=scan_result.budget_used,
        budget_max=scan_result.budget_max,
        budget_exhausted=scan_result.budget_exhausted,
        cases=cases,
    )
