"""Response analysis for BOLA detection.

The analyser turns a normalised :class:`ResponseRecord` into factual
observations (status category, field presence, resource-id match,
baseline similarity) that the classifier (phase 4) compares against
the endpoint's expected policy.

Data handling rules:
  * analysis results contain only field NAMES and booleans - never
    field values, so identity values and coordinates cannot leak into
    the database or reports;
  * the raw JSON bodies are compared in memory and then discarded;
  * field lists from endpoints.json are treated as provisional hints:
    a missing field is recorded as absent, never as an error.

Field names are matched recursively through the response body because
APIs commonly nest details (e.g. location data inside a list).
"""

from dataclasses import dataclass, field

from .endpoint_loader import EndpointDefinition
from .request_handler import ResponseRecord


@dataclass
class ResponseAnalysis:
    """Factual observations about one response. No field values."""

    status_code: int | None
    transport_error: str | None
    status_success: bool
    body_bytes: int
    truncated: bool
    json_parsed: bool
    json_is_object: bool
    json_parse_error: bool
    identity_fields_present: list[str] = field(default_factory=list)
    ownership_fields_present: list[str] = field(default_factory=list)
    resource_id_fields_present: list[str] = field(default_factory=list)
    sensitive_fields_present: list[str] = field(default_factory=list)
    resource_id_matches_request: bool | None = None
    # Factual observation for the classifier: the server returned a
    # success status with body content for this request. This is NOT a
    # vulnerability verdict - the classifier compares it with policy.
    access_obtained: bool = False


@dataclass
class DifferentialComparison:
    """Comparison of a cross-account response with the owner's baseline.

    All attributes are booleans or field names; values are compared in
    memory only and never stored.
    """

    cross_case_id: str
    baseline_case_id: str
    requester_label: str
    owner_label: str
    baseline_available: bool
    # Both bodies parsed as objects?
    both_bodies_parsed: bool | None
    # Cross-account body is identical to the owner's baseline body.
    matches_owner_baseline: bool | None
    # Identity fields in the cross-account response carry the resource
    # owner's values (compared against the owner's own baseline).
    identity_matches_resource_owner: bool | None
    # Cross-account response returns the requested resource identifier.
    resource_id_matches_request: bool | None
    sensitive_fields_present: list[str] = field(default_factory=list)


def find_field_values(node, field_name: str) -> list:
    """Recursively collect all values stored under ``field_name``."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == field_name:
                found.append(value)
            found.extend(find_field_values(value, field_name))
    elif isinstance(node, list):
        for item in node:
            found.extend(find_field_values(item, field_name))
    return found


def _present_fields(body, field_names) -> list[str]:
    return [name for name in field_names if find_field_values(body, name)]


def analyze_response(
    record: ResponseRecord,
    endpoint: EndpointDefinition,
    requested_resource_id: str | None,
) -> ResponseAnalysis:
    """Analyse a single response record against an endpoint definition."""
    status_code = record.status_code
    status_success = status_code is not None and 200 <= status_code < 300
    json_body = record.json_body
    json_parsed = json_body is not None
    json_is_object = isinstance(json_body, dict)

    analysis = ResponseAnalysis(
        status_code=status_code,
        transport_error=record.transport_error,
        status_success=status_success,
        body_bytes=record.body_bytes,
        truncated=record.truncated,
        json_parsed=json_parsed,
        json_is_object=json_is_object,
        json_parse_error=record.json_parse_error,
    )

    if json_parsed:
        analysis.identity_fields_present = _present_fields(
            json_body, endpoint.identity_fields)
        analysis.ownership_fields_present = _present_fields(
            json_body, endpoint.ownership_fields)
        analysis.resource_id_fields_present = _present_fields(
            json_body, endpoint.resource_id_fields)
        analysis.sensitive_fields_present = _present_fields(
            json_body, endpoint.sensitive_fields)

        if requested_resource_id is not None and analysis.resource_id_fields_present:
            analysis.resource_id_matches_request = any(
                str(value) == str(requested_resource_id)
                for field_name in analysis.resource_id_fields_present
                for value in find_field_values(json_body, field_name)
            )

    analysis.access_obtained = status_success and (json_parsed or record.body_bytes > 0)
    return analysis


def compare_with_baseline(
    cross_record: ResponseRecord,
    baseline_record: ResponseRecord,
    cross_case_id: str,
    baseline_case_id: str,
    requester_label: str,
    owner_label: str,
    endpoint: EndpointDefinition,
    requested_resource_id: str | None,
) -> DifferentialComparison:
    """Compare a cross-account response with the owner's own baseline.

    The comparison establishes whether the cross-account response
    exposes the resource owner's data: identical bodies, matching
    identity field values and a matching resource identifier are
    strong evidence for the classifier.
    """
    comparison = DifferentialComparison(
        cross_case_id=cross_case_id,
        baseline_case_id=baseline_case_id,
        requester_label=requester_label,
        owner_label=owner_label,
        baseline_available=True,
        both_bodies_parsed=None,
        matches_owner_baseline=None,
        identity_matches_resource_owner=None,
        resource_id_matches_request=None,
    )

    cross_body = cross_record.json_body
    baseline_body = baseline_record.json_body

    if not (isinstance(cross_body, dict) and isinstance(baseline_body, dict)):
        return comparison

    comparison.both_bodies_parsed = True
    comparison.matches_owner_baseline = cross_body == baseline_body
    comparison.sensitive_fields_present = _present_fields(
        cross_body, endpoint.sensitive_fields)

    if requested_resource_id is not None and endpoint.resource_id_fields:
        comparison.resource_id_matches_request = any(
            str(value) == str(requested_resource_id)
            for field_name in endpoint.resource_id_fields
            for value in find_field_values(cross_body, field_name)
        )

    # Identity match: for every identity field present in both bodies,
    # the cross-account values must equal the owner's baseline values.
    # Null values are ignored - matching nulls carry no evidence.
    field_results = []
    for field_name in endpoint.identity_fields:
        cross_values = [v for v in find_field_values(cross_body, field_name)
                        if v is not None]
        owner_values = [v for v in find_field_values(baseline_body, field_name)
                        if v is not None]
        if cross_values and owner_values:
            field_results.append(cross_values == owner_values)
    if field_results:
        comparison.identity_matches_resource_owner = all(field_results)

    return comparison
