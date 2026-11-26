"""JSON and HTML report generation.

Reports are built exclusively from data retrieved out of the SQLite
database (never from live responses), so everything they contain has
already passed the phase 4 redaction rules. Report content:

  * executive summary with per-classification counts;
  * scope, methodology and environment sections;
  * per-endpoint test matrix and results with reasons;
  * findings with severity, confidence and remediation;
  * limitations - including honest handling of INCONCLUSIVE and
    SUSPECTED outcomes;
  * a conclusion derived from the recorded verdicts.

No vulnerability results are ever fabricated: if a scan was
inconclusive (for example the target was unreachable), the report
says so.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from apishield import __version__

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

METHODOLOGY = [
    "APIShield performs differential API security testing focused on "
    "Broken Object Level Authorization (BOLA / IDOR).",
    "For each configured endpoint a five-case matrix is executed: two "
    "legitimate baseline requests (each user accessing their own "
    "resource), two cross-account probes (each user requesting the "
    "other user's resource) and one unauthenticated control request.",
    "Every request is a read-only HTTP GET sent through a constrained "
    "client (loopback-only target validation, request budget, timeout "
    "and response-size limits, redirects disabled).",
    "Responses are analysed for status, identity, ownership, resource "
    "identifier and sensitive-field indicators, and cross-account "
    "responses are compared against the resource owner's own baseline "
    "response.",
    "Outcomes are classified against the endpoint's configured "
    "authorization policy as CONFIRMED, SUSPECTED, INCONCLUSIVE or "
    "NO_ISSUE. HTTP 200 alone is never treated as proof of BOLA.",
    "All evidence is redacted before persistence: bearer tokens, "
    "credentials, raw response bodies, personal data and location "
    "coordinates are never stored or reported; resource identifiers "
    "are kept only as SHA-256 fingerprints.",
]

STATIC_LIMITATIONS = [
    "Testing was limited to the endpoints defined in the scan "
    "configuration; other endpoints and HTTP methods were not assessed.",
    "Only read-only GET requests were used, so write-based "
    "authorization flaws were not exercised.",
    "Reported identity, ownership and sensitive field names depend on "
    "the endpoint configuration and remain provisional until verified "
    "against real target responses.",
    "Positive findings demonstrate the observed responses only; full "
    "exploitability assessment requires manual validation.",
]


def build_report_data(run_data: dict) -> dict:
    """Assemble the full report structure from a stored run."""
    endpoints = run_data["endpoints"]
    counts = _classification_counts(endpoints)

    limitations = list(STATIC_LIMITATIONS)
    limitations.extend(_dynamic_limitations(endpoints))

    return {
        "title": "APIShield BOLA Assessment Report",
        "tool": {"name": "APIShield", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_data["run_id"],
        "target": run_data["target"],
        "executive_summary": {
            "overall_classification": run_data["overall"],
            "counts": counts,
            "summary": _executive_summary_text(run_data["overall"], counts),
        },
        "scope": {
            "target": run_data["target"],
            "endpoints": [
                {
                    "endpoint_id": e["endpoint_id"],
                    "name": e["endpoint_name"],
                    "method": e["method"],
                    "path": e["path"],
                    "policy": e["policy"],
                }
                for e in endpoints
            ],
            "identities": _identity_labels(endpoints),
            "request_budget": _budget_summary(endpoints),
        },
        "methodology": METHODOLOGY,
        "test_matrix": [
            {
                "endpoint_id": e["endpoint_id"],
                "cases": [_matrix_row(case) for case in e["cases"]],
            }
            for e in endpoints
        ],
        "results": [
            {
                "endpoint_id": e["endpoint_id"],
                "endpoint_name": e["endpoint_name"],
                "overall_classification": e["overall_classification"],
                "summary": e["summary"],
                "cases": e["cases"],
            }
            for e in endpoints
        ],
        "findings": [finding for e in endpoints for finding in e["findings"]],
        "limitations": limitations,
        "conclusion": _conclusion_text(run_data["overall"], counts),
    }


def write_json_report(report_data: dict, output_path: Path) -> Path:
    """Write the JSON report and return its path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report_data, indent=2), encoding="utf-8"
    )
    return output_path


def render_html_report(report_data: dict, template_name: str = "report.html") -> str:
    """Render the HTML report and return it as a string."""
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    template = environment.get_template(template_name)
    return template.render(report=report_data)


def write_html_report(report_data: dict, output_path: Path,
                      template_name: str = "report.html") -> Path:
    """Render and write the HTML report, returning its path."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_html_report(report_data, template_name), encoding="utf-8"
    )
    return output_path


# ----------------------------------------------------------------------
# Content helpers
# ----------------------------------------------------------------------

CLASSIFICATIONS = ("CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "NO_ISSUE")


def _classification_counts(endpoints: list[dict]) -> dict:
    counts = {name: 0 for name in CLASSIFICATIONS}
    for endpoint in endpoints:
        for case in endpoint["cases"]:
            counts[case["classification"]] = counts.get(case["classification"], 0) + 1
    return counts


def _executive_summary_text(overall: str, counts: dict) -> str:
    if overall == "CONFIRMED":
        return (
            f"Differential testing produced {counts['CONFIRMED']} confirmed "
            "Broken Object Level Authorization finding(s): cross-account "
            "requests returned data that the configured policy requires to "
            "be denied, verified against the resource owner's baseline."
        )
    if overall == "SUSPECTED":
        return (
            f"Differential testing produced {counts['SUSPECTED']} suspected "
            "authorization weakness(es). Access to protected resources "
            "succeeded but the exposure of owner data could not be fully "
            "verified; manual validation is recommended."
        )
    if overall == "INCONCLUSIVE":
        return (
            "Differential testing could not establish a definitive verdict "
            "for this run (unreachable endpoint, skipped cases, failed "
            "baselines or ambiguous responses). No vulnerability conclusion "
            "should be drawn from this run."
        )
    return (
        "No authorization issues were detected: observed access matched the "
        "configured policy for every case in this run."
    )


def _identity_labels(endpoints: list[dict]) -> list:
    labels = set()
    for endpoint in endpoints:
        for case in endpoint["cases"]:
            labels.add(case["requester_label"])
            labels.add(case["owner_label"])
    return sorted(labels)


def _budget_summary(endpoints: list[dict]) -> dict:
    last = endpoints[-1]["budget"]
    return {
        "max_per_scan": last["max"],
        "total_used": sum(e["budget"]["used"] for e in endpoints),
        "exhausted": any(e["budget"]["exhausted"] for e in endpoints),
    }


def _dynamic_limitations(endpoints: list[dict]) -> list:
    limitations = []
    if any(e["budget"]["exhausted"] for e in endpoints):
        limitations.append(
            "The per-scan request budget was exhausted; not all test cases "
            "were executed."
        )
    skipped = sum(
        1 for e in endpoints for case in e["cases"]
        if case["status_code"] is None and case["transport_error"]
    )
    if skipped:
        limitations.append(
            f"{skipped} case(s) failed at the transport level; their "
            "outcomes are inconclusive."
        )
    inconclusive = sum(
        1 for e in endpoints for case in e["cases"]
        if case["classification"] == "INCONCLUSIVE"
    )
    if inconclusive:
        limitations.append(
            f"{inconclusive} case(s) were classified INCONCLUSIVE and "
            "contribute no vulnerability evidence in either direction."
        )
    return limitations


def _matrix_row(case: dict) -> dict:
    return {
        "case_id": case["case_id"],
        "requester_label": case["requester_label"],
        "owner_label": case["owner_label"],
        "expected_decision": case["expected_decision"],
        "status_code": case["status_code"],
        "transport_error": case["transport_error"],
        "access_obtained": case["access_obtained"],
        "classification": case["classification"],
        "reason": case["reason"],
    }


def _conclusion_text(overall: str, counts: dict) -> str:
    if overall == "CONFIRMED":
        return (
            "The differential evidence indicates that object-level "
            "authorization is missing or ineffective on the affected "
            "endpoint(s). Authentication is enforced, but authorization "
            "of the requesting user against the referenced object is not. "
            "The remediation guidance in the findings section should be "
            "applied and the scan re-run to verify the fix."
        )
    if overall == "SUSPECTED":
        return (
            "Access behaviour inconsistent with the configured policy was "
            "observed, but the differential evidence was not strong enough "
            "to confirm unauthorized data exposure. Manually verify the "
            "suspected cases before treating them as vulnerabilities."
        )
    if overall == "INCONCLUSIVE":
        return (
            "This run did not produce a definitive assessment. Re-run the "
            "scan when the target is reachable and fully within budget "
            "before drawing conclusions."
        )
    return (
        "All executed cases matched the configured authorization policy. "
        "No Broken Object Level Authorization issue was detected within "
        "the scope of this run."
    )
