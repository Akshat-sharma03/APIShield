"""The BOLA differential testing engine.

For each endpoint definition the engine executes the standard five
case matrix:

  B01  user_a -> user_a's resource   (legitimate baseline)
  B02  user_b -> user_b's resource   (legitimate baseline)
  B03  user_a -> user_b's resource   (cross-account probe)
  B04  user_b -> user_a's resource   (cross-account probe)
  B05  anonymous -> user_b's resource (unauthenticated control)

The EXPECTED outcome of every case is read from the endpoint's
configured policy - never hardcoded. The engine records what actually
happened (factually, without interpretation); classification is the
responsibility of the classifier module.

Execution rules:
  * only GET requests, via the request handler and its safety limits;
  * each scan uses a fresh per-scan request budget; exhaustion skips
    the remaining cases gracefully and is reported in the summary;
  * response records live in memory only during the scan; the results
    carry redacted analyses (field names and booleans, no values);
  * the engine assumes the base URL was already validated as a
    literal loopback address by the caller.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .authentication import ANONYMOUS, USER_A, USER_B, IdentityRegistry
from .endpoint_loader import EndpointDefinition
from .evidence import fingerprint_identifier
from .request_handler import (
    RequestBudgetExceeded,
    RequestHandler,
    ResponseRecord,
)
from .response_analyzer import (
    DifferentialComparison,
    ResponseAnalysis,
    analyze_response,
    compare_with_baseline,
)

BUDGET_EXHAUSTED_REASON = "request_budget_exhausted"


@dataclass(frozen=True)
class CaseSpec:
    """One planned test case, derived from the endpoint policy."""

    case_id: str
    description: str
    requester_label: str
    owner_label: str
    expected_decision: str  # "ALLOW" or "DENY", from the endpoint policy
    resource_id: str | None


@dataclass
class CaseResult:
    """Outcome of one test case. Contains no secrets or field values."""

    case_id: str
    description: str
    requester_label: str
    owner_label: str
    expected_decision: str
    executed: bool
    skipped_reason: str | None = None
    # Hashed resource identifier (SHA-256 prefix) for correlating
    # evidence without storing the real identifier.
    resource_id_fingerprint: str | None = None
    status_code: int | None = None
    transport_error: str | None = None
    elapsed_ms: int | None = None
    body_bytes: int = 0
    truncated: bool = False
    analysis: ResponseAnalysis | None = None


@dataclass
class ScanResult:
    """Complete result of one endpoint scan."""

    endpoint_id: str
    endpoint_name: str
    started_at: str
    finished_at: str
    case_results: list[CaseResult] = field(default_factory=list)
    comparisons: list[DifferentialComparison] = field(default_factory=list)
    budget_used: int = 0
    budget_max: int = 0
    budget_exhausted: bool = False

    @property
    def skipped_count(self) -> int:
        return sum(1 for case in self.case_results if not case.executed)


class BolaEngine:
    """Executes the B01-B05 differential matrix for endpoints."""

    def __init__(self, registry: IdentityRegistry, handler: RequestHandler):
        self._registry = registry
        self._handler = handler

    def run_scan(self, endpoint: EndpointDefinition) -> ScanResult:
        """Run the full test matrix for one endpoint."""
        started = datetime.now(timezone.utc)
        specs = self._build_case_specs(endpoint)

        case_results: list[CaseResult] = []
        records: dict[str, ResponseRecord] = {}

        budget_exhausted = False
        for spec in specs:
            if budget_exhausted:
                case_results.append(self._skipped_result(spec))
                continue
            try:
                record = self._execute_case(spec, endpoint)
            except RequestBudgetExceeded:
                budget_exhausted = True
                case_results.append(self._skipped_result(spec))
                continue
            records[spec.case_id] = record
            case_results.append(self._build_result(spec, record, endpoint))

        comparisons = self._run_comparisons(endpoint, case_results, records, specs)

        finished = datetime.now(timezone.utc)
        return ScanResult(
            endpoint_id=endpoint.endpoint_id,
            endpoint_name=endpoint.name,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            case_results=case_results,
            comparisons=comparisons,
            budget_used=self._handler.budget.used,
            budget_max=self._handler.budget.max_requests,
            budget_exhausted=budget_exhausted,
        )

    def _build_case_specs(self, endpoint: EndpointDefinition) -> list[CaseSpec]:
        """Derive the B01-B05 matrix from the endpoint policy."""
        policy = endpoint.policy
        user_a = self._registry.get(USER_A)
        user_b = self._registry.get(USER_B)
        anonymous = self._registry.get(ANONYMOUS)

        def own_case(case_id, description, requester_label, identity):
            return CaseSpec(
                case_id=case_id,
                description=description,
                requester_label=requester_label,
                owner_label=requester_label,
                expected_decision=policy.own_resource,
                resource_id=identity.resource_id,
            )

        def cross_case(case_id, description, requester_label, owner_label, resource_id):
            return CaseSpec(
                case_id=case_id,
                description=description,
                requester_label=requester_label,
                owner_label=owner_label,
                expected_decision=policy.cross_account,
                resource_id=resource_id,
            )

        anonymous_case = CaseSpec(
            case_id="B05",
            description="Unauthenticated control request",
            requester_label=anonymous.label,
            owner_label=USER_B,
            expected_decision=policy.unauthenticated,
            resource_id=user_b.resource_id,
        )

        return [
            own_case("B01", "User A accesses own resource", USER_A, user_a),
            own_case("B02", "User B accesses own resource", USER_B, user_b),
            cross_case("B03", "User A accesses User B's resource", USER_A, USER_B, user_b.resource_id),
            cross_case("B04", "User B accesses User A's resource", USER_B, USER_A, user_a.resource_id),
            anonymous_case,
        ]

    def _execute_case(self, spec: CaseSpec, endpoint: EndpointDefinition) -> ResponseRecord:
        """Send the request for one case through the safe request handler."""
        identity = self._registry.get(spec.requester_label)
        path_params = {endpoint.resource_id_variable: spec.resource_id}
        return self._handler.get(
            endpoint.path,
            identity=identity,
            path_params=path_params,
        )

    def _build_result(self, spec: CaseSpec, record: ResponseRecord,
                      endpoint: EndpointDefinition) -> CaseResult:
        analysis = analyze_response(record, endpoint, spec.resource_id)
        return CaseResult(
            case_id=spec.case_id,
            description=spec.description,
            requester_label=spec.requester_label,
            owner_label=spec.owner_label,
            expected_decision=spec.expected_decision,
            executed=True,
            resource_id_fingerprint=(
                fingerprint_identifier(spec.resource_id)
                if spec.resource_id is not None else None
            ),
            status_code=record.status_code,
            transport_error=record.transport_error,
            elapsed_ms=record.elapsed_ms,
            body_bytes=record.body_bytes,
            truncated=record.truncated,
            analysis=analysis,
        )

    def _skipped_result(self, spec: CaseSpec) -> CaseResult:
        return CaseResult(
            case_id=spec.case_id,
            description=spec.description,
            requester_label=spec.requester_label,
            owner_label=spec.owner_label,
            expected_decision=spec.expected_decision,
            executed=False,
            skipped_reason=BUDGET_EXHAUSTED_REASON,
            resource_id_fingerprint=(
                fingerprint_identifier(spec.resource_id)
                if spec.resource_id is not None else None
            ),
        )

    def _run_comparisons(self, endpoint: EndpointDefinition,
                         case_results: list[CaseResult],
                         records: dict, specs: list[CaseSpec]) -> list[DifferentialComparison]:
        """Compare each cross-account probe with the owner's baseline."""
        spec_by_id = {spec.case_id: spec for spec in specs}
        comparisons = []

        # Map resource owner to their own-resource baseline case id.
        baseline_for_owner = {result.owner_label: result.case_id
                              for result in case_results
                              if result.executed and result.requester_label == result.owner_label}

        for result in case_results:
            if not result.executed or result.requester_label == result.owner_label:
                continue  # only cross-account or anonymous cases get compared

            baseline_case_id = baseline_for_owner.get(result.owner_label)
            if baseline_case_id is None:
                continue  # baseline was skipped; classifier will see gaps

            baseline_record = records[baseline_case_id]
            cross_record = records[result.case_id]

            # Transport-level failures carry no comparable evidence.
            if not cross_record.ok or not baseline_record.ok:
                continue

            spec = spec_by_id[result.case_id]

            comparisons.append(compare_with_baseline(
                cross_record=cross_record,
                baseline_record=baseline_record,
                cross_case_id=result.case_id,
                baseline_case_id=baseline_case_id,
                requester_label=result.requester_label,
                owner_label=result.owner_label,
                endpoint=endpoint,
                requested_resource_id=spec.resource_id,
            ))
        return comparisons
