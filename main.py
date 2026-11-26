#!/usr/bin/env python3
"""APIShield command-line interface.

Commands:
  check            Validate the target URL and required configuration.
  validate-config  Validate environment variables only.
  list-endpoints   Show configured endpoints and their policies.
  scan             Run the B01-B05 differential matrix against the target
                   and persist redacted evidence.
  results          List recorded scan runs.
  report           Export a run as a JSON or HTML report.
"""

import argparse
import json
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from apishield.authentication import IdentityRegistry
from apishield.bola_engine import BolaEngine
from apishield.classifier import classify_scan
from apishield.config import ConfigurationError, load_config
from apishield.database import Database, DatabaseError
from apishield.endpoint_loader import EndpointConfigError, load_endpoints
from apishield.evidence import build_scan_evidence
from apishield.request_handler import RequestBudget, RequestHandler, RequestLimits
from apishield.reporting import (
    build_report_data,
    write_html_report,
    write_json_report,
)
from apishield.target_validator import TargetValidationError, validate_base_url

ENDPOINTS_PATH = PROJECT_ROOT / "config" / "endpoints.json"


def load_settings() -> dict:
    settings_path = PROJECT_ROOT / "config" / "settings.json"
    return json.loads(settings_path.read_text(encoding="utf-8"))


def database_path() -> Path:
    settings = load_settings()
    return PROJECT_ROOT / settings.get("paths", {}).get(
        "database", "evidence/apishield.db")


def reports_dir() -> Path:
    settings = load_settings()
    return PROJECT_ROOT / settings.get("paths", {}).get("reports_dir", "reports")


def build_limits_and_budget(settings: dict) -> tuple[RequestLimits, RequestBudget]:
    request_cfg = settings.get("request", {})
    limits = RequestLimits(
        timeout_seconds=request_cfg.get("timeout_seconds", 10),
        max_response_bytes=request_cfg.get("max_response_bytes", 1_048_576),
        allow_redirects=request_cfg.get("allow_redirects", False),
        verify_tls=request_cfg.get("verify_tls", True),
        user_agent=request_cfg.get("user_agent", "APIShield/0.1"),
    )
    budget = RequestBudget(max_requests=request_cfg.get("max_requests_per_run", 50))
    return limits, budget


def load_selected_endpoints(endpoint_id: str | None) -> list:
    endpoints = load_endpoints(ENDPOINTS_PATH)
    if endpoint_id:
        matching = [e for e in endpoints if e.endpoint_id == endpoint_id]
        if not matching:
            known = ", ".join(e.endpoint_id for e in endpoints)
            print(f"[!] Unknown endpoint {endpoint_id!r}. Configured: {known}")
            raise SystemExit(2)
        return matching
    return endpoints


def cmd_check(args: argparse.Namespace) -> int:
    """Validate configuration and target, without sending any requests."""
    try:
        config = load_config()
    except ConfigurationError as exc:
        print(f"[!] Configuration error: {exc}")
        return 2

    try:
        base_url = validate_base_url(config.base_url)
    except TargetValidationError as exc:
        print(f"[!] Target rejected: {exc}")
        return 2

    registry = IdentityRegistry(config)
    print("[+] Configuration valid")
    print(f"[+] Target: {base_url} (literal loopback IP)")
    print(f"[+] Identities available: {', '.join(registry.labels)}")
    print("[+] No requests were sent.")
    return 0


def cmd_validate_config(args: argparse.Namespace) -> int:
    """Check that all required environment variables are present."""
    try:
        load_config()
    except ConfigurationError as exc:
        print(f"[!] {exc}")
        return 2
    print("[+] All required environment variables are set.")
    return 0


def cmd_list_endpoints(args: argparse.Namespace) -> int:
    """Show configured endpoints, methods and expected policies."""
    try:
        endpoints = load_endpoints(ENDPOINTS_PATH)
    except EndpointConfigError as exc:
        print(f"[!] {exc}")
        return 2

    for endpoint in endpoints:
        policy = endpoint.policy
        print(f"{endpoint.endpoint_id}: {endpoint.name}")
        print(f"  method : {endpoint.method} {endpoint.path}")
        print(f"  policy : own={policy.own_resource}, "
              f"cross-account={policy.cross_account}, "
              f"unauthenticated={policy.unauthenticated}")
        if endpoint.sensitive_fields:
            print(f"  sensitive fields: {', '.join(endpoint.sensitive_fields)}")
    return 0


def _print_case_result(case) -> None:
    if not case.executed:
        print(f"  [{case.case_id}] {case.description}")
        print(f"        requester={case.requester_label} owner={case.owner_label} "
              f"expected={case.expected_decision}")
        print(f"        SKIPPED ({case.skipped_reason})")
        return

    sensitive = ", ".join(case.analysis.sensitive_fields_present) if case.analysis else "-"
    access = "yes" if (case.analysis and case.analysis.access_obtained) else "no"
    status = case.status_code if case.status_code is not None else "n/a"
    if case.transport_error:
        status = f"transport_error({case.transport_error})"
    elapsed = f"{case.elapsed_ms}ms" if case.elapsed_ms is not None else "n/a"

    print(f"  [{case.case_id}] {case.description}")
    print(f"        requester={case.requester_label} owner={case.owner_label} "
          f"expected={case.expected_decision}")
    print(f"        status={status} access_obtained={access} "
          f"elapsed={elapsed} sensitive_fields={sensitive}")


def _print_comparisons(scan_result) -> None:
    if not scan_result.comparisons:
        return
    print("  Differential comparisons (cross-account vs owner baseline):")
    for comp in scan_result.comparisons:
        identity = comp.identity_matches_resource_owner
        identity = "n/a" if identity is None else ("yes" if identity else "no")
        matches = comp.matches_owner_baseline
        matches = "n/a" if matches is None else ("yes" if matches else "no")
        print(f"    {comp.cross_case_id} vs {comp.baseline_case_id}: "
              f"owner_data_returned={matches} identity_of_owner={identity}")


def _print_classifications(classification) -> None:
    for case in classification.case_classifications:
        print(f"  [{case.case_id}] {case.classification}")
        print(f"        {case.reason}")
    print(f"  Overall: {classification.overall} - {classification.summary}")


def cmd_scan(args: argparse.Namespace) -> int:
    """Run the B01-B05 differential matrix against the target."""
    try:
        config = load_config()
    except ConfigurationError as exc:
        print(f"[!] Configuration error: {exc}")
        return 2

    try:
        base_url = validate_base_url(config.base_url)
    except TargetValidationError as exc:
        print(f"[!] Target rejected: {exc}")
        return 2

    try:
        endpoints = load_selected_endpoints(args.endpoint)
    except EndpointConfigError as exc:
        print(f"[!] {exc}")
        return 2

    limits, budget = build_limits_and_budget(load_settings())
    handler = RequestHandler(base_url, limits=limits, budget=budget)
    registry = IdentityRegistry(config)
    engine = BolaEngine(registry, handler)
    run_id = uuid.uuid4().hex

    for endpoint in endpoints:
        print(f"[*] Scanning endpoint: {endpoint.endpoint_id} "
              f"({endpoint.method} {endpoint.path})")
        result = engine.run_scan(endpoint)
        _print_case_result_batch(result)
        _print_comparisons(result)

        budget_note = f"budget: {result.budget_used}/{result.budget_max}"
        if result.budget_exhausted:
            budget_note += " (EXHAUSTED - remaining cases skipped)"
        print(f"  {budget_note}, skipped={result.skipped_count}")

        classification = classify_scan(result)
        _print_classifications(classification)

        evidence = build_scan_evidence(result, classification, endpoint, run_id)
        try:
            database = Database(database_path())
        except DatabaseError as exc:
            print(f"[!] {exc}")
            return 2
        try:
            database.save_scan(evidence, target=base_url)
        except DatabaseError as exc:
            print(f"[!] {exc}")
            database.close()
            return 2
        database.close()
        print(f"  Evidence saved to {database_path()} "
              f"(run_id={run_id[:8]}, {len(evidence.cases)} cases, redacted).")

    print(f"[*] Scan complete. Use 'report --run {run_id[:8]}' to export results.")
    return 0


def _print_case_result_batch(result) -> None:
    for case in result.case_results:
        _print_case_result(case)


def cmd_results(args: argparse.Namespace) -> int:
    """List recorded scan runs from the database."""
    try:
        database = Database(database_path())
    except DatabaseError as exc:
        print(f"[!] {exc}")
        return 2

    try:
        runs = database.list_runs()
    except DatabaseError as exc:
        print(f"[!] {exc}")
        database.close()
        return 2
    database.close()

    if not runs:
        print("[*] No scan runs recorded yet. Run 'scan' first.")
        return 0

    for run in runs:
        print(f"{run['run_id'][:8]}  {run['endpoint_id']:<20} "
              f"{run['overall_classification']:<13} "
              f"{run['started_at'] or '-'}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Export a recorded scan run as a JSON or HTML report."""
    try:
        database = Database(database_path())
    except DatabaseError as exc:
        print(f"[!] {exc}")
        return 2

    try:
        run_id = args.run or database.latest_run_id()
        if run_id is None:
            print("[*] No scan runs recorded yet. Run 'scan' first.")
            return 0
        run_data = database.get_run(run_id)
        if run_data is None:
            # Allow the short run-id prefix printed by the CLI.
            matches = [r for r in database.list_runs()
                       if r["run_id"].startswith(run_id)]
            if len(matches) == 1:
                run_id = matches[0]["run_id"]
                run_data = database.get_run(run_id)
            else:
                print(f"[!] No unique run found with id {run_id!r}.")
                return 2
    except DatabaseError as exc:
        print(f"[!] {exc}")
        return 2
    finally:
        database.close()

    report_data = build_report_data(run_data)

    default_name = f"report-{run_id[:8]}.{args.format}"
    output = Path(args.output) if args.output else reports_dir() / default_name

    try:
        if args.format == "json":
            path = write_json_report(report_data, output)
        else:
            path = write_html_report(report_data, output)
    except OSError as exc:
        print(f"[!] Could not write report: {exc}")
        return 2

    print(f"[+] Report written: {path}")
    print(f"    Run {run_id[:8]}, overall verdict: "
          f"{report_data['executive_summary']['overall_classification']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apishield",
        description="APIShield - differential BOLA/IDOR API testing tool",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="validate target and configuration")
    sub.add_parser("validate-config", help="validate environment variables")
    sub.add_parser("list-endpoints", help="list configured endpoints and policies")

    scan_parser = sub.add_parser("scan", help="run the BOLA differential matrix")
    scan_parser.add_argument(
        "--endpoint",
        metavar="ID",
        help="scan only the endpoint with this endpoint_id",
    )

    sub.add_parser("results", help="list recorded scan runs")

    report_parser = sub.add_parser("report", help="export a run as JSON or HTML")
    report_parser.add_argument(
        "--format",
        choices=("json", "html"),
        default="html",
        help="report format (default: html)",
    )
    report_parser.add_argument(
        "--run",
        metavar="RUNID",
        help="run id to report (default: most recent run)",
    )
    report_parser.add_argument(
        "--output",
        metavar="PATH",
        help="output file path (default: reports/report-<runid>.<ext>)",
    )

    return parser


COMMANDS = {
    "check": cmd_check,
    "validate-config": cmd_validate_config,
    "list-endpoints": cmd_list_endpoints,
    "scan": cmd_scan,
    "results": cmd_results,
    "report": cmd_report,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
