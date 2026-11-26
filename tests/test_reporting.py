"""Unit tests for JSON and HTML report generation.

Reports are built from persisted (already redacted) run data. Tests
cover structure, honest handling of inconclusive runs, redaction and
both output formats.
"""

import json

import responses as responses_lib

from apishield.database import Database
from apishield.evidence import build_scan_evidence
from apishield.reporting import (
    build_report_data,
    render_html_report,
    write_html_report,
    write_json_report,
)

from test_evidence import run_mocked_scan

FORBIDDEN_RAW_VALUES = [
    "token-a", "token-b", "veh-a", "veh-b",
    "User A Name", "User B Name", "usera@apishield.local",
    "11.11", "22.22", "33.33", "44.44",
]

REPORT_SECTIONS = [
    "title", "generated_at", "run_id", "target",
    "executive_summary", "scope", "methodology", "test_matrix",
    "results", "findings", "limitations", "conclusion",
]


def persist_mocked_run(tmp_path, budget_max=50, run_id="run-report"):
    scan, classification, endpoint = run_mocked_scan(budget_max=budget_max)
    evidence = build_scan_evidence(scan, classification, endpoint, run_id)
    db = Database(tmp_path / "apishield.db")
    db.save_scan(evidence, target="http://127.0.0.1:8888")
    run_data = db.get_run(run_id)
    db.close()
    return run_data


class TestReportData:
    @responses_lib.activate
    def test_report_contains_all_sections(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        for section in REPORT_SECTIONS:
            assert section in report, f"Missing report section {section!r}"

    @responses_lib.activate
    def test_executive_summary_counts(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        counts = report["executive_summary"]["counts"]
        assert counts["CONFIRMED"] == 2     # B03, B04
        assert counts["NO_ISSUE"] == 3      # B01, B02, B05
        assert report["executive_summary"]["overall_classification"] == "CONFIRMED"

    @responses_lib.activate
    def test_findings_include_remediation(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        assert len(report["findings"]) == 2
        for finding in report["findings"]:
            assert finding["severity"] == "High"
            assert "object-level authorization" in finding["remediation"]

    @responses_lib.activate
    def test_methodology_and_limitations_present(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        assert len(report["methodology"]) >= 5
        assert any("GET" in item for item in report["limitations"])

    @responses_lib.activate
    def test_conclusion_matches_verdict(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        assert "object-level" in report["conclusion"].lower()


class TestInconclusiveRuns:
    def test_offline_run_is_reported_honestly(self, tmp_path, monkeypatch):
        # Simulate an unreachable target by making every request fail.
        from apishield.bola_engine import BolaEngine
        from apishield.classifier import classify_scan
        from apishield.request_handler import RequestHandler
        from test_bola_engine import make_endpoint, make_registry

        monkeypatch.setattr(
            RequestHandler, "get",
            lambda self, path, identity=None, path_params=None:
                _failing_record(path, path_params),
        )
        endpoint = make_endpoint()
        engine = BolaEngine(make_registry(), RequestHandler("http://127.0.0.1:8888"))
        scan = engine.run_scan(endpoint)
        classification = classify_scan(scan)
        evidence = build_scan_evidence(scan, classification, endpoint, "offline-run")

        db = Database(tmp_path / "apishield.db")
        db.save_scan(evidence, target="http://127.0.0.1:8888")
        run_data = db.get_run("offline-run")
        db.close()

        report = build_report_data(run_data)
        assert report["executive_summary"]["overall_classification"] == "INCONCLUSIVE"
        assert report["findings"] == []
        assert "No vulnerability conclusion" in \
            report["executive_summary"]["summary"]
        assert any("transport level" in item for item in report["limitations"])

    @responses_lib.activate
    def test_empty_scan_run_is_handled(self, tmp_path):
        # All cases skipped by budget exhaustion.
        run_data = persist_mocked_run(tmp_path, budget_max=0, run_id="empty-run")
        report = build_report_data(run_data)
        assert report["executive_summary"]["overall_classification"] == "INCONCLUSIVE"
        assert report["findings"] == []
        assert any("budget was exhausted" in item
                   for item in report["limitations"])


def _failing_record(path, path_params):
    from apishield.request_handler import ResponseRecord
    record = ResponseRecord(url=f"http://127.0.0.1:8888{path}")
    record.transport_error = "connection_error"
    return record


class TestJsonExport:
    @responses_lib.activate
    def test_json_report_is_serialisable(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        path = write_json_report(report, tmp_path / "report.json")
        assert path.is_file()
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded == report

    @responses_lib.activate
    def test_json_report_contains_no_secrets(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        rendered = json.dumps(report)
        for forbidden in FORBIDDEN_RAW_VALUES:
            assert forbidden not in rendered


class TestHtmlReport:
    @responses_lib.activate
    def test_html_report_renders_sections(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        html = render_html_report(report)
        for marker in [
            "APIShield BOLA Assessment Report",
            "Executive Summary", "Scope", "Methodology", "Test Matrix",
            "Findings", "Redacted Evidence", "Limitations", "Conclusion",
            "B03", "CONFIRMED", "Remediation",
        ]:
            assert marker in html, f"HTML report missing {marker!r}"

    @responses_lib.activate
    def test_html_report_contains_no_secrets(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        html = render_html_report(report)
        for forbidden in FORBIDDEN_RAW_VALUES:
            assert forbidden not in html

    @responses_lib.activate
    def test_html_report_written_to_file(self, tmp_path):
        report = build_report_data(persist_mocked_run(tmp_path))
        path = write_html_report(report, tmp_path / "out" / "report.html")
        assert path.is_file()
        assert "<html" in path.read_text(encoding="utf-8")

    @responses_lib.activate
    def test_html_escapes_case_text(self, tmp_path):
        # Case reasons are attacker-influenced text and must be escaped.
        run_data = persist_mocked_run(tmp_path)
        run_data["endpoints"][0]["cases"][0]["reason"] = \
            "<script>alert(1)</script>"
        report = build_report_data(run_data)
        html = render_html_report(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    @responses_lib.activate
    def test_html_for_inconclusive_run_has_no_findings(self, tmp_path):
        run_data = persist_mocked_run(tmp_path, budget_max=0, run_id="no-run")
        report = build_report_data(run_data)
        html = render_html_report(report)
        assert "No CONFIRMED or SUSPECTED findings" in html
