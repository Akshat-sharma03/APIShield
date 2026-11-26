"""Unit tests for SQLite persistence.

Evidence bundles are produced by the mocked engine scan (no real HTTP)
and persisted into a temporary database. Tests verify schema creation,
round trips, redaction and graceful error handling.
"""

import pytest
import responses as responses_lib

from apishield.database import Database, DatabaseError

from test_evidence import run_mocked_scan

# Raw values that must never reach the database.
FORBIDDEN_RAW_VALUES = [
    "token-a", "token-b", "veh-a", "veh-b",
    "User A Name", "User B Name", "usera@apishield.local",
    "11.11", "22.22", "33.33", "44.44",
]


def dump_all_rows(db: Database) -> str:
    """Concatenate every value stored in every table."""
    parts = []
    for table in ("test_runs", "test_cases", "findings"):
        rows = db._conn.execute(f"SELECT * FROM {table}").fetchall()
        for row in rows:
            parts.append(" | ".join(str(v) for v in row))
    return "\n".join(parts)


def build_and_save(tmp_path, budget_max=50, run_id="run-abc123"):
    """Run a mocked scan, classify it and persist the evidence."""
    scan, classification, endpoint = run_mocked_scan(budget_max=budget_max)
    from apishield.evidence import build_scan_evidence
    evidence = build_scan_evidence(scan, classification, endpoint, run_id)

    db = Database(tmp_path / "apishield.db")
    db.save_scan(evidence, target="http://127.0.0.1:8888")
    return db, evidence


class TestSchema:
    def test_tables_are_created(self, tmp_path):
        db = Database(tmp_path / "apishield.db")
        tables = {
            row["name"] for row in db._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert {"test_runs", "test_cases", "findings"} <= tables
        db.close()

    def test_schema_is_idempotent(self, tmp_path):
        path = tmp_path / "apishield.db"
        first = Database(path)
        first.close()
        second = Database(path)  # must not fail on re-open
        second.close()

    def test_database_directory_is_created(self, tmp_path):
        db = Database(tmp_path / "nested" / "dir" / "apishield.db")
        assert (tmp_path / "nested" / "dir" / "apishield.db").is_file()
        db.close()


class TestPersistence:
    @responses_lib.activate
    def test_save_and_retrieve_full_run(self, tmp_path):
        db, evidence = build_and_save(tmp_path)
        run = db.get_run("run-abc123")
        db.close()

        assert run["run_id"] == "run-abc123"
        assert run["target"] == "http://127.0.0.1:8888"
        assert run["overall"] == "CONFIRMED"
        assert len(run["endpoints"]) == 1

        endpoint = run["endpoints"][0]
        assert endpoint["endpoint_id"] == "vehicle_location"
        assert endpoint["method"] == "GET"
        assert endpoint["policy"]["cross_account"] == "DENY"
        assert len(endpoint["cases"]) == 5
        assert endpoint["budget"]["used"] == 5

    @responses_lib.activate
    def test_case_round_trip(self, tmp_path):
        db, _ = build_and_save(tmp_path)
        run = db.get_run("run-abc123")
        db.close()

        cases = {c["case_id"]: c for c in run["endpoints"][0]["cases"]}
        b03 = cases["B03"]
        assert b03["requester_label"] == "user_a"
        assert b03["owner_label"] == "user_b"
        assert b03["expected_decision"] == "DENY"
        assert b03["status_code"] == 200
        assert b03["access_obtained"] is True
        assert b03["classification"] == "CONFIRMED"
        assert b03["reason"]
        assert b03["fields_present"]["sensitive_fields"] == ["latitude", "longitude"]
        assert b03["comparison"]["baseline_case_id"] == "B02"
        assert b03["comparison"]["identity_matches_resource_owner"] is True

        b05 = cases["B05"]
        assert b05["classification"] == "NO_ISSUE"
        assert b05["status_code"] == 401

    @responses_lib.activate
    def test_findings_stored_for_confirmed_and_suspected_only(self, tmp_path):
        db, _ = build_and_save(tmp_path)
        run = db.get_run("run-abc123")
        db.close()

        findings = run["endpoints"][0]["findings"]
        confirmed = [f for f in findings if f["classification"] == "CONFIRMED"]
        assert {f["case_id"] for f in confirmed} == {"B03", "B04"}
        for finding in confirmed:
            assert finding["severity"] == "High"
            assert finding["confidence"] == "High"
            assert "object-level authorization" in finding["remediation"]

    @responses_lib.activate
    def test_multiple_endpoints_share_run_id(self, tmp_path):
        scan, classification, endpoint = run_mocked_scan()
        from apishield.evidence import build_scan_evidence
        evidence = build_scan_evidence(scan, classification, endpoint, "shared-run")

        db = Database(tmp_path / "apishield.db")
        db.save_scan(evidence, target="http://127.0.0.1:8888")
        # Save the same run for a second (cloned) endpoint id.
        from dataclasses import replace
        second = replace(evidence, endpoint_id="vehicle_location_2")
        db.save_scan(second, target="http://127.0.0.1:8888")
        db.close()

        db = Database(tmp_path / "apishield.db")
        run = db.get_run("shared-run")
        db.close()
        assert len(run["endpoints"]) == 2
        assert {e["endpoint_id"] for e in run["endpoints"]} == {
            "vehicle_location", "vehicle_location_2"}

    @responses_lib.activate
    def test_list_runs_returns_summaries(self, tmp_path):
        db, _ = build_and_save(tmp_path)
        runs = db.list_runs()
        db.close()
        assert len(runs) == 1
        assert runs[0]["endpoint_id"] == "vehicle_location"
        assert runs[0]["overall_classification"] == "CONFIRMED"

    @responses_lib.activate
    def test_latest_run_id(self, tmp_path):
        db, _ = build_and_save(tmp_path)
        assert db.latest_run_id() == "run-abc123"
        db.close()

    @responses_lib.activate
    def test_unknown_run_returns_none(self, tmp_path):
        db, _ = build_and_save(tmp_path)
        assert db.get_run("does-not-exist") is None
        db.close()

    def test_empty_database_lists_nothing(self, tmp_path):
        db = Database(tmp_path / "apishield.db")
        assert db.list_runs() == []
        assert db.latest_run_id() is None
        db.close()


class TestRedaction:
    @responses_lib.activate
    def test_no_secrets_or_values_in_database(self, tmp_path):
        db, _ = build_and_save(tmp_path)
        dumped = dump_all_rows(db)
        db.close()
        for forbidden in FORBIDDEN_RAW_VALUES:
            assert forbidden not in dumped, (
                f"Database leaked sensitive value {forbidden!r}")

    @responses_lib.activate
    def test_resource_ids_stored_as_fingerprints(self, tmp_path):
        db, _ = build_and_save(tmp_path)
        run = db.get_run("run-abc123")
        db.close()
        cases = run["endpoints"][0]["cases"]
        fingerprints = {c["resource_id_fingerprint"] for c in cases}
        assert None not in fingerprints
        assert len(fingerprints) == 2  # A's and B's resources


class TestErrorHandling:
    def test_invalid_database_path_raises_database_error(self, tmp_path):
        # A directory where the database file should be.
        blocker = tmp_path / "apishield.db"
        blocker.mkdir()
        with pytest.raises(DatabaseError, match="Could not open database"):
            Database(blocker)

    @responses_lib.activate
    def test_save_error_is_wrapped(self, tmp_path, monkeypatch):
        db, _ = build_and_save(tmp_path)
        # Corrupt the connection to force a low-level sqlite error.
        db._conn.close()
        with pytest.raises(DatabaseError, match="Failed to save scan"):
            db.save_scan(_dummy_evidence(), target="http://127.0.0.1:8888")

    @responses_lib.activate
    @responses_lib.activate
    def test_sql_injection_via_reason_text_is_harmless(self, tmp_path):
        # Quotes and SQL fragments in text fields must be stored as
        # plain data, proving statements are parameterised.
        db, evidence = build_and_save(tmp_path)
        evidence.cases[0].reason = "'); DROP TABLE test_cases; --"
        evidence.run_id = "second-run"
        db.save_scan(evidence, target="http://127.0.0.1:8888")
        db.close()

        db = Database(tmp_path / "apishield.db")
        tables = {
            row["name"] for row in db._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "test_cases" in tables
        db.close()


def _dummy_evidence():
    from apishield.evidence import ScanEvidence
    return ScanEvidence(
        run_id="x", endpoint_id="x", endpoint_name="x", method="GET",
        path="/x", policy={}, started_at="", finished_at="",
        overall_classification="NO_ISSUE", summary="",
        budget_used=0, budget_max=0, budget_exhausted=False,
        cases=[],
    )
