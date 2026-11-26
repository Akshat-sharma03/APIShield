"""SQLite persistence for redacted scan evidence.

Only redacted data ever reaches this layer: the evidence bundles built
in phase 4 contain labels, booleans, status codes, field names and
fingerprinted identifiers - no tokens, raw bodies, personal data or
coordinates. The database therefore stores exactly what it is given
and adds nothing sensitive of its own.

Schema (three tables, deliberately simple):
  test_runs   one row per (scan run, endpoint)
  test_cases  one row per B01-B05 case, with comparison evidence
  findings    one row per CONFIRMED or SUSPECTED case, with severity,
              confidence and remediation

All statements are parameterised. Database errors are translated into
a DatabaseError with a safe message so the CLI can fail gracefully.
"""

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from .classifier import CONFIRMED, SUSPECTED
from .evidence import ScanEvidence, remediation_guidance

SEVERITY = {CONFIRMED: "High", SUSPECTED: "Medium"}
CONFIDENCE = {CONFIRMED: "High", SUSPECTED: "Medium"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS test_runs (
    run_id                TEXT NOT NULL,
    endpoint_id           TEXT NOT NULL,
    endpoint_name         TEXT NOT NULL,
    method                TEXT NOT NULL,
    path                  TEXT NOT NULL,
    target                TEXT NOT NULL,
    policy_json           TEXT NOT NULL,
    started_at            TEXT,
    finished_at           TEXT,
    overall_classification TEXT NOT NULL,
    summary               TEXT,
    budget_used           INTEGER NOT NULL DEFAULT 0,
    budget_max            INTEGER NOT NULL DEFAULT 0,
    budget_exhausted      INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS test_cases (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                 TEXT NOT NULL,
    endpoint_id            TEXT NOT NULL,
    case_id                TEXT NOT NULL,
    description            TEXT,
    requester_label        TEXT NOT NULL,
    owner_label            TEXT NOT NULL,
    expected_decision      TEXT NOT NULL,
    resource_id_fingerprint TEXT,
    status_code            INTEGER,
    transport_error        TEXT,
    elapsed_ms             INTEGER,
    body_bytes             INTEGER NOT NULL DEFAULT 0,
    truncated              INTEGER NOT NULL DEFAULT 0,
    access_obtained        INTEGER NOT NULL DEFAULT 0,
    fields_present_json    TEXT,
    comparison_json        TEXT,
    classification         TEXT NOT NULL,
    reason                 TEXT,
    classified_at          TEXT,
    FOREIGN KEY (run_id, endpoint_id)
        REFERENCES test_runs (run_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    endpoint_id     TEXT NOT NULL,
    case_id         TEXT NOT NULL,
    classification  TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    description     TEXT,
    remediation     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (run_id, endpoint_id)
        REFERENCES test_runs (run_id, endpoint_id)
);
"""


class DatabaseError(Exception):
    """Raised when a database operation fails."""


class Database:
    """Persistence layer for scan runs, cases and findings."""

    def __init__(self, path: Path):
        self._path = Path(path)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        except (sqlite3.Error, OSError) as exc:
            raise DatabaseError(
                f"Could not open database at {self._path}: {exc}"
            ) from None

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def save_scan(self, evidence: ScanEvidence, target: str) -> None:
        """Persist one scan's redacted evidence bundle."""
        try:
            with self._conn:
                self._conn.execute(
                    """INSERT INTO test_runs
                       (run_id, endpoint_id, endpoint_name, method, path,
                        target, policy_json, started_at, finished_at,
                        overall_classification, summary, budget_used,
                        budget_max, budget_exhausted)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        evidence.run_id,
                        evidence.endpoint_id,
                        evidence.endpoint_name,
                        evidence.method,
                        evidence.path,
                        target,
                        json.dumps(evidence.policy),
                        evidence.started_at,
                        evidence.finished_at,
                        evidence.overall_classification,
                        evidence.summary,
                        evidence.budget_used,
                        evidence.budget_max,
                        int(evidence.budget_exhausted),
                    ),
                )

                for case in evidence.cases:
                    self._insert_case(evidence.run_id, evidence.endpoint_id, case)

                self._insert_findings(evidence.run_id, evidence.endpoint_id,
                                      evidence.cases)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to save scan: {exc}") from None

    def _insert_case(self, run_id: str, endpoint_id: str, case) -> None:
        fields_present = {
            "identity_fields": case.identity_fields_present,
            "ownership_fields": case.ownership_fields_present,
            "resource_id_fields": case.resource_id_fields_present,
            "sensitive_fields": case.sensitive_fields_present,
            "resource_id_matches_request": case.resource_id_matches_request,
        }
        self._conn.execute(
            """INSERT INTO test_cases
               (run_id, endpoint_id, case_id, description, requester_label,
                owner_label, expected_decision, resource_id_fingerprint,
                status_code, transport_error, elapsed_ms, body_bytes,
                truncated, access_obtained, fields_present_json,
                comparison_json, classification, reason, classified_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                endpoint_id,
                case.case_id,
                case.description,
                case.requester_label,
                case.owner_label,
                case.expected_decision,
                case.resource_id_fingerprint,
                case.status_code,
                case.transport_error,
                case.elapsed_ms,
                case.body_bytes,
                int(case.truncated),
                int(case.access_obtained),
                json.dumps(fields_present),
                json.dumps(asdict(case.comparison)) if case.comparison else None,
                case.classification,
                case.reason,
                case.classified_at,
            ),
        )

    def _insert_findings(self, run_id: str, endpoint_id: str, cases) -> None:
        """Store one finding per CONFIRMED or SUSPECTED case."""
        for case in cases:
            if case.classification not in SEVERITY:
                continue
            description = (
                f"[{case.case_id}] {case.requester_label} accessed the "
                f"resource owned by {case.owner_label} "
                f"(expected policy: {case.expected_decision}). {case.reason}"
            )
            self._conn.execute(
                """INSERT INTO findings
                   (run_id, endpoint_id, case_id, classification, severity,
                    confidence, description, remediation)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    endpoint_id,
                    case.case_id,
                    case.classification,
                    SEVERITY[case.classification],
                    CONFIDENCE[case.classification],
                    description,
                    remediation_guidance(case.classification),
                ),
            )

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def list_runs(self) -> list[dict]:
        """Return run summaries, most recent first."""
        try:
            rows = self._conn.execute(
                """SELECT run_id, endpoint_id, endpoint_name, target,
                          overall_classification, started_at, finished_at,
                          budget_used, budget_max
                   FROM test_runs
                   ORDER BY created_at DESC, endpoint_id"""
            ).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to list runs: {exc}") from None
        return [dict(row) for row in rows]

    def latest_run_id(self) -> str | None:
        try:
            row = self._conn.execute(
                "SELECT run_id FROM test_runs ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to find latest run: {exc}") from None
        return row["run_id"] if row else None

    def get_run(self, run_id: str) -> dict | None:
        """Return the full stored record for a scan run.

        The result aggregates every endpoint scanned in the run:
        {"run_id", "target", "overall", "endpoints": [{...}]}.
        """
        try:
            run_rows = self._conn.execute(
                "SELECT * FROM test_runs WHERE run_id = ? ORDER BY started_at",
                (run_id,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to load run: {exc}") from None

        if not run_rows:
            return None

        endpoints = []
        for run_row in run_rows:
            case_rows = self._conn.execute(
                "SELECT * FROM test_cases WHERE run_id = ? AND endpoint_id = ? "
                "ORDER BY id",
                (run_id, run_row["endpoint_id"]),
            ).fetchall()
            finding_rows = self._conn.execute(
                "SELECT * FROM findings WHERE run_id = ? AND endpoint_id = ? "
                "ORDER BY id",
                (run_id, run_row["endpoint_id"]),
            ).fetchall()

            endpoints.append({
                "endpoint_id": run_row["endpoint_id"],
                "endpoint_name": run_row["endpoint_name"],
                "method": run_row["method"],
                "path": run_row["path"],
                "policy": json.loads(run_row["policy_json"]),
                "started_at": run_row["started_at"],
                "finished_at": run_row["finished_at"],
                "overall_classification": run_row["overall_classification"],
                "summary": run_row["summary"],
                "budget": {
                    "used": run_row["budget_used"],
                    "max": run_row["budget_max"],
                    "exhausted": bool(run_row["budget_exhausted"]),
                },
                "cases": [self._case_row_to_dict(row) for row in case_rows],
                "findings": [dict(row) for row in finding_rows],
            })

        return {
            "run_id": run_id,
            "target": run_rows[0]["target"],
            "overall": self._worst_overall(endpoints),
            "endpoints": endpoints,
        }

    def _case_row_to_dict(self, row) -> dict:
        case = dict(row)
        case["truncated"] = bool(case["truncated"])
        case["access_obtained"] = bool(case["access_obtained"])
        case["fields_present"] = json.loads(case.pop("fields_present_json"))
        case["comparison"] = (
            json.loads(case["comparison_json"])
            if case["comparison_json"] is not None else None
        )
        case.pop("comparison_json")
        return case

    @staticmethod
    def _worst_overall(endpoints: list[dict]) -> str:
        order = {"NO_ISSUE": 0, "INCONCLUSIVE": 1, "SUSPECTED": 2, "CONFIRMED": 3}
        return max(
            (endpoint["overall_classification"] for endpoint in endpoints),
            key=lambda c: order.get(c, 0),
        )
