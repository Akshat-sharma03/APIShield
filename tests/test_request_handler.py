"""Unit tests for the request handler.

All HTTP traffic is mocked with the ``responses`` library; no request
leaves the machine. Tests cover authentication headers, limits, body
streaming, JSON parsing and transport failures.
"""

import json
from datetime import timedelta

import pytest
import requests
import responses as responses_lib

from apishield.authentication import Identity
from apishield.request_handler import (
    RequestBudget,
    RequestBudgetExceeded,
    RequestHandler,
    RequestLimits,
    ResponseRecord,
)

BASE_URL = "http://127.0.0.1:8888"


def make_handler(**limits_kwargs) -> RequestHandler:
    limits = RequestLimits(**limits_kwargs) if limits_kwargs else None
    return RequestHandler(BASE_URL, limits=limits)


class TestUrlBuilding:
    def test_builds_url_from_template(self):
        handler = make_handler()
        url = handler.build_url(
            "/identity/api/v2/vehicle/{vehicle_id}/location",
            {"vehicle_id": "abc-123"},
        )
        assert url == f"{BASE_URL}/identity/api/v2/vehicle/abc-123/location"

    def test_quotes_path_parameters(self):
        handler = make_handler()
        url = handler.build_url("/x/{vehicle_id}", {"vehicle_id": "a b/c?d"})
        assert url == f"{BASE_URL}/x/a%20b%2Fc%3Fd"


class TestAuthenticatedRequests:
    @responses_lib.activate
    def test_sends_bearer_token(self):
        responses_lib.get(f"{BASE_URL}/location", json={"status": "ok"})
        handler = make_handler()
        identity = Identity(label="user_a", token="secret-token")

        record = handler.get("/location", identity=identity)

        request = responses_lib.calls[0].request
        assert request.headers["Authorization"] == "Bearer secret-token"
        assert record.status_code == 200

    @responses_lib.activate
    def test_anonymous_request_has_no_auth_header(self):
        responses_lib.get(f"{BASE_URL}/location", json={"message": "Unauthorized"})
        handler = make_handler()

        handler.get("/location", identity=None)

        request = responses_lib.calls[0].request
        assert "Authorization" not in request.headers

    @responses_lib.activate
    def test_response_record_holds_no_token_or_raw_body(self):
        body = {"fullName": "User A", "latitude": 12.34}
        responses_lib.get(f"{BASE_URL}/location", json=body)
        handler = make_handler()
        identity = Identity(label="user_a", token="secret-token")

        record = handler.get("/location", identity=identity)

        assert "secret-token" not in repr(record)
        # JSON is parsed in memory for the analyser.
        assert record.json_body == body


class TestResponseParsing:
    @responses_lib.activate
    def test_parses_json_body(self):
        responses_lib.get(
            f"{BASE_URL}/location",
            body=json.dumps({"fullName": "A"}),
            content_type="application/json",
        )
        record = make_handler().get("/location")
        assert record.json_body == {"fullName": "A"}
        assert not record.json_parse_error

    @responses_lib.activate
    def test_invalid_json_is_flagged(self):
        responses_lib.get(
            f"{BASE_URL}/location",
            body="not json {",
            content_type="application/json",
        )
        record = make_handler().get("/location")
        assert record.json_parse_error
        assert record.json_body is None

    @responses_lib.activate
    def test_non_json_content_type_is_not_parsed(self):
        responses_lib.get(
            f"{BASE_URL}/location",
            body="<html>hi</html>",
            content_type="text/html",
        )
        record = make_handler().get("/location")
        assert record.json_body is None
        assert not record.json_parse_error
        assert record.content_type == "text/html"

    @responses_lib.activate
    def test_records_metadata(self):
        responses_lib.get(f"{BASE_URL}/location", json={})
        record = make_handler().get("/location")
        assert record.status_code == 200
        assert record.content_type == "application/json"
        assert record.elapsed_ms is not None
        assert record.ok

    @responses_lib.activate
    def test_records_error_status_codes(self):
        responses_lib.get(f"{BASE_URL}/location", json={"message": "nope"}, status=401)
        record = make_handler().get("/location")
        assert record.status_code == 401
        assert record.ok  # transport level succeeded


class TestTransportFailures:
    @responses_lib.activate
    def test_timeout_is_recorded_not_raised(self):
        responses_lib.get(
            f"{BASE_URL}/location",
            body=requests.exceptions.ReadTimeout(),
        )
        record = make_handler(timeout_seconds=1).get("/location")
        assert record.transport_error == "timeout"
        assert not record.ok
        assert record.status_code is None

    @responses_lib.activate
    def test_connection_error_is_recorded(self):
        responses_lib.get(
            f"{BASE_URL}/location",
            body=requests.exceptions.ConnectionError("refused"),
        )
        record = make_handler().get("/location")
        assert record.transport_error == "connection_error"
        assert record.status_code is None

    def test_mid_stream_connection_drop_is_recorded(self):
        # A connection that fails part-way through the body must be
        # recorded as a transport error, never crash the scan.
        class DroppingResponse:
            status_code = 200
            reason = "OK"
            headers = {"Content-Type": "application/json"}
            elapsed = timedelta(milliseconds=12)

            def iter_content(self, chunk_size=1):
                yield b'{"partial":'
                raise requests.exceptions.ChunkedEncodingError("connection dropped")

            def close(self):
                pass

        record = ResponseRecord(url=f"{BASE_URL}/location")
        make_handler()._populate_record(DroppingResponse(), record)

        assert record.transport_error == "stream_error"
        assert record.status_code == 200
        assert record.json_body is None  # partial body discarded
        assert not record.ok

    @responses_lib.activate
    def test_safe_summary_contains_no_body_or_headers(self):
        responses_lib.get(f"{BASE_URL}/location", json={"secret": "value"})
        record = make_handler().get("/location")
        summary = record.safe_summary()
        assert "json_body" not in summary
        assert "secret" not in str(summary)


class TestSessionIsolation:
    def test_environment_proxies_are_ignored(self, monkeypatch):
        # trust_env=False ensures HTTP_PROXY/HTTPS_PROXY environment
        # variables cannot redirect traffic outside the target.
        monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.99:8080")
        monkeypatch.setenv("http_proxy", "http://203.0.113.99:8080")
        handler = make_handler()
        assert handler._session.trust_env is False

    @responses_lib.activate
    def test_redirect_to_external_host_is_rejected(self):
        # Regression: with redirects enabled in configuration, a target
        # that redirects off loopback must be discarded, not followed.
        # The external target is also mocked so the guard itself is
        # exercised rather than the mock's connection failure.
        responses_lib.get(
            f"{BASE_URL}/location",
            status=302,
            headers={"Location": "http://203.0.113.10/evil"},
        )
        responses_lib.get("http://203.0.113.10/evil", json={"pwned": True})
        handler = make_handler(allow_redirects=True)
        record = handler.get("/location")

        assert record.transport_error == "unsafe_redirect"
        assert record.status_code is None
        assert record.json_body is None

    @responses_lib.activate
    def test_redirect_to_loopback_is_allowed(self):
        responses_lib.get(
            f"{BASE_URL}/old",
            status=302,
            headers={"Location": f"{BASE_URL}/location"},
        )
        responses_lib.get(f"{BASE_URL}/location", json={"moved": True})
        handler = make_handler(allow_redirects=True)
        record = handler.get("/old")

        assert record.transport_error is None
        assert record.status_code == 200
        assert record.json_body == {"moved": True}


class TestSizeLimit:
    @responses_lib.activate
    def test_oversized_body_is_truncated_while_streaming(self):
        # 2 MB body with a 64 KB limit: download must stop early.
        large_body = "x" * (2 * 1024 * 1024)
        responses_lib.get(
            f"{BASE_URL}/location",
            body=large_body,
            content_type="text/plain",
        )
        handler = make_handler(max_response_bytes=64 * 1024)
        record = handler.get("/location")

        assert record.truncated
        assert record.body_bytes <= 64 * 1024 + 8192  # at most one chunk over
        assert record.json_body is None

    @responses_lib.activate
    def test_body_under_limit_is_not_truncated(self):
        responses_lib.get(f"{BASE_URL}/location", body="small", content_type="text/plain")
        handler = make_handler(max_response_bytes=1024 * 1024)
        record = handler.get("/location")
        assert not record.truncated
        assert record.body_bytes == len("small")


class TestRequestBudget:
    def test_budget_counts_requests(self):
        budget = RequestBudget(max_requests=3)
        assert budget.remaining == 3
        budget.consume()
        budget.consume()
        assert budget.remaining == 1
        assert not budget.exhausted

    def test_budget_exhaustion_raises(self):
        budget = RequestBudget(max_requests=1)
        budget.consume()
        assert budget.exhausted
        with pytest.raises(RequestBudgetExceeded):
            budget.consume()

    @responses_lib.activate
    def test_handler_enforces_shared_budget(self):
        responses_lib.get(f"{BASE_URL}/x", json={})
        budget = RequestBudget(max_requests=1)
        handler = RequestHandler(BASE_URL, budget=budget)

        handler.get("/x")
        with pytest.raises(RequestBudgetExceeded):
            handler.get("/x")

    def test_budget_is_independent_per_scan(self):
        # Each scan creates a fresh budget, so the limit resets.
        first = RequestBudget(max_requests=2)
        first.consume()
        first.consume()
        second = RequestBudget(max_requests=2)
        assert second.remaining == 2
