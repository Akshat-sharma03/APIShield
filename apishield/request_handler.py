"""HTTP request handling with strict safety limits.

This module is the only place that talks to the network. Every safety
control required by the project lives here:

  * per-scan request budget (default 50) with graceful exhaustion;
  * configurable timeout (default 10 s);
  * redirects disabled;
  * response bodies are STREAMED and cut off at the configured size
    limit (default 1 MB) so an oversized response is never fully
    downloaded;
  * only GET requests are supported in this version;
  * environment proxy settings are ignored (trust_env disabled);
  * transport failures - including connections that drop mid-stream -
    are captured as safe error records.

Secret handling: the Authorization header is set from an Identity's
token, used for the request, and immediately discarded. Response
records hold only the parsed JSON body (in memory, for the analyser),
the body size and metadata — never the bearer token, never raw
response text. Persistence layers receive redacted data only.
"""

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

import requests

from .authentication import Identity

CHUNK_SIZE = 8192
JSON_CONTENT_TYPES = ("application/json",)


class RequestBudgetExceeded(Exception):
    """Raised when a scan has consumed its full request budget."""


@dataclass
class RequestBudget:
    """Counts requests against a per-scan limit.

    A fresh budget is created for every scan run, so the limit applies
    to each scan individually rather than to the process lifetime.
    """

    max_requests: int = 50
    used: int = field(default=0)

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.used)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.max_requests

    def consume(self) -> None:
        if self.exhausted:
            raise RequestBudgetExceeded(
                f"Request budget exhausted ({self.used}/{self.max_requests}). "
                "Remaining test cases were skipped."
            )
        self.used += 1


@dataclass
class ResponseRecord:
    """Normalised, memory-safe description of one HTTP exchange.

    ``json_body`` is kept in memory only. It is never written to the
    database or reports unredacted; downstream modules copy out
    redacted field summaries only.
    """

    url: str
    status_code: int | None = None
    reason: str = ""
    elapsed_ms: int | None = None
    content_type: str | None = None
    body_bytes: int = 0
    truncated: bool = False
    json_body: Any | None = None
    json_parse_error: bool = False
    transport_error: str | None = None

    @property
    def ok(self) -> bool:
        """True when the request completed at the transport level."""
        return self.transport_error is None

    def safe_summary(self) -> dict:
        """Return a dict safe for logging: no body, no headers."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "elapsed_ms": self.elapsed_ms,
            "body_bytes": self.body_bytes,
            "truncated": self.truncated,
            "transport_error": self.transport_error,
        }


@dataclass
class RequestLimits:
    """Configurable request limits, loaded from settings.json."""

    timeout_seconds: float = 10
    max_response_bytes: int = 1_048_576
    allow_redirects: bool = False
    verify_tls: bool = True
    user_agent: str = "APIShield/0.1 (BOLA differential testing)"


class RequestHandler:
    """Sends GET requests for the BOLA engine within strict limits."""

    def __init__(self, base_url: str, limits: RequestLimits | None = None,
                 budget: RequestBudget | None = None):
        self.base_url = base_url.rstrip("/")
        self.limits = limits or RequestLimits()
        self.budget = budget or RequestBudget()
        self._session = requests.Session()
        # Ignore environment proxy configuration (HTTP_PROXY etc.) so a
        # stray environment variable cannot silently route requests
        # through an external proxy.
        self._session.trust_env = False
        self._session.headers["User-Agent"] = self.limits.user_agent

    def build_url(self, path: str, path_params: dict | None = None) -> str:
        """Join the base URL with a path template.

        ``{vehicle_id}`` style placeholders are filled with URL-quoted
        values from ``path_params``.
        """
        filled = path
        if path_params:
            quoted = {k: quote(str(v), safe="") for k, v in path_params.items()}
            filled = path.format(**quoted)
        return f"{self.base_url}{filled}"

    def get(self, path: str, identity: Identity | None = None,
            path_params: dict | None = None) -> ResponseRecord:
        """Perform one authenticated or anonymous GET request.

        Args:
            path: endpoint path template, e.g. ``/api/v2/x/{vehicle_id}``.
            identity: identity whose token is used, or None / anonymous
                identity for the unauthenticated control case.
            path_params: values substituted into the path template.

        Returns:
            ResponseRecord describing the outcome. Transport-level
            failures (timeout, connection refused) are returned as
            records with ``transport_error`` set rather than raised.
        """
        url = self.build_url(path, path_params)
        record = ResponseRecord(url=url)

        headers = {}
        if identity is not None and identity.is_authenticated:
            headers["Authorization"] = f"Bearer {identity.token}"

        self.budget.consume()
        try:
            response = self._session.get(
                url,
                headers=headers,
                timeout=self.limits.timeout_seconds,
                allow_redirects=self.limits.allow_redirects,
                verify=self.limits.verify_tls,
                stream=True,
            )
        except requests.Timeout:
            record.transport_error = "timeout"
            return record
        except requests.ConnectionError:
            record.transport_error = "connection_error"
            return record
        except requests.RequestException:
            record.transport_error = "request_error"
            return record

        # Redirects are disabled by default. If redirects were enabled
        # in configuration and the target redirected elsewhere, verify
        # the final host is still a literal loopback address before
        # reading any content - otherwise the response is discarded.
        if response.history and not self._final_host_is_loopback(response.url):
            record.transport_error = "unsafe_redirect"
            response.close()
            return record

        try:
            self._populate_record(response, record)
        finally:
            response.close()
        return record

    def _final_host_is_loopback(self, final_url: str) -> bool:
        host = (urlsplit(final_url).hostname or "").lower()
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _populate_record(self, response, record: ResponseRecord) -> None:
        """Extract metadata and a size-capped body from a streaming response."""
        record.status_code = response.status_code
        record.reason = response.reason or ""
        record.elapsed_ms = int(response.elapsed.total_seconds() * 1000)
        record.content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()

        # Stream the body in chunks and stop as soon as the size limit is
        # exceeded, so an oversized response is never fully downloaded.
        # A connection that drops mid-stream raises a RequestException
        # subclass from iter_content(); this is recorded as a transport
        # error rather than crashing the scan.
        chunks = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                total += len(chunk)
                if total > self.limits.max_response_bytes:
                    record.truncated = True
                    record.body_bytes = total
                    return
                chunks.append(chunk)
        except requests.RequestException:
            record.transport_error = "stream_error"
            record.body_bytes = total
            # Partial body content is discarded: it cannot be trusted
            # as complete evidence.
            chunks.clear()
            record.json_body = None
            return

        record.body_bytes = total
        body = b"".join(chunks)

        # Parse JSON only when the server declares a JSON content type.
        # On a parse error we record the failure and keep no raw body.
        if record.content_type in JSON_CONTENT_TYPES and body:
            try:
                record.json_body = json.loads(body.decode("utf-8", errors="replace"))
            except (ValueError, UnicodeDecodeError):
                record.json_parse_error = True
