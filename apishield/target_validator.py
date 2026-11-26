"""Target URL validation.

APIShield is a lab tool. To guarantee it can never be pointed at an
external host, the base URL must be a LITERAL loopback IP address:

  * IPv4: any address in 127.0.0.0/8;
  * IPv6: ::1 only (requests/urllib3 fully support literal IPv6
    hosts, so ::1 is accepted in bracketed URL form, e.g.
    ``http://[::1]:8888``).

HOSTNAMES ARE REJECTED, including ``localhost``. Rationale: accepting
hostnames would require DNS resolution, which introduces a
time-of-check/time-of-use gap (the classic DNS rebinding window)
between validation and connection. By accepting literal IPs only,
no name resolution ever happens - the validated address IS the
address the HTTP client connects to, so there is nothing to rebind.

Additional static checks:
  * scheme must be http or https;
  * no username/password component;
  * port, when present, must be a valid integer in 1-65535;
  * query strings and fragments are rejected in a base URL;
  * trailing slash is stripped for predictable path joining.
"""

import ipaddress
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})


class TargetValidationError(Exception):
    """Raised when a target URL is outside the permitted scope."""


def validate_base_url(raw_url: str) -> str:
    """Validate a base URL and return a normalised form.

    Raises:
        TargetValidationError: with a safe, non-revealing message when
            the URL is malformed or the host is not a literal loopback
            IP address.
    """
    if not raw_url or not raw_url.strip():
        raise TargetValidationError("Target URL is empty.")

    try:
        parts = urlsplit(raw_url.strip())
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError(f"Malformed target URL: {exc}.") from None

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise TargetValidationError(
            f"Unsupported URL scheme {parts.scheme!r}. Use http or https."
        )

    if parts.username or parts.password:
        raise TargetValidationError(
            "URLs with embedded credentials are not accepted."
        )

    if parts.query or parts.fragment:
        raise TargetValidationError(
            "Base URLs must not contain a query string or fragment."
        )

    if port is not None and not 1 <= port <= 65535:
        raise TargetValidationError(
            f"Invalid port {port!r}. Ports must be in the range 1-65535."
        )

    host = (parts.hostname or "").lower()
    if not host:
        raise TargetValidationError("Target URL has no host.")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise TargetValidationError(
            f"Target host {host!r} is a hostname. APIShield only accepts "
            "literal loopback IP addresses (e.g. http://127.0.0.1:8888); "
            "hostnames such as 'localhost' are rejected to rule out DNS "
            "rebinding."
        ) from None

    if not address.is_loopback:
        raise TargetValidationError(
            f"Target address {host!r} is not a loopback address. "
            "External targets are not permitted."
        )

    if not parts.path or parts.path == "/":
        normalised = f"{parts.scheme.lower()}://{parts.netloc}"
    else:
        normalised = f"{parts.scheme.lower()}://{parts.netloc}{parts.path}"

    return normalised.rstrip("/")
