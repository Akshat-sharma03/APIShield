"""Unit tests for target validation.

The validator accepts only LITERAL loopback IP addresses. Hostnames
(including localhost) are rejected, which removes DNS resolution from
the request path entirely and closes the DNS-rebinding window.
"""

import pytest

from apishield.target_validator import TargetValidationError, validate_base_url


class TestAcceptedTargets:
    def test_accepts_primary_loopback(self):
        assert validate_base_url("http://127.0.0.1:8888") == "http://127.0.0.1:8888"

    def test_accepts_any_ipv4_loopback_address(self):
        # The full 127.0.0.0/8 range is loopback, not just 127.0.0.1.
        assert validate_base_url("http://127.0.0.5:8888")
        assert validate_base_url("http://127.255.255.254:80")

    def test_accepts_ipv6_loopback(self):
        assert validate_base_url("http://[::1]:8888") == "http://[::1]:8888"

    def test_accepts_portless_url(self):
        assert validate_base_url("http://127.0.0.1") == "http://127.0.0.1"


class TestRejectedHosts:
    def test_rejects_localhost(self):
        with pytest.raises(TargetValidationError, match="hostname"):
            validate_base_url("http://localhost:8888")

    def test_rejects_localhost_without_port(self):
        with pytest.raises(TargetValidationError, match="hostname"):
            validate_base_url("http://localhost")

    def test_rejects_external_hostname(self):
        with pytest.raises(TargetValidationError):
            validate_base_url("http://example.com")

    def test_rejects_external_ip(self):
        with pytest.raises(TargetValidationError, match="not a loopback"):
            validate_base_url("http://8.8.8.8")

    def test_rejects_link_local_metadata_address(self):
        # Cloud metadata endpoints are link-local, not loopback.
        with pytest.raises(TargetValidationError, match="not a loopback"):
            validate_base_url("http://169.254.169.254")

    def test_rejects_private_network_address(self):
        with pytest.raises(TargetValidationError, match="not a loopback"):
            validate_base_url("http://192.168.1.10")

    def test_accepts_ipv4_mapped_ipv6_loopback(self):
        # ::ffff:127.0.0.1 maps to IPv4 loopback; Python's ipaddress
        # classifies it as loopback, so it is accepted.
        assert validate_base_url("http://[::ffff:127.0.0.1]:8888")


class TestMalformedUrls:
    def test_rejects_empty_url(self):
        with pytest.raises(TargetValidationError):
            validate_base_url("")

    def test_rejects_whitespace_url(self):
        with pytest.raises(TargetValidationError):
            validate_base_url("   ")

    def test_rejects_url_without_scheme(self):
        with pytest.raises(TargetValidationError):
            validate_base_url("127.0.0.1:8888")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(TargetValidationError):
            validate_base_url("ftp://127.0.0.1")

    def test_rejects_embedded_credentials(self):
        with pytest.raises(TargetValidationError, match="credentials"):
            validate_base_url("http://user:pass@127.0.0.1:8888")

    def test_rejects_non_numeric_port(self):
        with pytest.raises(TargetValidationError, match="Malformed"):
            validate_base_url("http://127.0.0.1:abc")

    def test_rejects_out_of_range_port(self):
        with pytest.raises(TargetValidationError, match="Malformed"):
            validate_base_url("http://127.0.0.1:70000")

    def test_rejects_port_zero(self):
        with pytest.raises(TargetValidationError, match="Invalid port"):
            validate_base_url("http://127.0.0.1:0")

    def test_rejects_query_string_in_base_url(self):
        with pytest.raises(TargetValidationError, match="query string"):
            validate_base_url("http://127.0.0.1:8888?x=1")

    def test_rejects_fragment_in_base_url(self):
        with pytest.raises(TargetValidationError, match="fragment"):
            validate_base_url("http://127.0.0.1:8888#top")

    def test_rejects_url_without_host(self):
        with pytest.raises(TargetValidationError, match="no host"):
            validate_base_url("http://")


class TestNormalisation:
    def test_strips_trailing_slash(self):
        assert validate_base_url("http://127.0.0.1:8888/") == "http://127.0.0.1:8888"

    def test_keeps_base_path(self):
        assert validate_base_url("http://127.0.0.1:8888/api") == "http://127.0.0.1:8888/api"

    def test_scheme_is_lowercased(self):
        assert validate_base_url("HTTP://127.0.0.1:8888") == "http://127.0.0.1:8888"
