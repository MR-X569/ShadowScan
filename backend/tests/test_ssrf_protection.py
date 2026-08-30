"""
Tests for Server-Side Request Forgery (SSRF) Protection and Safe Redirect Validation.
"""

import asyncio
from unittest.mock import patch
import pytest
from pydantic import ValidationError

from app.core.ssrf import (
    SSRFSecurityError,
    is_ip_allowed,
    resolve_hostname_ips,
    validate_url_for_ssrf,
)
from app.scanner.http_client import create_http_client
from app.schemas.scan import ScanCreate


# ---------------------------------------------------------------------------
# 1. IP Whitelist/Blacklist Unit Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prohibited_ip",
    [
        "127.0.0.1",
        "127.0.0.2",
        "0.0.0.0",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.100",
        "169.254.169.254",  # AWS/GCP/Azure Cloud Metadata
        "169.254.1.1",
        "100.64.0.1",      # Carrier-grade NAT
        "224.0.0.1",       # Multicast
        "240.0.0.1",       # Reserved
        "255.255.255.255",
        "::1",             # IPv6 loopback
        "::",              # IPv6 unspecified
        "fc00::1",         # IPv6 ULA
        "fd00::ec2:254",   # AWS IPv6 Metadata
        "fe80::1",         # IPv6 Link-local
        "ff02::1",         # IPv6 Multicast
        "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
        "::ffff:10.0.0.1",  # IPv4-mapped IPv6 private
        "::ffff:169.254.169.254",
    ],
)
def test_prohibited_ips_rejected(prohibited_ip: str):
    """Ensure non-routable, private, loopback, link-local, and cloud metadata IPs are disallowed."""
    assert is_ip_allowed(prohibited_ip) is False


@pytest.mark.parametrize(
    "public_ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "142.250.190.46",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ],
)
def test_legitimate_public_ips_allowed(public_ip: str):
    """Ensure valid, publicly routable IPv4 and IPv6 addresses are permitted."""
    assert is_ip_allowed(public_ip) is True


# ---------------------------------------------------------------------------
# 2. URL Validation & DNS Resolution Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prohibited_url",
    [
        "http://127.0.0.1/",
        "http://127.0.0.1:8000/api",
        "http://localhost/",
        "http://localhost:5432/",
        "http://0.0.0.0:80/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://instance-data/latest/meta-data/",
        "http://metadata.google.internal/",
    ],
)
def test_validate_url_ssrf_rejects_forbidden_destinations(prohibited_url: str):
    """Verify validate_url_for_ssrf raises SSRFSecurityError for direct private destinations."""
    with pytest.raises(SSRFSecurityError):
        validate_url_for_ssrf(prohibited_url)


def test_validate_url_ssrf_hostname_resolving_to_private_ip():
    """Verify domain resolving to a private IP is rejected."""
    with patch("app.core.ssrf.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (2, 1, 6, "", ("192.168.1.55", 80)),
        ]
        with pytest.raises(SSRFSecurityError, match="private/loopback/cloud metadata"):
            validate_url_for_ssrf("https://internal.corp.example.com")


def test_validate_url_ssrf_multiple_dns_answers_one_private():
    """Verify domain resolving to multiple IPs where one is private is rejected (anti-DNS rebinding)."""
    with patch("app.core.ssrf.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),  # Public
            (2, 1, 6, "", ("10.0.0.5", 443)),       # Private
        ]
        with pytest.raises(SSRFSecurityError, match="prohibited IP '10.0.0.5'"):
            validate_url_for_ssrf("https://dual-homed.example.com")


def test_validate_url_ssrf_legitimate_public_domain():
    """Verify legitimate public domain resolving to public IP is accepted."""
    with patch("app.core.ssrf.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ]
        validated = validate_url_for_ssrf("https://example.com/login")
        assert validated == "https://example.com/login"


# ---------------------------------------------------------------------------
# 3. Pydantic ScanCreate Schema Validator Tests
# ---------------------------------------------------------------------------


def test_scan_create_schema_blocks_private_ip():
    """Verify ScanCreate Pydantic schema rejects internal target URL at input validation."""
    with pytest.raises(ValidationError) as exc_info:
        ScanCreate(target_url="http://127.0.0.1:8000")
    assert "private" in str(exc_info.value).lower() or "ssrf" in str(exc_info.value).lower()


def test_scan_create_schema_accepts_valid_public_url():
    """Verify ScanCreate Pydantic schema accepts legitimate public targets."""
    with patch("app.core.ssrf.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        schema = ScanCreate(target_url="https://example.com")
        assert str(schema.target_url) == "https://example.com/"


# ---------------------------------------------------------------------------
# 4. HTTP Client Pre-Request & Safe Redirect Blocking Tests
# ---------------------------------------------------------------------------


def test_http_client_blocks_outbound_connection_to_loopback():
    """Verify create_http_client aborts requests to loopback addresses before making a TCP connection."""
    async def _run():
        async with create_http_client() as client:
            with pytest.raises(SSRFSecurityError):
                await client.get("http://127.0.0.1:5432/")

    asyncio.run(_run())


def test_http_client_blocks_redirect_to_internal_metadata():
    """Verify create_http_client blocks a 302 redirect targeting cloud metadata or private IP."""
    async def _run():
        import httpx

        # Mock initial transport response to return 302 Redirect to 169.254.169.254
        class MockRedirectTransport(httpx.AsyncBaseTransport):
            def __init__(self):
                self.req_count = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.req_count += 1
                if self.req_count == 1:
                    # Initial public request returns 302 to metadata IP
                    return httpx.Response(
                        status_code=302,
                        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
                        request=request,
                    )
                # Should NEVER be reached because the redirect request is intercepted and blocked
                return httpx.Response(status_code=200, text="METADATA_LEAK", request=request)

        from app.scanner.http_client import RetryTransport

        mock_base = MockRedirectTransport()
        retry_transport = RetryTransport(transport=mock_base, max_retries=0)

        def mock_dns(host, *args, **kwargs):
            if host == "example.com":
                return [(2, 1, 6, "", ("93.184.216.34", 80))]
            return [(2, 1, 6, "", (host, 80))]

        with patch("app.core.ssrf.socket.getaddrinfo", side_effect=mock_dns):
            async with httpx.AsyncClient(
                transport=retry_transport,
                follow_redirects=True,
            ) as client:
                with pytest.raises(SSRFSecurityError):
                    await client.get("http://example.com/redirect-to-metadata")

        # Confirm the transport only processed the first request and refused to execute the redirect
        assert mock_base.req_count == 1

    asyncio.run(_run())


def test_http_client_blocks_redirect_to_rfc1918_private_ip():
    """Verify create_http_client blocks a 302 redirect targeting private RFC 1918 subnet."""
    async def _run():
        import httpx

        class MockRedirectTransport(httpx.AsyncBaseTransport):
            def __init__(self):
                self.req_count = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.req_count += 1
                if self.req_count == 1:
                    return httpx.Response(
                        status_code=302,
                        headers={"Location": "http://10.0.0.1/admin"},
                        request=request,
                    )
                return httpx.Response(status_code=200, text="PRIVATE_DATA", request=request)

        from app.scanner.http_client import RetryTransport

        mock_base = MockRedirectTransport()
        retry_transport = RetryTransport(transport=mock_base, max_retries=0)

        def mock_dns(host, *args, **kwargs):
            if host == "example.com":
                return [(2, 1, 6, "", ("93.184.216.34", 80))]
            return [(2, 1, 6, "", (host, 80))]

        with patch("app.core.ssrf.socket.getaddrinfo", side_effect=mock_dns):
            async with httpx.AsyncClient(
                transport=retry_transport,
                follow_redirects=True,
            ) as client:
                with pytest.raises(SSRFSecurityError):
                    await client.get("http://example.com/redirect-to-private")

        assert mock_base.req_count == 1

    asyncio.run(_run())

