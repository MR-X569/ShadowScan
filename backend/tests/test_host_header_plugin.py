"""
Tests for HostHeaderPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.host_header import HostHeaderPlugin, _PROBE_HOST


@pytest.fixture
def plugin() -> HostHeaderPlugin:
    return HostHeaderPlugin()


def test_host_header_redirect_location_poisoning_high(plugin: HostHeaderPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/login",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            headers = headers or {}
            # If custom X-Forwarded-Host probe sent, server reflects it in Location header
            if headers.get("X-Forwarded-Host") == _PROBE_HOST:
                return httpx.Response(
                    status_code=302,
                    headers={"Location": f"https://{_PROBE_HOST}/oauth/callback"},
                )
            return httpx.Response(status_code=200, text="Login Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Host Header Injection: Open Redirect" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_host_header_password_reset_poisoning_high(plugin: HostHeaderPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/forgot_password",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            headers = headers or {}
            if headers.get("X-Forwarded-Host") == _PROBE_HOST or headers.get("Host") == _PROBE_HOST:
                html_body = f"<html><body><a href='https://{_PROBE_HOST}/auth/reset-password?token=xyz'>Reset Link</a></body></html>"
                return httpx.Response(status_code=200, text=html_body)
            return httpx.Response(status_code=200, text="<html><body>Forgot Password Page</body></html>")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Password Reset / Link Poisoning Risk" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_host_header_canonical_url_poisoning_medium(plugin: HostHeaderPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/article/1",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            headers = headers or {}
            if headers.get("X-Forwarded-Host") == _PROBE_HOST:
                html_body = f'<html><head><link rel="canonical" href="https://{_PROBE_HOST}/article/1"></head><body>Article</body></html>'
                return httpx.Response(status_code=200, text=html_body)
            return httpx.Response(status_code=200, text='<html><head><link rel="canonical" href="https://example.com/article/1"></head><body>Article</body></html>')

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Web Resource / Canonical URL Poisoning" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_host_header_baseline_marker_suppressed(plugin: HostHeaderPlugin):
    async def _run():
        # Baseline HTML already contains the probe domain
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs",
            user_id=1,
        )
        context.html = f"Documentation discussing {_PROBE_HOST} test procedures."

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text=f"Documentation discussing {_PROBE_HOST} test procedures.")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_host_header_clean_response_no_findings(plugin: HostHeaderPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/about",
            user_id=1,
        )

        mock_client = AsyncMock()
        # Clean static response ignoring all custom host headers
        mock_client.get.return_value = httpx.Response(status_code=200, text="<html><body>About us static page</body></html>")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_host_header_network_error_handled(plugin: HostHeaderPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/error",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
