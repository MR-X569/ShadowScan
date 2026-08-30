"""
Tests for CrlfInjectionPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.crlf_injection import CrlfInjectionPlugin


@pytest.fixture
def plugin() -> CrlfInjectionPlugin:
    return CrlfInjectionPlugin()


def test_confirmed_header_injection_high(plugin: CrlfInjectionPlugin):
    """Test detection of confirmed CRLF-induced HTTP response header creation."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/redirect?next=/home",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if "%0d%0a" in url.lower() or "%0D%0A" in url:
                headers = {
                    "location": "/home",
                    "shadowscan-crlf-probe": "1",
                    "content-type": "text/html",
                }
                return httpx.Response(status_code=302, headers=headers, text="Redirecting...")
            return httpx.Response(status_code=200, text="Home Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "CRLF Injection" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_raw_crlf_in_location_header_medium(plugin: CrlfInjectionPlugin):
    """Test detection of unsanitized raw CRLF characters inside Location header."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/login?redirect_url=/dashboard",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if "%0d%0a" in url.lower():
                # Server unescapes CRLF into Location header value without creating new header field
                headers = {
                    "location": "/dashboard\r\nTest",
                    "content-type": "text/html",
                }
                return httpx.Response(status_code=302, headers=headers, text="Redirecting...")
            return httpx.Response(status_code=200, text="Login Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Unsanitized CRLF Characters" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_encoded_reflection_suppressed(plugin: CrlfInjectionPlugin):
    """Test that literal URL-encoded %0d%0a inside Location header does not trigger false positive."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/jump?url=https://example.com/test",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            # Properly encoded Location header value
            headers = {
                "location": "https://example.com/test%0d%0aShadowScan-CRLF-Probe:1",
                "content-type": "text/html",
            }
            return httpx.Response(status_code=302, headers=headers, text="Redirecting...")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_baseline_suppression(plugin: CrlfInjectionPlugin):
    """Test that pre-existing probe header in baseline does not trigger false positive."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/test?path=/app",
            user_id=1,
        )
        context.headers = {"shadowscan-crlf-probe": "1"}

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            headers={"shadowscan-crlf-probe": "1"},
            text="Test Page",
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_response_no_findings(plugin: CrlfInjectionPlugin):
    """Test clean response yields no findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/view?file=report.pdf",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            headers={"content-type": "application/pdf"},
            text="PDF Content",
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_candidate_parameter_discovery(plugin: CrlfInjectionPlugin):
    """Test candidate parameter discovery from crawler metadata."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/forward",
            user_id=1,
        )
        context.metadata["discovered_parameters"] = ["destination", "callback"]

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if "destination" in url and "%0d%0a" in url.lower():
                return httpx.Response(
                    status_code=302,
                    headers={"location": "/api", "shadowscan-crlf-probe": "1"},
                    text="Redirecting...",
                )
            return httpx.Response(status_code=200, text="API")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "destination" in context.findings[0].title

    asyncio.run(_run())


def test_error_handling_graceful(plugin: CrlfInjectionPlugin):
    """Test network timeouts during CRLF probing are handled without crash."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/redirect?next=/home",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
