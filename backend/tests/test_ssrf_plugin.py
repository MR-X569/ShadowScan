"""
Tests for SsrfPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.ssrf import SsrfPlugin


@pytest.fixture
def plugin() -> SsrfPlugin:
    return SsrfPlugin()


def test_ssrf_remote_content_embedded_high(plugin: SsrfPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/proxy?url=https://mysite.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Target server fetched https://example.com/ and embedded its HTML title in response
            if "example.com" in url:
                fetched_html = (
                    "<html><body>"
                    "<div>Proxy fetched content: <title>Example Domain</title> This domain is for use in illustrative examples</div>"
                    "</body></html>"
                )
                return httpx.Response(status_code=200, text=fetched_html)
            return httpx.Response(status_code=200, text="<html><body>Proxy Ready</body></html>")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Server-Side Request Forgery" in finding.title
        assert finding.severity == Severity.HIGH
        assert "url" in finding.title

    asyncio.run(_run())


def test_ssrf_server_fetch_error_medium(plugin: SsrfPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/fetch_feed?source=https://test.com/rss",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Target server backend threw cURL / urllib error when attempting outbound fetch
            error_response = "Error processing request: cURL error 28: Operation timed out after 5000 milliseconds with 0 bytes received"
            return httpx.Response(status_code=500, text=error_response)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Fetch Attempt" in finding.title or "SSRF" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_ssrf_baseline_diff_prevents_false_positive(plugin: SsrfPlugin):
    async def _run():
        # Baseline HTML already mentions Example Domain in its documentation
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs?topic=example",
            user_id=1,
        )
        context.html = "<html><body>Documentation about Example Domain for developers</body></html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="<html><body>Documentation about Example Domain for developers</body></html>",
        )
        context.session = mock_client

        await plugin.run(context)

        # Content was already present in baseline -> no new SSRF finding
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_ssrf_normal_response_no_findings(plugin: SsrfPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/view?endpoint=profile",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="<html><body>User Profile Page Content</body></html>",
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_ssrf_network_error_handled(plugin: SsrfPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api?url=1",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
