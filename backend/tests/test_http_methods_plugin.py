"""
Tests for HttpMethodsPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.http_methods import HttpMethodsPlugin


@pytest.fixture
def plugin() -> HttpMethodsPlugin:
    return HttpMethodsPlugin()


def test_standard_safe_methods(plugin: HttpMethodsPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com/api", user_id=1)

        mock_client = AsyncMock()

        async def mock_request(method, url, headers=None):
            if method == "OPTIONS":
                return httpx.Response(
                    status_code=200,
                    headers={"Allow": "GET, POST, HEAD, OPTIONS"},
                )
            if method == "TRACE":
                return httpx.Response(status_code=405, text="Method Not Allowed")
            return httpx.Response(status_code=200, text="OK")

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        # Standard safe methods -> 0 findings
        assert len(context.findings) == 0
        assert set(context.metadata.get("allowed_http_methods", [])) == {"GET", "POST", "HEAD", "OPTIONS"}

    asyncio.run(_run())


def test_trace_active_xst_medium(plugin: HttpMethodsPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com/login", user_id=1)

        mock_client = AsyncMock()

        async def mock_request(method, url, headers=None):
            if method == "OPTIONS":
                return httpx.Response(
                    status_code=200,
                    headers={"Allow": "GET, POST, TRACE, OPTIONS"},
                )
            if method == "TRACE":
                # Server echoes back the request headers in response body
                echoed_body = (
                    "TRACE /login HTTP/1.1\r\n"
                    "Host: example.com\r\n"
                    "X-ShadowScan-Trace-Probe: xst-active-verification-probe\r\n"
                    "Cookie: session_id=secret123\r\n"
                )
                return httpx.Response(
                    status_code=200,
                    text=echoed_body,
                    headers={"content-type": "message/http"},
                )
            return httpx.Response(status_code=200, text="OK")

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("HTTP TRACE Method Enabled" in t for t in titles)
        finding = next(f for f in context.findings if "HTTP TRACE Method Enabled" in f.title)
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_trace_advertised_but_disabled(plugin: HttpMethodsPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_request(method, url, headers=None):
            if method == "OPTIONS":
                return httpx.Response(
                    status_code=200,
                    headers={"Allow": "GET, POST, TRACE, OPTIONS"},
                )
            if method == "TRACE":
                return httpx.Response(status_code=405, text="Method Not Allowed")
            return httpx.Response(status_code=200, text="OK")

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("HTTP TRACE Method Advertised in Allow Header" in t for t in titles)
        finding = next(f for f in context.findings if "Advertised in Allow Header" in f.title)
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_put_and_delete_advertised(plugin: HttpMethodsPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com/api/items", user_id=1)

        mock_client = AsyncMock()

        async def mock_request(method, url, headers=None):
            if method == "OPTIONS":
                return httpx.Response(
                    status_code=200,
                    headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"},
                )
            if method == "TRACE":
                return httpx.Response(status_code=405, text="Method Not Allowed")
            return httpx.Response(status_code=200, text="OK")

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Potentially Risky HTTP Methods Advertised" in t for t in titles)
        finding = next(f for f in context.findings if "Risky HTTP Methods" in f.title)
        assert finding.severity == Severity.LOW
        assert "PUT, DELETE" in finding.title or "DELETE, PUT" in finding.title

    asyncio.run(_run())


def test_connect_method_advertised(plugin: HttpMethodsPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_request(method, url, headers=None):
            if method == "OPTIONS":
                return httpx.Response(
                    status_code=200,
                    headers={"Allow": "GET, POST, CONNECT, OPTIONS"},
                )
            if method == "TRACE":
                return httpx.Response(status_code=405, text="Method Not Allowed")
            return httpx.Response(status_code=200, text="OK")

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("HTTP CONNECT Method Advertised" in t for t in titles)

    asyncio.run(_run())


def test_network_exception_handled_gracefully(plugin: HttpMethodsPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()
        mock_client.request.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
