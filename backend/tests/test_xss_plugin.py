"""
Tests for XssPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.xss import XssPlugin, _XSS_PROBE_MARKER


@pytest.fixture
def plugin() -> XssPlugin:
    return XssPlugin()


def test_reflected_unescaped_html_body(plugin: XssPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?q=test",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Target reflects the probe marker directly into HTML body unescaped
            html_body = f"<html><body><h1>Search Results for: {_XSS_PROBE_MARKER}</h1></body></html>"
            return httpx.Response(
                status_code=200,
                text=html_body,
                headers={"content-type": "text/html; charset=utf-8"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Reflected Cross-Site Scripting" in finding.title
        assert finding.severity == Severity.HIGH
        assert "q" in finding.title

    asyncio.run(_run())


def test_html_encoded_reflection_suppressed(plugin: XssPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?q=test",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Safely HTML-encoded: &lt;ssxss&gt;
            safe_html = "<html><body><h1>Search Results for: ShadowScanXssProbe7a8b&lt;ssxss&gt;1</h1></body></html>"
            return httpx.Response(
                status_code=200,
                text=safe_html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Safely escaped marker must NOT generate finding
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_reflected_in_script_context_high(plugin: XssPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/item?name=sample",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Reflected inside <script> tag
            script_html = f"<html><head><script>var itemName = '{_XSS_PROBE_MARKER}';</script></head><body></body></html>"
            return httpx.Response(
                status_code=200,
                text=script_html,
                headers={"content-type": "text/html"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Reflected Cross-Site Scripting" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_reflected_in_attribute_context_high(plugin: XssPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/profile?user=guest",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Reflected inside input value attribute
            attr_html = f"<html><body><input type='text' name='user' value='{_XSS_PROBE_MARKER}'></body></html>"
            return httpx.Response(
                status_code=200,
                text=attr_html,
                headers={"content-type": "text/html"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert context.findings[0].severity == Severity.HIGH

    asyncio.run(_run())


def test_json_api_reflection_suppressed(plugin: XssPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/users?search=guest",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Reflected inside pure JSON API
            json_text = f'{{"status": "ok", "query": "{_XSS_PROBE_MARKER}", "results": []}}'
            return httpx.Response(
                status_code=200,
                text=json_text,
                headers={"content-type": "application/json; charset=utf-8"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # JSON reflections are not HTML XSS
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_no_reflection_clean(plugin: XssPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/catalog?page=2",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="<html><body>Catalog Page 2</body></html>",
            headers={"content-type": "text/html"},
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_network_exception_handled_gracefully(plugin: XssPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?q=1",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
