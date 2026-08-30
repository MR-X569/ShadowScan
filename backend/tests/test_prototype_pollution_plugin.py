"""
Tests for PrototypePollutionPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.prototype_pollution import PrototypePollutionPlugin


@pytest.fixture
def plugin() -> PrototypePollutionPlugin:
    return PrototypePollutionPlugin()


def test_server_side_prototype_pollution_high(plugin: PrototypePollutionPlugin):
    """Test detection of server-side prototype property assignment in JSON response."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/settings?config=default",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "shadow_proto_prop" in url:
                # Server recursively merged query params and polluted object response
                response_json = '{"status": "ok", "shadow_proto_prop": "shadow_proto_val"}'
                return httpx.Response(
                    status_code=200,
                    text=response_json,
                    headers={"content-type": "application/json"},
                )
            return httpx.Response(
                status_code=200,
                text='{"status": "ok"}',
                headers={"content-type": "application/json"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Server-Side Prototype Pollution" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_nested_constructor_prototype_pattern(plugin: PrototypePollutionPlugin):
    """Test constructor[prototype] pattern triggering prototype mutation error."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/merge?__proto__=1",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "constructor" in url or "shadow_proto_prop" in url:
                error_body = "TypeError: Cannot assign to read only property 'shadow_proto_prop' of object '#<Object>'"
                return httpx.Response(status_code=500, text=error_body)
            return httpx.Response(status_code=200, text="Clean page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Prototype Pollution" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_static_client_side_vulnerable_merge_low(plugin: PrototypePollutionPlugin):
    """Test static analysis detection of unsafe client-side recursive merge in script tag."""
    async def _run():
        vuln_html = """
        <html>
        <head>
            <script>
            function mergeObjects(target, source) {
                for (var key in source) {
                    target[key] = source[key];
                }
                return target;
            }
            // Uses __proto__ in object operations
            var p = Object.prototype;
            </script>
        </head>
        <body>Application Content</body>
        </html>
        """
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = vuln_html

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text=vuln_html)
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Client-Side Object Merge" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_literal_reflection_suppression(plugin: PrototypePollutionPlugin):
    """Test that literal reflection of the parameter does not trigger false positive."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?query=test",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Normal HTML page echoing user query string
            return httpx.Response(
                status_code=200,
                text=f"<div>Results for: {url}</div>",
                headers={"content-type": "text/html"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_documentation_suppression(plugin: PrototypePollutionPlugin):
    """Test that markdown / security documentation mentioning prototype pollution is ignored."""
    async def _run():
        doc_html = """
        <html>
        <body>
            <h1># Prototype Pollution Vulnerability Guide</h1>
            <p>Understanding CVE-2020 prototype pollution risks in Node.js applications.</p>
            <script>
            // Sample documentation code
            function demo(target, source) {
                target[key] = source[key];
            }
            </script>
        </body>
        </html>
        """
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs/security/prototype-pollution",
            user_id=1,
        )
        context.html = doc_html

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text=doc_html)
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_response_no_findings(plugin: PrototypePollutionPlugin):
    """Test clean target yields no findings."""
    async def _run():
        clean_html = "<html><body>Simple static page</body></html>"
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/about",
            user_id=1,
        )
        context.html = clean_html

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text=clean_html)
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_error_handling_graceful(plugin: PrototypePollutionPlugin):
    """Test exceptions during probe requests are caught cleanly."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/data?config=test",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.NetworkError("Network down")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
