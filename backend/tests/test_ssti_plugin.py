"""
Tests for SstiPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.ssti import SstiPlugin


@pytest.fixture
def plugin() -> SstiPlugin:
    return SstiPlugin()


def test_ssti_jinja_arithmetic_evaluated_high(plugin: SstiPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/render?template=welcome",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            from urllib.parse import unquote
            decoded = unquote(url)
            # If 7*7*7 probe injected, return 343; if 7*7 probe, return 49
            if "7*7*7" in decoded:
                return httpx.Response(status_code=200, text="<html><body>Template output: 343</body></html>")
            if "7*7" in decoded:
                return httpx.Response(status_code=200, text="<html><body>Template output: 49</body></html>")
            return httpx.Response(status_code=200, text="<html><body>Welcome to application</body></html>")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Server-Side Template Injection" in finding.title
        assert finding.severity == Severity.HIGH
        assert "template" in finding.title

    asyncio.run(_run())


def test_ssti_freemarker_arithmetic_evaluated_high(plugin: SstiPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/greet?name=user",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            from urllib.parse import unquote
            decoded = unquote(url)
            if "7*7*7" in decoded:
                return httpx.Response(status_code=200, text="Hello 343!")
            if "7*7" in decoded:
                return httpx.Response(status_code=200, text="Hello 49!")
            return httpx.Response(status_code=200, text="Hello user!")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert context.findings[0].severity == Severity.HIGH

    asyncio.run(_run())


def test_ssti_literal_reflection_suppressed(plugin: SstiPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?q=test",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Target reflects back the raw input string {{7*7}} without executing arithmetic
            if "%7B%7B7*7%7D%7D" in url or "{{7*7}}" in url:
                return httpx.Response(status_code=200, text="<html><body>Search query: {{7*7}}</body></html>")
            return httpx.Response(status_code=200, text="<html><body>Search page</body></html>")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Literal reflection is NOT SSTI
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_ssti_baseline_number_suppressed(plugin: SstiPlugin):
    async def _run():
        # Baseline HTML already contains number 49 (e.g. price $49)
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/items?view=grid",
            user_id=1,
        )
        context.html = "<html><body>Product Price: $49</body></html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="<html><body>Product Price: $49</body></html>",
        )
        context.session = mock_client

        await plugin.run(context)

        # 49 already in baseline must not trigger SSTI
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_ssti_clean_response_no_findings(plugin: SstiPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/catalog?page=1",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text="Catalog item page 1")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
