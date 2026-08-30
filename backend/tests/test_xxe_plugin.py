"""
Tests for XxePlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.xxe import XxePlugin, _XXE_ENTITY_TOKEN


@pytest.fixture
def plugin() -> XxePlugin:
    return XxePlugin()


def test_xxe_entity_expanded_high(plugin: XxePlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/xml_service",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_request(method, url, content=None, headers=None):
            # Target parses incoming XML and expands internal entity &ssxxe;
            expanded_response = f"<response><status>OK</status><result>{_XXE_ENTITY_TOKEN}</result></response>"
            return httpx.Response(status_code=200, text=expanded_response, headers={"content-type": "application/xml"})

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "XML Entity Resolution" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_xxe_literal_reflection_suppressed(plugin: XxePlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/xml_echo",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_request(method, url, content=None, headers=None):
            # Target simply echoes back raw unparsed input (contains <!DOCTYPE and <!ENTITY)
            raw_echo = f"<!DOCTYPE root [ <!ENTITY ssxxe \"{_XXE_ENTITY_TOKEN}\"> ]><root><data>&ssxxe;</data></root>"
            return httpx.Response(status_code=200, text=raw_echo, headers={"content-type": "text/xml"})

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        # Raw literal reflection is not entity resolution
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_xxe_rejected_no_finding(plugin: XxePlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/soap",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_request(method, url, content=None, headers=None):
            # Server rejects DTD parsing with security error
            error_response = "<error>DOCTYPE is disallowed when parser feature 'disallow-doctype-decl' is set to true.</error>"
            return httpx.Response(status_code=400, text=error_response)

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_xxe_uses_crawler_discovered_urls(plugin: XxePlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.metadata["discovered_urls"] = ["https://example.com/api/import_xml_feed"]

        mock_client = AsyncMock()

        async def mock_request(method, url, content=None, headers=None):
            if "import_xml_feed" in url:
                return httpx.Response(
                    status_code=200,
                    text=f"<feed><item>{_XXE_ENTITY_TOKEN}</item></feed>",
                )
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        assert "import_xml_feed" in context.findings[0].title or "import_xml_feed" in context.findings[0].evidence

    asyncio.run(_run())


def test_xxe_network_error_handled(plugin: XxePlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/xml",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.request.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
