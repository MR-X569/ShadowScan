"""
Tests for ApiSecurityPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.api_security import ApiSecurityPlugin


@pytest.fixture
def plugin() -> ApiSecurityPlugin:
    return ApiSecurityPlugin()


def test_openapi_json_exposed_medium(plugin: ApiSecurityPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/openapi.json"):
                spec_json = '{"openapi": "3.0.2", "info": {"title": "FastAPI App"}, "paths": {"/users": {}, "/admin/delete": {}}}'
                return httpx.Response(status_code=200, text=spec_json, headers={"content-type": "application/json"})
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        mock_client.request.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "OpenAPI / Swagger Specification" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_swagger_ui_html_exposed_low(plugin: ApiSecurityPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/docs"):
                docs_html = "<html><head><title>Swagger UI</title></head><body><div id='swagger-ui'></div></body></html>"
                return httpx.Response(status_code=200, text=docs_html, headers={"content-type": "text/html"})
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        mock_client.request.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Interactive Documentation Interface" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_graphql_introspection_enabled_medium(plugin: ApiSecurityPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=404, text="Not Found")

        async def mock_request(method, url, content=None, headers=None):
            if "graphql" in url and method == "POST":
                introspection_res = '{"data": {"__schema": {"types": [{"name": "User"}, {"name": "Query"}, {"name": "Mutation"}]}}}'
                return httpx.Response(status_code=200, text=introspection_res, headers={"content-type": "application/json"})
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.request = mock_request
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "GraphQL Introspection Enabled" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_graphiql_ide_exposed_low(plugin: ApiSecurityPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "graphql" in url:
                graphiql_html = "<html><head><title>GraphiQL</title></head><body><script>GraphiQL.createFetcher()</script></body></html>"
                return httpx.Response(status_code=200, text=graphiql_html, headers={"content-type": "text/html"})
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        mock_client.request.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "GraphQL Interactive IDE" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_fake_swagger_html_suppressed(plugin: ApiSecurityPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/blog/swagger-in-tech",
            user_id=1,
        )

        mock_client = AsyncMock()
        # Normal blog post mentioning the word swagger without being an API doc
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="<html><body>Blog post discussing API architecture and swagger tools.</body></html>",
            headers={"content-type": "text/html"},
        )
        mock_client.request.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_api_security_network_error_handled(plugin: ApiSecurityPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        mock_client.request.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
