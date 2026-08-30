"""
Tests for GraphQLIntrospectionPlugin.
"""

import asyncio
import json
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.graphql_introspection import GraphQLIntrospectionPlugin


@pytest.fixture
def plugin() -> GraphQLIntrospectionPlugin:
    return GraphQLIntrospectionPlugin()


def test_introspection_with_sensitive_fields_high(plugin: GraphQLIntrospectionPlugin):
    """Test introspection exposing sensitive admin/password fields triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        schema_payload = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {"name": "AdminUser", "fields": [{"name": "password_hash"}, {"name": "api_key"}]},
                        {"name": "Query", "fields": [{"name": "getSecrets"}]},
                    ],
                }
            }
        }

        async def mock_request(method, url, content=None, headers=None):
            if method == "POST" and "/graphql" in url:
                return httpx.Response(status_code=200, text=json.dumps(schema_payload))
            return httpx.Response(status_code=404)

        mock_client.request = mock_request
        mock_client.get.return_value = httpx.Response(status_code=200, text="GraphQL Endpoint")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Sensitive Fields Exposed" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_standard_introspection_enabled_medium(plugin: GraphQLIntrospectionPlugin):
    """Test standard schema introspection enabled triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api",
            user_id=1,
        )

        mock_client = AsyncMock()

        schema_payload = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {"name": "Book", "fields": [{"name": "title"}, {"name": "author"}]},
                    ],
                }
            }
        }

        async def mock_request(method, url, content=None, headers=None):
            if method == "POST" and "/graphql" in url:
                return httpx.Response(status_code=200, text=json.dumps(schema_payload))
            return httpx.Response(status_code=404)

        mock_client.request = mock_request
        mock_client.get.return_value = httpx.Response(status_code=200, text="")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Schema Disclosed" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_field_suggestion_leakage_medium(plugin: GraphQLIntrospectionPlugin):
    """Test field suggestion ('Did you mean') with introspection disabled triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_request(method, url, content=None, headers=None):
            if method == "POST" and "/graphql" in url:
                content_str = content.decode("utf-8") if isinstance(content, bytes) else str(content)
                if "__schema" in content_str:
                    # Introspection disabled
                    return httpx.Response(
                        status_code=400,
                        text='{"errors": [{"message": "GraphQL introspection is disabled."}]}',
                    )
                elif "__shadowscan_nonexistent_field" in content_str:
                    # Probe triggers field suggestion leak
                    return httpx.Response(
                        status_code=400,
                        text='{"errors": [{"message": "Cannot query field \'__shadowscan_nonexistent_field\'. Did you mean \'systemStatus\'?"}]}',
                    )
            return httpx.Response(status_code=404)

        mock_client.request = mock_request
        mock_client.get.return_value = httpx.Response(status_code=200, text="")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Field Suggestion Schema Leakage" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_graphql_ide_exposed_low(plugin: GraphQLIntrospectionPlugin):
    """Test exposed GraphQL playground / GraphiQL console triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        # GET returns GraphQL Playground UI
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="<html><head><title>GraphQL Playground</title></head><body><script>GraphQLPlayground.init()</script></body></html>",
        )

        # POST introspection disabled and no suggestions
        mock_client.request.return_value = httpx.Response(
            status_code=400,
            text='{"errors": [{"message": "Introspection disabled"}]}',
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Interactive Console Exposed" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_introspection_securely_disabled_clean(plugin: GraphQLIntrospectionPlugin):
    """Test properly secured GraphQL endpoint yields zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=405, text="Method Not Allowed")
        mock_client.request.return_value = httpx.Response(
            status_code=400,
            text='{"errors": [{"message": "Invalid GraphQL operation."}]}',
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_non_graphql_404_suppressed(plugin: GraphQLIntrospectionPlugin):
    """Test non-existent endpoints (404) produce zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=404, text="Not Found")
        mock_client.request.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_error_handling_graceful(plugin: GraphQLIntrospectionPlugin):
    """Test network timeouts are handled gracefully."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ReadTimeout("Timeout")
        mock_client.request.side_effect = httpx.ReadTimeout("Timeout")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
