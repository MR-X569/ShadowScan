"""
Tests for NosqlInjectionPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.nosql_injection import NosqlInjectionPlugin


@pytest.fixture
def plugin() -> NosqlInjectionPlugin:
    return NosqlInjectionPlugin()


def test_mongo_server_error_high(plugin: NosqlInjectionPlugin):
    """Test detection of MongoServerError / unknown top level operator."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/users?user=admin",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "%5B%24unknown_op_probe%5D" in url or "[$unknown_op_probe]" in url:
                error_html = (
                    "<h1>Internal Server Error</h1>"
                    "<p>MongoServerError: unknown top level operator: $unknown_op_probe. "
                    "If you have a field named '$unknown_op_probe', consider using $getField</p>"
                )
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="User Admin Details")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "NoSQL Injection" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_mongoose_cast_error_high(plugin: NosqlInjectionPlugin):
    """Test detection of Mongoose / BSON Cast to ObjectId error."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/items?id=123",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "%5B%24regex%5D" in url or "[$regex]" in url:
                error_html = "Cast to ObjectId failed for value '{ '$regex': '(' }' (type Object) at path '_id' for model 'Item'"
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="Item 123")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "NoSQL Injection" in context.findings[0].title
        assert "Mongoose" in context.findings[0].title or "BSON" in context.findings[0].title

    asyncio.run(_run())


def test_boolean_differential_nosql_high(plugin: NosqlInjectionPlugin):
    """Test detection of boolean differential NoSQL response ($ne vs $eq)."""
    async def _run():
        baseline_content = "<html><body>" + "Product catalog item details " * 25 + "</body></html>"
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/products?category=electronics",
            user_id=1,
        )
        context.html = baseline_content

        mock_client = AsyncMock()

        async def mock_get(url):
            if "%24ne" in url or "$ne" in url:
                # True condition: returns catalog items consistent with baseline
                return httpx.Response(status_code=200, text=baseline_content)
            if "%24eq" in url or "$eq" in url:
                # False condition: suppresses all items
                return httpx.Response(status_code=200, text="<html><body>No products found</body></html>")
            return httpx.Response(status_code=200, text=baseline_content)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Boolean-Based NoSQL Injection" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_baseline_suppression(plugin: NosqlInjectionPlugin):
    """Test that pre-existing MongoDB error in baseline does not trigger finding."""
    async def _run():
        baseline_err = "Tutorial: MongoServerError can occur when query operators are improperly configured."
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs/mongodb",
            user_id=1,
        )
        context.html = baseline_err

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text=baseline_err)
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_generic_json_error_suppression(plugin: NosqlInjectionPlugin):
    """Test generic JSON syntax errors without NoSQL signatures are suppressed."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/data?query=test",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=400,
            text="SyntaxError: Unexpected token in JSON at position 0",
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_response_no_findings(plugin: NosqlInjectionPlugin):
    """Test clean target response yields zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?q=phone",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text="Search results for phone")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_candidate_parameter_discovery(plugin: NosqlInjectionPlugin):
    """Test discovery and probing of candidate parameter from crawler metadata."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/lookup",
            user_id=1,
        )
        context.metadata["discovered_parameters"] = ["lookup", "document"]

        mock_client = AsyncMock()

        async def mock_get(url):
            if ("lookup%5B" in url or "lookup[" in url) and ("%24regex" in url or "$regex" in url):
                return httpx.Response(
                    status_code=500,
                    text="MongoError: Can't canonicalize query: BadValue: Regular expression is invalid",
                )
            return httpx.Response(status_code=200, text="API Lookup")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "lookup" in context.findings[0].title

    asyncio.run(_run())


def test_error_handling_graceful(plugin: NosqlInjectionPlugin):
    """Test exception resilience when requests fail or time out."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?user=test",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ReadTimeout("Read timeout")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
