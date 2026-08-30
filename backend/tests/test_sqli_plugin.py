"""
Tests for SqliPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.sqli import SqliPlugin


@pytest.fixture
def plugin() -> SqliPlugin:
    return SqliPlugin()


def test_mysql_syntax_error_high(plugin: SqliPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/products?id=10",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "'" in url or "%27" in url:
                error_html = (
                    "<h1>Database Error</h1>"
                    "<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''10''' at line 1</p>"
                )
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="Product Details Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Error-Based SQL Injection" in finding.title
        assert "MySQL" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_postgresql_error_high(plugin: SqliPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/users?user=admin",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "'" in url or "%27" in url:
                error_html = "ERROR: syntax error at or near \"'admin'\" at character 42 (PSQLException)"
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="User Profile")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "PostgreSQL" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_mssql_error_high(plugin: SqliPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/items?item=1",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "'" in url or "%27" in url:
                error_html = "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string '1''."
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="Items List")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "Microsoft SQL Server" in context.findings[0].title

    asyncio.run(_run())


def test_sqlite_error_high(plugin: SqliPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/view?cat=books",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "'" in url or "%27" in url:
                error_html = "SQLite3::SQLException: unrecognized token: \"'\""
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="Category Books")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "SQLite" in context.findings[0].title

    asyncio.run(_run())


def test_oracle_error_high(plugin: SqliPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/order?id=5",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "'" in url or "%27" in url:
                error_html = "ORA-01756: quoted string not properly terminated"
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="Order Summary")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "Oracle" in context.findings[0].title

    asyncio.run(_run())


def test_boolean_differential_sqli_high(plugin: SqliPlugin):
    async def _run():
        baseline_content = "<html><body>" + "Item record details with description " * 20 + "</body></html>"
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?q=phone",
            user_id=1,
        )
        context.html = baseline_content

        mock_client = AsyncMock()

        async def mock_get(url):
            if "OR" in url:
                # TRUE condition -> returns full baseline results
                return httpx.Response(status_code=200, text=baseline_content)
            if "AND" in url:
                # FALSE condition -> returns 0 results / empty list
                return httpx.Response(status_code=200, text="<html><body>No items found.</body></html>")
            # Default quote test -> clean response without error
            return httpx.Response(status_code=200, text=baseline_content)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Boolean-Based Blind SQL Injection" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_baseline_error_prevents_false_positive(plugin: SqliPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/forum?topic=mysql",
            user_id=1,
        )
        context.html = "Discussion thread: You have an error in your SQL syntax in version 8.0"

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="Discussion thread: You have an error in your SQL syntax in version 8.0",
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_response_no_findings(plugin: SqliPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/page?p=1",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text="Clean page content")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
