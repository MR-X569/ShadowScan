"""
Tests for DirectoryListingPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.directory_listing import DirectoryListingPlugin


@pytest.fixture
def plugin() -> DirectoryListingPlugin:
    return DirectoryListingPlugin()


def test_apache_directory_listing_uploads(plugin: DirectoryListingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/uploads/"):
                html = (
                    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
                    "<html>\n"
                    " <head>\n"
                    "  <title>Index of /uploads</title>\n"
                    " </head>\n"
                    " <body>\n"
                    "<h1>Index of /uploads</h1>\n"
                    "<table>\n"
                    "<tr><th>Name</th><th>Last modified</th><th>Size</th></tr>\n"
                    "<tr><td><a href=\"/parent\">Parent Directory</a></td><td></td><td>-</td></tr>\n"
                    "<tr><td><a href=\"doc.pdf\">doc.pdf</a></td><td>2024-01-01</td><td>12K</td></tr>\n"
                    "</table>\n"
                    "</body></html>"
                )
                return httpx.Response(status_code=200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Directory Indexing Enabled on /uploads/" in t for t in titles)
        finding = next(f for f in context.findings if "/uploads/" in f.title)
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_sensitive_backup_directory_listing_high(plugin: DirectoryListingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/backup/"):
                html = "<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1></body></html>"
                return httpx.Response(status_code=200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Directory Indexing Enabled on /backup/" in t for t in titles)
        finding = next(f for f in context.findings if "/backup/" in f.title)
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_exposed_database_sql_dump_critical(plugin: DirectoryListingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/backup.sql"):
                sql_content = (
                    "-- MySQL dump 10.13  Distrib 8.0.28\n"
                    "CREATE TABLE `users` (\n"
                    "  `id` int NOT NULL AUTO_INCREMENT,\n"
                    "  `username` varchar(50) NOT NULL,\n"
                    "  `password_hash` varchar(255) NOT NULL\n"
                    ");\n"
                    "INSERT INTO `users` VALUES (1,'admin','$2b$12$eXampleHashedSecretPassword123');\n"
                )
                return httpx.Response(
                    status_code=200,
                    text=sql_content,
                    headers={"content-type": "application/sql"},
                )
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Exposed Database Dump File" in t for t in titles)
        finding = next(f for f in context.findings if "Database Dump" in f.title)
        assert finding.severity == Severity.CRITICAL

    asyncio.run(_run())


def test_exposed_zip_archive_high(plugin: DirectoryListingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/backup.zip"):
                # ZIP header: PK\x03\x04
                zip_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 100
                return httpx.Response(
                    status_code=200,
                    content=zip_bytes,
                    headers={"content-type": "application/zip"},
                )
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Exposed Backup Archive File" in t for t in titles)
        finding = next(f for f in context.findings if "Backup Archive" in f.title)
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_spa_200_html_fallback_suppressed(plugin: DirectoryListingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        # SPA router returns 200 OK with index.html for any requested path (/backup.sql, /uploads/, etc.)
        async def mock_get(url):
            spa_html = (
                "<!DOCTYPE html>"
                "<html lang=\"en\">"
                "<head><title>My React App</title></head>"
                "<body><div id=\"root\"></div><script src=\"/bundle.js\"></script></body>"
                "</html>"
            )
            return httpx.Response(
                status_code=200,
                text=spa_html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Anti-signature must suppress all false-positive directory/archive alerts
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_404_responses(plugin: DirectoryListingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
