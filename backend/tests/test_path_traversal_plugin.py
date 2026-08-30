"""
Tests for PathTraversalPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.path_traversal import PathTraversalPlugin


@pytest.fixture
def plugin() -> PathTraversalPlugin:
    return PathTraversalPlugin()


def test_linux_etc_passwd_traversal_high(plugin: PathTraversalPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/download?file=report.pdf",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Target server returns Linux /etc/passwd contents
            if "etc" in url and "passwd" in url:
                passwd_content = (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                )
                return httpx.Response(
                    status_code=200,
                    text=passwd_content,
                    headers={"content-type": "text/plain"},
                )
            return httpx.Response(status_code=200, text="PDF File Content")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Path Traversal" in finding.title
        assert finding.severity == Severity.HIGH
        assert "file" in finding.title

    asyncio.run(_run())


def test_windows_win_ini_traversal_high(plugin: PathTraversalPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/view?page=home",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Target server returns Windows win.ini contents
            if "win.ini" in url:
                win_ini_content = (
                    "; for 16-bit app support\n"
                    "[fonts]\n"
                    "[extensions]\n"
                    "[mci extensions]\n"
                    "[files]\n"
                )
                return httpx.Response(
                    status_code=200,
                    text=win_ini_content,
                    headers={"content-type": "text/plain"},
                )
            return httpx.Response(status_code=200, text="Home Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Path Traversal" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_filesystem_error_medium(plugin: PathTraversalPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/include?template=default",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Server exposes PHP open_basedir restriction error
            error_html = "Warning: file_get_contents(): open_basedir restriction in effect. File(/etc/passwd) is not within the allowed path(s)"
            return httpx.Response(status_code=500, text=error_html)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Path Traversal Indicator" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_spa_200_html_fallback_suppressed(plugin: PathTraversalPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs?path=intro",
            user_id=1,
        )

        mock_client = AsyncMock()

        # SPA returns index.html for all requests
        async def mock_get(url):
            spa_html = (
                "<!DOCTYPE html>"
                "<html><head><title>App</title></head>"
                "<body><div id=\"root\"></div><script src=\"/bundle.js\"></script></body></html>"
            )
            return httpx.Response(
                status_code=200,
                text=spa_html,
                headers={"content-type": "text/html; charset=utf-8"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Anti-signature must suppress false positives
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_normal_response_no_findings(plugin: PathTraversalPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/read?doc=readme",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="Welcome to the application readme.",
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_network_error_handled(plugin: PathTraversalPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/get?file=1",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
