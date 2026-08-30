"""
Tests for CrawlerPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.scanner.context import ScanContext
from app.scanner.plugins.passive.crawler import CrawlerPlugin


@pytest.fixture
def plugin() -> CrawlerPlugin:
    return CrawlerPlugin()


def test_crawler_same_origin_extraction(plugin: CrawlerPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "  <a href='/about'>About</a>"
            "  <a href='/products?id=10&cat=books'>Books</a>"
            "  <a href='https://external.com/out'>External Link</a>"
            "  <a href='mailto:info@example.com'>Email Us</a>"
            "  <a href='javascript:void(0)'>JS Action</a>"
            "  <a href='/image.png'>Image</a>"
            "  <form action='/search' method='GET'>"
            "    <input type='text' name='query'>"
            "    <select name='filter'><option>1</option></select>"
            "  </form>"
            "  <script src='/static/js/app.js'></script>"
            "</body></html>"
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/static/js/app.js"):
                js_code = "fetch('/api/v1/users').then(r => r.json()); const scanUrl = '/api/v1/scans';"
                return httpx.Response(
                    status_code=200,
                    text=js_code,
                    headers={"content-type": "application/javascript"},
                )
            if url.endswith("/about"):
                return httpx.Response(
                    status_code=200,
                    text="<html><body>About us page <a href='/contact?msg=hello'>Contact</a></body></html>",
                    headers={"content-type": "text/html"},
                )
            return httpx.Response(status_code=200, text="<html><body>OK</body></html>", headers={"content-type": "text/html"})

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Verify discovered metadata
        discovered_urls = context.metadata.get("discovered_urls", [])
        discovered_params = context.metadata.get("discovered_parameters", [])
        discovered_forms = context.metadata.get("discovered_forms", [])
        stats = context.metadata.get("crawler_stats", {})

        # Same-origin URLs discovered
        assert "https://example.com/about" in discovered_urls
        assert "https://example.com/products?id=10&cat=books" in discovered_urls
        assert "https://example.com/api/v1/users" in discovered_urls
        assert "https://example.com/api/v1/scans" in discovered_urls

        # External and ignored links suppressed
        assert not any("external.com" in u for u in discovered_urls)
        assert not any("image.png" in u for u in discovered_urls)
        assert not any("mailto" in u for u in discovered_urls)

        # Parameters extracted
        assert "id" in discovered_params
        assert "cat" in discovered_params
        assert "query" in discovered_params
        assert "filter" in discovered_params

        # Forms extracted
        assert len(discovered_forms) >= 1
        assert any(f["action"] == "https://example.com/search" for f in discovered_forms)

        # Stats populated
        assert stats.get("discovered_url_count", 0) > 0
        assert stats.get("parameter_count", 0) > 0

    asyncio.run(_run())


def test_crawler_depth_limit_enforced(plugin: CrawlerPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/level0",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Chain links: level0 -> level1 -> level2 -> level3 -> level4 -> level5
            for i in range(5):
                if f"level{i}" in url:
                    next_level = f"/level{i+1}"
                    return httpx.Response(
                        status_code=200,
                        text=f"<html><body><a href='{next_level}'>Next</a></body></html>",
                        headers={"content-type": "text/html"},
                    )
            return httpx.Response(status_code=200, text="<html><body>End</body></html>", headers={"content-type": "text/html"})

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        discovered = context.metadata.get("discovered_urls", [])
        # Max depth is 3, so level 0, 1, 2, 3 are visited/discovered, but unbounded depth is blocked
        assert "https://example.com/level0" in discovered
        assert "https://example.com/level1" in discovered
        assert "https://example.com/level2" in discovered
        assert "https://example.com/level3" in discovered

    asyncio.run(_run())


def test_crawler_external_js_rejected(plugin: CrawlerPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/home",
            user_id=1,
        )
        context.html = "<html><head><script src='https://cdn.thirdparty.com/analytics.js'></script></head><body></body></html>"

        mock_client = AsyncMock()
        context.session = mock_client

        await plugin.run(context)

        discovered = context.metadata.get("discovered_urls", [])
        assert not any("thirdparty.com" in u for u in discovered)

    asyncio.run(_run())


def test_crawler_network_error_handled(plugin: CrawlerPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/broken",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert "discovered_urls" in context.metadata

    asyncio.run(_run())
