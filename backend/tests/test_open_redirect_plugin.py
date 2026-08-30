"""
Tests for OpenRedirectPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.open_redirect import OpenRedirectPlugin


@pytest.fixture
def plugin() -> OpenRedirectPlugin:
    return OpenRedirectPlugin()


def test_vulnerable_external_redirect_302(plugin: OpenRedirectPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://mysite.com/login?redirect=https://mysite.com/dashboard",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if "redirect=https%3A%2F%2Fexample.com%2F" in url or "redirect=https://example.com/" in url:
                return httpx.Response(
                    status_code=302,
                    headers={"Location": "https://example.com/"},
                )
            return httpx.Response(status_code=200, text="OK")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Open Redirect Vulnerability" in finding.title
        assert finding.severity == Severity.HIGH
        assert "redirect" in finding.title

    asyncio.run(_run())


def test_protocol_relative_redirect_301(plugin: OpenRedirectPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://mysite.com/auth?next=/home",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            # Absolute payload (next=https...) is rejected with 400
            if "next=https" in url or "next=%2F%2F" not in url and "next=//" not in url:
                return httpx.Response(status_code=400, text="Bad Request")
            # Protocol-relative payload (next=//example.com...) is accepted with 301
            return httpx.Response(
                status_code=301,
                headers={"Location": "//example.com/"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Protocol-Relative" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_safe_same_origin_redirect_ignored(plugin: OpenRedirectPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://mysite.com/login?redirect=/dashboard",
            user_id=1,
        )

        mock_client = AsyncMock()

        # Application safely forces redirect to internal /dashboard regardless of payload
        async def mock_get(url, follow_redirects=False):
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://mysite.com/dashboard"},
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Same-origin redirect to mysite.com is safe -> 0 findings
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_redirect_307_and_308_status_codes(plugin: OpenRedirectPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://mysite.com/goto?url=default",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if "example.com" in url:
                return httpx.Response(
                    status_code=307,
                    headers={"Location": "https://example.com/target"},
                )
            return httpx.Response(status_code=200, text="OK")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "Open Redirect" in context.findings[0].title

    asyncio.run(_run())


def test_missing_location_header_on_302(plugin: OpenRedirectPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://mysite.com/login?next=1",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            return httpx.Response(status_code=302, headers={})

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_sanitized_rejected_parameter(plugin: OpenRedirectPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://mysite.com/login?return_to=/profile",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            # Application rejects external URLs with 403 Forbidden
            return httpx.Response(status_code=403, text="Forbidden external redirect")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0


def test_network_exception_handled_gracefully(plugin: OpenRedirectPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://mysite.com/login?redirect=1",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
