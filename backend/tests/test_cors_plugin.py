"""
Tests for CorsMisconfigurationPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.cors import CorsMisconfigurationPlugin


@pytest.fixture
def plugin() -> CorsMisconfigurationPlugin:
    return CorsMisconfigurationPlugin()


def test_passive_wildcard_origin(plugin: CorsMisconfigurationPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://api.example.com/data", user_id=1)
        context.headers = {
            "access-control-allow-origin": "*",
        }
        await plugin.run(context)

        assert len(context.findings) == 1
        assert "Wildcard Origin Allowed" in context.findings[0].title
        assert context.findings[0].severity == Severity.LOW

    asyncio.run(_run())


def test_passive_wildcard_with_credentials_invalid(plugin: CorsMisconfigurationPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://api.example.com/data", user_id=1)
        context.headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        await plugin.run(context)

        assert len(context.findings) == 1
        assert "Wildcard Origin With Credentials" in context.findings[0].title
        assert context.findings[0].severity == Severity.HIGH

    asyncio.run(_run())


def test_passive_null_origin_with_credentials(plugin: CorsMisconfigurationPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://api.example.com/data", user_id=1)
        context.headers = {
            "access-control-allow-origin": "null",
            "access-control-allow-credentials": "true",
        }
        await plugin.run(context)

        assert len(context.findings) == 1
        assert "Null Origin Allowed With Credentials" in context.findings[0].title
        assert context.findings[0].severity == Severity.HIGH

    asyncio.run(_run())


def test_active_arbitrary_origin_reflection_critical(plugin: CorsMisconfigurationPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com/api/user", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            origin = (headers or {}).get("Origin", "")
            # Server reflects any Origin with credentials=true
            resp_headers = {
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            }
            return httpx.Response(status_code=200, headers=resp_headers)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        severities = [f.severity for f in context.findings]

        assert any("Arbitrary Origin Reflection with Credentials" in t for t in titles)
        assert Severity.CRITICAL in severities

    asyncio.run(_run())


def test_active_prefix_bypass_reflection_critical(plugin: CorsMisconfigurationPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com/api/user", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            origin = (headers or {}).get("Origin", "")
            if "example.com" in origin and "attacker" in origin:
                # Server improperly trusts origin starting with target domain
                return httpx.Response(
                    status_code=200,
                    headers={
                        "access-control-allow-origin": origin,
                        "access-control-allow-credentials": "true",
                    },
                )
            return httpx.Response(status_code=200, headers={})

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Prefix/Subdomain Trust Bypass with Credentials" in t for t in titles)
        prefix_finding = next(f for f in context.findings if "Prefix/Subdomain" in f.title)
        assert prefix_finding.severity == Severity.CRITICAL

    asyncio.run(_run())


def test_secure_cors_no_findings(plugin: CorsMisconfigurationPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            # Server properly rejects untrusted origins
            return httpx.Response(status_code=200, headers={})

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_network_exception_handled_gracefully(plugin: CorsMisconfigurationPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        # Should not raise exception
        await plugin.run(context)
        assert len(context.findings) == 0

    asyncio.run(_run())
