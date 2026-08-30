"""
Tests for SecurityPolicyPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.security_policy import SecurityPolicyPlugin


@pytest.fixture
def plugin() -> SecurityPolicyPlugin:
    return SecurityPolicyPlugin()


def test_valid_security_txt_future_expiry(plugin: SecurityPolicyPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "security.txt" in url:
                policy_content = (
                    "Contact: mailto:security@example.com\n"
                    "Expires: 2035-12-31T23:59:59.000Z\n"
                    "Preferred-Languages: en, es\n"
                    "Canonical: https://example.com/.well-known/security.txt\n"
                )
                return httpx.Response(status_code=200, text=policy_content)
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Valid security.txt with contact and future expiration -> 0 findings (metadata populated)
        assert len(context.findings) == 0
        assert context.metadata.get("has_security_txt") is True

    asyncio.run(_run())


def test_security_txt_missing_contact_low(plugin: SecurityPolicyPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "security.txt" in url:
                # Missing Contact: directive
                policy_content = (
                    "Expires: 2035-12-31T23:59:59.000Z\n"
                    "Preferred-Languages: en\n"
                )
                return httpx.Response(status_code=200, text=policy_content)
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Missing Required Contact Directive" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_security_txt_expired_low(plugin: SecurityPolicyPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "security.txt" in url:
                # Expired in 2020
                policy_content = (
                    "Contact: mailto:security@example.com\n"
                    "Expires: 2020-01-01T00:00:00.000Z\n"
                )
                return httpx.Response(status_code=200, text=policy_content)
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Policy Expired" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_robots_txt_security_path_extraction(plugin: SecurityPolicyPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "robots.txt" in url:
                robots_content = (
                    "User-agent: *\n"
                    "Disallow: /admin\n"
                    "Disallow: /backup/db.sql\n"
                    "Disallow: /private/api\n"
                    "Disallow: /public/css\n"
                )
                return httpx.Response(status_code=200, text=robots_content)
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Discovered paths stored in metadata
        discovered_paths = context.metadata.get("security_policy_discovered_paths", [])
        assert "/admin" in discovered_paths
        assert "/backup/db.sql" in discovered_paths
        assert "/private/api" in discovered_paths
        assert "/public/css" not in discovered_paths

    asyncio.run(_run())


def test_missing_security_txt_no_crash(plugin: SecurityPolicyPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        assert context.metadata.get("has_security_txt") is False

    asyncio.run(_run())


def test_security_policy_network_error_handled(plugin: SecurityPolicyPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
