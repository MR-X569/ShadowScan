"""
Tests for LdapInjectionPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.ldap_injection import LdapInjectionPlugin


@pytest.fixture
def plugin() -> LdapInjectionPlugin:
    return LdapInjectionPlugin()


def test_ldap_parser_error_detection_high(plugin: LdapInjectionPlugin):
    """Test detection of high-confidence LDAP parser syntax error (javax.naming)."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/directory?user=jdoe",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "%2A%29%28cn%3D%2A" in url or "*)(cn=*" in url or "%29%28" in url or ")(" in url:
                error_html = (
                    "<h1>Directory Service Error</h1>"
                    "<p>javax.naming.directory.InvalidSearchFilterException: [LDAP: error code 87 - Bad search filter]; "
                    "remaining name 'ou=users,dc=example,dc=com'</p>"
                )
                return httpx.Response(status_code=500, text=error_html)
            return httpx.Response(status_code=200, text="User Directory Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "LDAP Filter Injection" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_generic_ldap_filter_syntax_error(plugin: LdapInjectionPlugin):
    """Test detection of generic LDAP filter syntax error."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?filter=active",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            if "*)(&" in url or "%2A%29%28%26" in url or ")(" in url or "%29%28" in url or "*)(cn=*" in url:
                error_html = "LDAPException: Invalid filter syntax at position 12"
                return httpx.Response(status_code=200, text=error_html)
            return httpx.Response(status_code=200, text="Directory Search")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "LDAP" in finding.title

    asyncio.run(_run())


def test_baseline_error_suppression(plugin: LdapInjectionPlugin):
    """Test that pre-existing LDAP error on page does not cause false positives."""
    async def _run():
        baseline_err = "Static documentation: Bad search filter occurs when parentheses are mismatched."
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs/ldap?topic=errors",
            user_id=1,
        )
        context.html = baseline_err

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text=baseline_err)
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_response_no_findings(plugin: LdapInjectionPlugin):
    """Test clean target response yields zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/lookup?username=alice",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text="<h1>User Alice</h1>")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_literal_reflection_suppression(plugin: LdapInjectionPlugin):
    """Test that literal reflection of probe without LDAP parser errors is suppressed."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/echo?name=test",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Page simply reflects the parameter value
            return httpx.Response(status_code=200, text=f"Echo: {url}")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_candidate_parameter_discovery(plugin: LdapInjectionPlugin):
    """Test candidate parameter discovery from crawler metadata."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/org",
            user_id=1,
        )
        context.metadata["discovered_parameters"] = ["ou", "employee"]

        mock_client = AsyncMock()

        async def mock_get(url):
            if "ou=" in url and ("*)" in url or ")(" in url or "%29%28" in url):
                return httpx.Response(
                    status_code=500,
                    text="System.DirectoryServices.Protocols.LdapException: The search filter is invalid.",
                )
            return httpx.Response(status_code=200, text="Org Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "ou" in context.findings[0].title

    asyncio.run(_run())


def test_error_handling_graceful(plugin: LdapInjectionPlugin):
    """Test network/timeout exceptions are caught without raising unhandled error."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search?user=test",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
