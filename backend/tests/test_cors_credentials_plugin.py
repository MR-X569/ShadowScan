"""
Tests for CorsCredentialsPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.cors_credentials import CorsCredentialsPlugin


@pytest.fixture
def plugin() -> CorsCredentialsPlugin:
    return CorsCredentialsPlugin()


def test_arbitrary_origin_with_credentials_high(plugin: CorsCredentialsPlugin):
    """Test arbitrary origin reflection with credentials enabled on authenticated endpoint triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/user/profile",
            user_id=1,
        )
        context.cookies = {"session_id": "secret123"}

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            req_origin = headers.get("Origin", "") if headers else ""
            if req_origin:
                return httpx.Response(
                    status_code=200,
                    headers={
                        "access-control-allow-origin": req_origin,
                        "access-control-allow-credentials": "true",
                        "content-type": "application/json",
                    },
                    text='{"name": "Alice"}',
                )
            return httpx.Response(status_code=200, text="Profile")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Arbitrary Origin Reflection with Credentials" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_null_origin_with_credentials_medium(plugin: CorsCredentialsPlugin):
    """Test 'Origin: null' accepted with credentials triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/data",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            req_origin = headers.get("Origin", "") if headers else ""
            if req_origin == "null":
                return httpx.Response(
                    status_code=200,
                    headers={
                        "access-control-allow-origin": "null",
                        "access-control-allow-credentials": "true",
                    },
                    text="Data",
                )
            return httpx.Response(status_code=200, text="Data")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Null Origin Allowed with Credentials" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_prefix_bypass_with_credentials_medium(plugin: CorsCredentialsPlugin):
    """Test prefix domain matching with credentials triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/feed",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            req_origin = headers.get("Origin", "") if headers else ""
            if "example.com.shadowscan-eval.test" in req_origin:
                return httpx.Response(
                    status_code=200,
                    headers={
                        "access-control-allow-origin": req_origin,
                        "access-control-allow-credentials": "true",
                    },
                    text="Feed",
                )
            return httpx.Response(status_code=200, text="Feed")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Prefix Domain Matching" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_permissive_preflight_headers_with_credentials_low(plugin: CorsCredentialsPlugin):
    """Test wildcard preflight headers with credentials triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/v1/auth",
            user_id=1,
        )
        context.headers = {
            "access-control-allow-origin": "https://trusted.example.com",
            "access-control-allow-credentials": "true",
            "access-control-allow-headers": "*",
        }

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text="Auth API")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Permissive Preflight Headers" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_strict_allowlist_clean(plugin: CorsCredentialsPlugin):
    """Test strict trusted origin allowlist produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/status",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            # Server only reflects trusted whitelist, rejecting arbitrary test origins
            return httpx.Response(
                status_code=200,
                headers={"access-control-allow-origin": "https://app.example.com"},
                text="Status",
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_credential_redaction_in_evidence(plugin: CorsCredentialsPlugin):
    """Test sensitive tokens in query strings are redacted in finding evidence."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/data?token=super_secret_token_123",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, headers=None):
            req_origin = headers.get("Origin", "") if headers else ""
            if req_origin:
                return httpx.Response(
                    status_code=200,
                    headers={
                        "access-control-allow-origin": req_origin,
                        "access-control-allow-credentials": "true",
                    },
                    text="Secret Data",
                )
            return httpx.Response(status_code=200, text="Data")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "[REDACTED]" in context.findings[0].evidence
        assert "super_secret_token_123" not in context.findings[0].evidence

    asyncio.run(_run())


def test_error_handling_graceful(plugin: CorsCredentialsPlugin):
    """Test probe exceptions are handled without crashing."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/info",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
