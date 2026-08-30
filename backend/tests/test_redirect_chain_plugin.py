"""
Tests for RedirectChainPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.redirect_chain import RedirectChainPlugin


@pytest.fixture
def plugin() -> RedirectChainPlugin:
    return RedirectChainPlugin()


def test_dangerous_javascript_scheme_high(plugin: RedirectChainPlugin):
    """Test Location header with javascript: scheme triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/goto?dest=x",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=302,
            headers={"location": "javascript:alert(document.domain)"},
            text="",
        )
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Dangerous Non-HTTP Redirect Scheme" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_sensitive_token_leak_to_external_domain_high(plugin: RedirectChainPlugin):
    """Test sensitive token forwarded across domain boundary triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/auth/callback?token=super_secret_token_abc",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if "example.com" in url:
                return httpx.Response(
                    status_code=302,
                    headers={"location": "https://external-partner.test/receive?token=super_secret_token_abc"},
                    text="",
                )
            return httpx.Response(status_code=200, text="External Page")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Sensitive Token / Credential Leakage" in finding.title
        assert finding.severity == Severity.HIGH
        assert "[REDACTED]" in finding.evidence
        assert "super_secret_token_abc" not in finding.evidence

    asyncio.run(_run())


def test_https_to_http_downgrade_medium(plugin: RedirectChainPlugin):
    """Test HTTPS redirecting to unencrypted HTTP triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://secure.example.com/login",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if url.startswith("https://"):
                return httpx.Response(
                    status_code=301,
                    headers={"location": "http://secure.example.com/home"},
                    text="",
                )
            return httpx.Response(status_code=200, text="Insecure Home")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Insecure Transport Downgrade" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_redirect_loop_low(plugin: RedirectChainPlugin):
    """Test circular redirect loop triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/step1",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if "step1" in url:
                return httpx.Response(status_code=302, headers={"location": "https://example.com/step2"})
            elif "step2" in url:
                return httpx.Response(status_code=302, headers={"location": "https://example.com/step1"})
            return httpx.Response(status_code=200, text="")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Redirect Loop Detected" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_excessive_redirect_chain_low(plugin: RedirectChainPlugin):
    """Test redirect chain > 5 hops triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/hop1",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            for i in range(1, 8):
                if f"hop{i}" in url:
                    return httpx.Response(status_code=302, headers={"location": f"https://example.com/hop{i+1}"})
            return httpx.Response(status_code=200, text="Done")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Excessive HTTP Redirect Chain" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_normal_same_origin_redirect_clean(plugin: RedirectChainPlugin):
    """Test normal same-origin redirect terminating at 200 OK produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url, follow_redirects=False):
            if url == "https://example.com/app":
                return httpx.Response(status_code=301, headers={"location": "https://example.com/app/"})
            return httpx.Response(status_code=200, text="Welcome App")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_error_handling_graceful(plugin: RedirectChainPlugin):
    """Test network timeouts during redirect tracing are handled cleanly."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/jump",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ReadTimeout("Timeout")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
