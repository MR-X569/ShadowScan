"""
Tests for CacheControlSecurityPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.cache_control_security import CacheControlSecurityPlugin


@pytest.fixture
def plugin() -> CacheControlSecurityPlugin:
    return CacheControlSecurityPlugin()


def test_sensitive_authenticated_with_no_store_clean(plugin: CacheControlSecurityPlugin):
    """Test sensitive authenticated endpoint with no-store produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/v1/dashboard",
            user_id=1,
        )
        context.cookies = {"session_token": "abc123xyz"}
        context.headers = {
            "content-type": "application/json",
            "cache-control": "no-store, no-cache, must-revalidate, private",
            "pragma": "no-cache",
        }
        context.html = '{"user": "alice", "account_balance": 1000}'

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_dangerous_public_caching_of_authenticated_content_high(plugin: CacheControlSecurityPlugin):
    """Test authenticated profile marked with public caching triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/account/profile",
            user_id=1,
        )
        context.cookies = {"session_id": "secret_sess_123"}
        context.headers = {
            "content-type": "text/html",
            "cache-control": "public, max-age=3600, s-maxage=3600",
        }
        context.html = "<html><body><h1>User Alice Profile: alice@example.com</h1></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Unsafe Public/Shared Caching" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_missing_cache_control_on_sensitive_endpoint_medium(plugin: CacheControlSecurityPlugin):
    """Test sensitive API endpoint missing Cache-Control triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/user/settings",
            user_id=1,
        )
        context.headers = {"content-type": "application/json"}
        context.html = '{"settings": {"email": "alice@example.com"}}'

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Cache-Control Protection" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_private_caching_without_no_store_on_token_endpoint_low(plugin: CacheControlSecurityPlugin):
    """Test token endpoint using private caching without no-store triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/auth/token?token=secret123",
            user_id=1,
        )
        context.headers = {
            "content-type": "application/json",
            "cache-control": "private, max-age=600",
        }
        context.html = '{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.abc"}'

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Weak Cache-Control" in finding.title
        assert finding.severity == Severity.LOW
        assert "[REDACTED]" in finding.evidence

    asyncio.run(_run())


def test_public_static_asset_suppression(plugin: CacheControlSecurityPlugin):
    """Test public static assets (.css, .png) with public caching are suppressed."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/assets/styles.css",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/css",
            "cache-control": "public, max-age=86400",
        }
        context.html = "body { background: #fff; }"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_non_sensitive_page(plugin: CacheControlSecurityPlugin):
    """Test non-sensitive informational page yields no findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/about",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "cache-control": "max-age=3600",
        }
        context.html = "<html><body>About Us</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_empty_headers_graceful(plugin: CacheControlSecurityPlugin):
    """Test empty headers handled gracefully."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/profile",
            user_id=1,
        )
        context.headers = {}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
