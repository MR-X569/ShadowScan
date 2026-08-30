"""
Tests for CookieSecurityPlugin.
"""

import asyncio
from unittest.mock import MagicMock
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.cookies import CookieSecurityPlugin


@pytest.fixture
def plugin() -> CookieSecurityPlugin:
    return CookieSecurityPlugin()


def test_no_cookies_found(plugin: CookieSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        await plugin.run(context)
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_fully_secure_session_cookie(plugin: CookieSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "set-cookie": "session_id=abc123secret; Path=/; Secure; HttpOnly; SameSite=Strict"
        }
        await plugin.run(context)
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_sensitive_cookie_missing_httponly_and_secure(plugin: CookieSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "set-cookie": "jwt_token=eyJh...; Path=/; SameSite=Lax"
        }
        await plugin.run(context)

        severities = [f.severity for f in context.findings]
        titles = [f.title for f in context.findings]

        # Should have HIGH for missing HttpOnly on sensitive cookie
        assert any("Missing HttpOnly" in t for t in titles)
        # Should have HIGH for missing Secure on HTTPS
        assert any("Missing Secure" in t for t in titles)
        assert Severity.HIGH in severities

    asyncio.run(_run())


def test_samesite_none_without_secure(plugin: CookieSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "set-cookie": "auth_sid=123; HttpOnly; SameSite=None"
        }
        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("SameSite=None Without Secure" in t for t in titles)
        samesite_finding = next(f for f in context.findings if "SameSite=None" in f.title)
        assert samesite_finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_general_cookie_missing_flags_low_severity(plugin: CookieSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "set-cookie": "user_preference=dark; Path=/"
        }
        await plugin.run(context)

        # General cookie should only have LOW severity findings, not HIGH
        for f in context.findings:
            assert f.severity in (Severity.LOW, Severity.MEDIUM)

    asyncio.run(_run())


def test_host_prefix_violation(plugin: CookieSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        # __Host- cookie must have Path=/, Secure, and NO Domain attribute
        context.headers = {
            "set-cookie": "__Host-session=xyz; Domain=example.com; Path=/app; HttpOnly"
        }
        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Invalid __Host- Cookie Prefix" in t for t in titles)

    asyncio.run(_run())


def test_multiple_cookies_from_httpx_response(plugin: CookieSecurityPlugin):
    async def _run():
        mock_response = MagicMock()
        mock_headers = MagicMock()
        mock_headers.get_list.return_value = [
            "session=abc; HttpOnly; Secure; SameSite=Lax",
            "tracker_id=123; SameSite=Lax",
        ]
        mock_response.headers = mock_headers

        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.response = mock_response

        await plugin.run(context)

        # session cookie is secure -> 0 findings for session
        # tracker_id missing HttpOnly & Secure -> LOW findings only
        titles = [f.title for f in context.findings]
        assert not any("session" in t for t in titles)
        assert any("tracker_id" in t for t in titles)

    asyncio.run(_run())
