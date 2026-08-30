"""
Tests for ClickjackingAdvancedPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.clickjacking_advanced import ClickjackingAdvancedPlugin


@pytest.fixture
def plugin() -> ClickjackingAdvancedPlugin:
    return ClickjackingAdvancedPlugin()


def test_sensitive_html_unprotected_high(plugin: ClickjackingAdvancedPlugin):
    """Test sensitive interactive page with no framing protection triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/account/settings",
            user_id=1,
        )
        context.headers = {"content-type": "text/html; charset=utf-8"}
        context.html = "<html><body><form action='/update'><input type='password' name='pwd'><button type='submit'>Save</button></form></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Unrestricted Framing" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_permissive_csp_overrides_xfo_conflict_medium(plugin: ClickjackingAdvancedPlugin):
    """Test permissive CSP frame-ancestors overriding restrictive XFO triggers MEDIUM conflict finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "content-security-policy": "frame-ancestors *; default-src 'self'",
            "x-frame-options": "DENY",
        }
        context.html = "<html><body>App</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Policy Conflict" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_broad_csp_wildcard_medium(plugin: ClickjackingAdvancedPlugin):
    """Test broad wildcard in frame-ancestors triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/portal",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "content-security-policy": "frame-ancestors https://*; default-src 'self'",
        }
        context.html = "<html><body>Portal</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Permissive Anti-Framing Policy" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_deprecated_allow_from_medium(plugin: ClickjackingAdvancedPlugin):
    """Test deprecated ALLOW-FROM XFO header triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/login",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "x-frame-options": "ALLOW-FROM https://partner.example.com",
        }
        context.html = "<html><body>Login Form</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Ineffective / Deprecated" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_legacy_conflict_low(plugin: ClickjackingAdvancedPlugin):
    """Test restrictive CSP combined with invalid XFO triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/dashboard",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "content-security-policy": "frame-ancestors 'self'",
            "x-frame-options": "INVALID_VAL",
        }
        context.html = "<html><body>Dashboard</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Legacy Anti-Framing Conflict" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_strong_csp_clean(plugin: ClickjackingAdvancedPlugin):
    """Test strong CSP frame-ancestors 'none' produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/checkout",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "content-security-policy": "frame-ancestors 'none'; default-src 'self'",
        }
        context.html = "<html><body>Checkout</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_strong_xfo_clean(plugin: ClickjackingAdvancedPlugin):
    """Test strong X-Frame-Options: SAMEORIGIN produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/page",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "x-frame-options": "SAMEORIGIN",
        }
        context.html = "<html><body>Page</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_non_frameable_json_api_clean(plugin: ClickjackingAdvancedPlugin):
    """Test non-frameable JSON API endpoint is ignored and produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/v1/data",
            user_id=1,
        )
        context.headers = {"content-type": "application/json"}
        context.html = '{"status": "ok"}'

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_empty_headers_graceful(plugin: ClickjackingAdvancedPlugin):
    """Test empty context headers are handled gracefully."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/unknown",
            user_id=1,
        )
        context.headers = {}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
