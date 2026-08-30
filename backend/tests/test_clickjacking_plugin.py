"""
Tests for ClickjackingPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.clickjacking import ClickjackingPlugin


@pytest.fixture
def plugin() -> ClickjackingPlugin:
    return ClickjackingPlugin()


def test_x_frame_options_deny_protected(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"X-Frame-Options": "DENY"}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_x_frame_options_sameorigin_protected(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"X-Frame-Options": "SAMEORIGIN"}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_csp_frame_ancestors_none_protected(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_csp_frame_ancestors_self_protected(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"Content-Security-Policy": "frame-ancestors 'self'"}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_missing_anti_framing_protection_medium(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"Server": "nginx", "Content-Type": "text/html"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Anti-Framing Protection" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_wildcard_frame_ancestors_medium(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"Content-Security-Policy": "frame-ancestors *"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Wildcard" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_deprecated_allow_from_xfo_low(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"X-Frame-Options": "ALLOW-FROM https://partner.com"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Invalid or Deprecated X-Frame-Options" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_multiple_csp_headers_handled(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "content-security-policy": "script-src 'self'",
            "content-security-policy-report-only": "frame-ancestors 'self'",
        }

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_empty_headers_handled_gracefully(plugin: ClickjackingPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
