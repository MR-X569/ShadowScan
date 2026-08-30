"""
Tests for CsrfCheckPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.csrf_check import CsrfCheckPlugin


@pytest.fixture
def plugin() -> CsrfCheckPlugin:
    return CsrfCheckPlugin()


def test_post_form_with_csrf_token_no_findings(plugin: CsrfCheckPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/settings",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='/settings/update' method='POST'>"
            "  <input type='hidden' name='csrf_token' value='abcdef1234567890'>"
            "  <input type='text' name='email' value='user@example.com'>"
            "  <button type='submit'>Save</button>"
            "</form>"
            "</body></html>"
        )

        await plugin.run(context)

        # Form has valid CSRF token -> 0 findings
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_post_form_missing_csrf_token_finding(plugin: CsrfCheckPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/profile",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='/profile/change_password' method='POST'>"
            "  <input type='password' name='old_password'>"
            "  <input type='password' name='new_password'>"
            "  <button type='submit'>Change Password</button>"
            "</form>"
            "</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Anti-CSRF Token" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_state_changing_get_link_detected(plugin: CsrfCheckPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/dashboard",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "  <h1>Dashboard</h1>"
            "  <a href='/user/delete?id=42' class='btn-danger'>Delete Account</a>"
            "  <a href='/auth/logout'>Log Out</a>"
            "</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "State-Changing Operation Exposed via HTTP GET" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_harmless_search_get_form_suppressed(plugin: CsrfCheckPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/products",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='/search' method='GET'>"
            "  <input type='text' name='q' placeholder='Search products...'>"
            "  <button type='submit'>Search</button>"
            "</form>"
            "<a href='/products?page=2'>Next Page</a>"
            "</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_malformed_html_handled(plugin: CsrfCheckPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/broken",
            user_id=1,
        )
        context.html = "<form action=/invalid method=> <input name=none <button"

        await plugin.run(context)

        # Should not crash
        assert isinstance(context.findings, list)

    asyncio.run(_run())


def test_no_html_handled(plugin: CsrfCheckPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/empty",
            user_id=1,
        )
        context.html = ""

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
