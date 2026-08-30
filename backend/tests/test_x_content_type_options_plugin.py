"""
Tests for XContentTypeOptionsPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.x_content_type_options import XContentTypeOptionsPlugin


@pytest.fixture
def plugin() -> XContentTypeOptionsPlugin:
    return XContentTypeOptionsPlugin()


def test_missing_nosniff_medium(plugin: XContentTypeOptionsPlugin):
    """Test missing X-Content-Type-Options on HTML response triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/index.html",
            user_id=1,
        )
        context.headers = {"content-type": "text/html; charset=utf-8"}
        context.html = "<html><body><h1>Home</h1></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing X-Content-Type-Options" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_valid_nosniff_clean(plugin: XContentTypeOptionsPlugin):
    """Test valid 'nosniff' configuration produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html; charset=utf-8",
            "x-content-type-options": "nosniff",
        }
        context.html = "<html><body><h1>Dashboard</h1></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_invalid_header_value_low(plugin: XContentTypeOptionsPlugin):
    """Test invalid or non-standard header value triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "x-content-type-options": "0",
        }
        context.html = "<html><body>App</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Invalid X-Content-Type-Options" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_mime_confusion_js_in_text_plain_medium(plugin: XContentTypeOptionsPlugin):
    """Test detection of executable JavaScript served with text/plain and missing nosniff."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/static/script.txt",
            user_id=1,
        )
        context.headers = {"content-type": "text/plain"}
        context.html = "function executePayload() { window.location = 'https://attacker.com'; }"

        await plugin.run(context)

        # Missing header finding + MIME confusion finding
        assert len(context.findings) >= 1
        titles = [f.title for f in context.findings]
        assert any("MIME Confusion" in t for t in titles)

    asyncio.run(_run())


def test_mime_confusion_html_in_text_plain_medium(plugin: XContentTypeOptionsPlugin):
    """Test detection of HTML markup served with text/plain without nosniff."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/download/file.txt",
            user_id=1,
        )
        context.headers = {"content-type": "text/plain"}
        context.html = "<html><script>alert(document.cookie);</script></html>"

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("MIME Confusion: HTML Content" in t for t in titles)

    asyncio.run(_run())


def test_normal_json_response_clean(plugin: XContentTypeOptionsPlugin):
    """Test standard API JSON response with nosniff yields no findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/v1/users",
            user_id=1,
        )
        context.headers = {
            "content-type": "application/json",
            "x-content-type-options": "nosniff",
        }
        context.html = '{"users": [{"id": 1, "name": "Alice"}]}'

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_no_headers_graceful(plugin: XContentTypeOptionsPlugin):
    """Test empty context headers are handled without exception."""
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
