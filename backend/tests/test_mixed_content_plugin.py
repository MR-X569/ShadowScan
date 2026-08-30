"""
Tests for MixedContentPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.mixed_content import MixedContentPlugin


@pytest.fixture
def plugin() -> MixedContentPlugin:
    return MixedContentPlugin()


def test_active_mixed_script_high(plugin: MixedContentPlugin):
    """Test HTTPS page loading script over HTTP triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><head><script src='http://cdn.example.com/library.js'></script></head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Active Mixed Content" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_active_mixed_iframe_high(plugin: MixedContentPlugin):
    """Test HTTPS page embedding HTTP iframe triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://secure.example.com",
            user_id=1,
        )
        context.html = (
            "<html><body><iframe src='http://insecure-widget.test/frame'></iframe></body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Active Mixed Content" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_mixed_stylesheet_medium(plugin: MixedContentPlugin):
    """Test HTTPS page loading CSS over HTTP triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = (
            "<html><head><link rel='stylesheet' href='http://assets.example.com/style.css'></head><body>Content</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Mixed Content: Stylesheet" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_passive_mixed_image_low(plugin: MixedContentPlugin):
    """Test HTTPS page loading image over HTTP triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/blog",
            user_id=1,
        )
        context.html = (
            "<html><body><img src='http://media.example.com/photo.jpg?token=secret123'></body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Passive Mixed Content" in finding.title
        assert finding.severity == Severity.LOW
        assert "[REDACTED]" in finding.evidence
        assert "secret123" not in finding.evidence

    asyncio.run(_run())


def test_secure_https_page_clean(plugin: MixedContentPlugin):
    """Test page with all HTTPS and relative subresources produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<script src='https://cdn.example.com/app.js'></script>"
            "<link rel='stylesheet' href='/static/style.css'>"
            "</head><body><img src='//images.example.com/logo.png'></body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_http_target_suppressed(plugin: MixedContentPlugin):
    """Test plain HTTP targets are skipped."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="http://insecure-site.test",
            user_id=1,
        )
        context.html = "<html><body><script src='http://insecure-site.test/script.js'></script></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_empty_html_graceful(plugin: MixedContentPlugin):
    """Test empty HTML content handled gracefully."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = ""

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
