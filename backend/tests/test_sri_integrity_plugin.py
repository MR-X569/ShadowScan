"""
Tests for SRIIntegrityPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.sri_integrity import SRIIntegrityPlugin


@pytest.fixture
def plugin() -> SRIIntegrityPlugin:
    return SRIIntegrityPlugin()


def test_missing_sri_on_external_script_high(plugin: SRIIntegrityPlugin):
    """Test external CDN script missing integrity attribute triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>"
            "</head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Subresource Integrity" in finding.title
        assert "cdn.jsdelivr.net" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_missing_sri_on_external_stylesheet_medium(plugin: SRIIntegrityPlugin):
    """Test external CDN stylesheet missing integrity attribute triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'>"
            "</head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Subresource Integrity (SRI) on External Stylesheet" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_weak_sri_algorithm_low(plugin: SRIIntegrityPlugin):
    """Test deprecated/weak hash algorithm (sha1-) triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<script src='https://cdn.example.net/lib.js' integrity='sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=' crossorigin='anonymous'></script>"
            "</head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Weak Cryptographic Hash Algorithm" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_missing_crossorigin_attribute_low(plugin: SRIIntegrityPlugin):
    """Test external SRI script missing crossorigin attribute triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<script src='https://cdn.example.net/lib.js' integrity='sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNMzMQK'></script>"
            "</head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing 'crossorigin' Attribute" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_valid_sri_clean(plugin: SRIIntegrityPlugin):
    """Test valid SRI configuration with sha384 and crossorigin produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<script src='https://cdn.jsdelivr.net/npm/vue@3.2.47/dist/vue.global.prod.js' "
            "integrity='sha384-9rT3v6rU3L9Vp...' crossorigin='anonymous'></script>"
            "<link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' "
            "integrity='sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM' crossorigin='anonymous'>"
            "</head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_same_origin_resources_suppressed(plugin: SRIIntegrityPlugin):
    """Test same-origin application scripts and stylesheets are suppressed."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<script src='/static/js/bundle.js'></script>"
            "<script src='https://example.com/static/js/main.js'></script>"
            "<link rel='stylesheet' href='/static/css/theme.css'>"
            "</head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_inline_scripts_ignored(plugin: SRIIntegrityPlugin):
    """Test inline scripts without src attributes are ignored."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = "<html><head><script>console.log('inline');</script></head><body>App</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_empty_html_graceful(plugin: SRIIntegrityPlugin):
    """Test empty HTML is handled gracefully."""
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


def test_multiple_integrity_hashes_clean(plugin: SRIIntegrityPlugin):
    """Test script with multiple valid space-separated SRI hashes produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = (
            "<html><head>"
            "<script src='https://cdn.example.net/lib.js' "
            "integrity='sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNMzMQK sha512-v9Q...' "
            "crossorigin='anonymous'></script>"
            "</head><body>App</body></html>"
        )

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())

