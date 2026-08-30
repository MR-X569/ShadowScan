"""
Tests for HstsPreloadingPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.hsts_preloading import HstsPreloadingPlugin


@pytest.fixture
def plugin() -> HstsPreloadingPlugin:
    return HstsPreloadingPlugin()


def test_missing_hsts_header_high(plugin: HstsPreloadingPlugin):
    """Test HTTPS site missing HSTS header triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://secure.example.com",
            user_id=1,
        )
        context.headers = {"content-type": "text/html"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Strict-Transport-Security" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_strong_hsts_preload_ready_clean(plugin: HstsPreloadingPlugin):
    """Test full preload-ready HSTS configuration produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://app.example.com",
            user_id=1,
        )
        context.headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-type": "text/html",
        }

        await plugin.run(context)

        assert len(context.findings) == 0
        assert context.get_metadata("hsts_preload_ready") is True

    asyncio.run(_run())


def test_short_max_age_medium(plugin: HstsPreloadingPlugin):
    """Test HSTS max-age less than 1 year triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://app.example.com",
            user_id=1,
        )
        context.headers = {
            "strict-transport-security": "max-age=86400; includeSubDomains; preload",
            "content-type": "text/html",
        }

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Short Strict-Transport-Security" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_missing_includesubdomains_medium(plugin: HstsPreloadingPlugin):
    """Test HSTS missing includeSubDomains triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://app.example.com",
            user_id=1,
        )
        context.headers = {
            "strict-transport-security": "max-age=31536000; preload",
            "content-type": "text/html",
        }

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "includeSubDomains" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_missing_preload_low(plugin: HstsPreloadingPlugin):
    """Test HSTS with 1 yr max-age and includeSubDomains but missing preload triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://app.example.com",
            user_id=1,
        )
        context.headers = {
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "content-type": "text/html",
        }

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Not Preload-Ready" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_malformed_max_age_medium(plugin: HstsPreloadingPlugin):
    """Test non-numeric or conflicting max-age triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://app.example.com",
            user_id=1,
        )
        context.headers = {
            "strict-transport-security": "max-age=invalid_duration; includeSubDomains",
            "content-type": "text/html",
        }

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Malformed" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_localhost_suppressed(plugin: HstsPreloadingPlugin):
    """Test localhost/internal hosts are suppressed."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://localhost:8443",
            user_id=1,
        )
        context.headers = {}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
