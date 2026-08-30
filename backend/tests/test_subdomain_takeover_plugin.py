"""
Tests for SubdomainTakeoverPlugin.
"""

import asyncio
from unittest.mock import AsyncMock, patch
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.subdomain_takeover import SubdomainTakeoverPlugin


@pytest.fixture
def plugin() -> SubdomainTakeoverPlugin:
    return SubdomainTakeoverPlugin()


def test_github_pages_orphan_takeover_high(plugin: SubdomainTakeoverPlugin):
    """Test detection of dangling CNAME to GitHub Pages with orphan fingerprint."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://blog.example.com",
            user_id=1,
        )
        context.html = "<html><body>404 There isn't a GitHub Pages site here.</body></html>"

        with patch.object(plugin, "_resolve_cnames", new=AsyncMock(return_value=["myuser.github.io"])):
            await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Subdomain Takeover" in finding.title
        assert "GitHub Pages" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_amazon_s3_nosuchbucket_takeover_high(plugin: SubdomainTakeoverPlugin):
    """Test detection of dangling S3 website CNAME with NoSuchBucket XML response."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://assets.example.com",
            user_id=1,
        )
        context.html = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"

        with patch.object(plugin, "_resolve_cnames", new=AsyncMock(return_value=["assets.example.com.s3-website-us-east-1.amazonaws.com"])):
            await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Amazon S3" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_heroku_no_such_app_takeover_high(plugin: SubdomainTakeoverPlugin):
    """Test detection of dangling Heroku CNAME with No such app error."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://app.example.com",
            user_id=1,
        )
        context.html = "<title>No such app</title><body><p>There's nothing here, yet.</p></body>"

        with patch.object(plugin, "_resolve_cnames", new=AsyncMock(return_value=["app-prod.herokuapp.com"])):
            await plugin.run(context)

        assert len(context.findings) == 1
        assert "Heroku" in context.findings[0].title

    asyncio.run(_run())


def test_generic_404_suppressed(plugin: SubdomainTakeoverPlugin):
    """Test generic 404 without provider orphan signature is suppressed."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://docs.example.com",
            user_id=1,
        )
        # Generic 404
        context.html = "<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>"

        with patch.object(plugin, "_resolve_cnames", new=AsyncMock(return_value=["docs.github.io"])):
            await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_healthy_cname_suppressed(plugin: SubdomainTakeoverPlugin):
    """Test healthy cloud-hosted site with active content produces no finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://blog.example.com",
            user_id=1,
        )
        context.html = "<html><body><h1>Welcome to My Tech Blog</h1><p>Articles and tutorials...</p></body></html>"

        with patch.object(plugin, "_resolve_cnames", new=AsyncMock(return_value=["myblog.github.io"])):
            await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_dns_failure_handling(plugin: SubdomainTakeoverPlugin):
    """Test DNS failure / no CNAME is handled gracefully without errors."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://direct.example.com",
            user_id=1,
        )
        context.html = "<html><body>Direct IP Host</body></html>"

        with patch.object(plugin, "_resolve_cnames", new=AsyncMock(return_value=[])):
            await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_private_internal_host_suppressed(plugin: SubdomainTakeoverPlugin):
    """Test localhost and private IPs are skipped."""
    async def _run():
        for url in ("http://localhost:8000", "http://127.0.0.1:3000", "http://app.local"):
            context = ScanContext(
                scan_id=1,
                target_url=url,
                user_id=1,
            )
            context.html = "<Code>NoSuchBucket</Code>"

            with patch.object(plugin, "_resolve_cnames", new=AsyncMock(return_value=["test.s3.amazonaws.com"])):
                await plugin.run(context)

            assert len(context.findings) == 0

    asyncio.run(_run())
