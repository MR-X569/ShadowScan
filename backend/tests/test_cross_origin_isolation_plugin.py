"""
Tests for CrossOriginIsolationPlugin.
"""

import asyncio
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.cross_origin_isolation import CrossOriginIsolationPlugin


@pytest.fixture
def plugin() -> CrossOriginIsolationPlugin:
    return CrossOriginIsolationPlugin()


def test_contradictory_coop_coep_conflict_high(plugin: CrossOriginIsolationPlugin):
    """Test COOP same-origin paired with COEP unsafe-none on sensitive page triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/account",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html; charset=utf-8",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "unsafe-none",
        }
        context.html = "<html><body><form action='/update'><input type='password' name='p'></form></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Contradictory Cross-Origin Isolation" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_invalid_header_value_medium(plugin: CrossOriginIsolationPlugin):
    """Test invalid or unrecognized header values trigger MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "cross-origin-opener-policy": "invalid-token-123",
        }
        context.html = "<html><body>App</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Invalid Cross-Origin Isolation Policy" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_missing_isolation_headers_on_sensitive_app_low(plugin: CrossOriginIsolationPlugin):
    """Test sensitive interactive page missing COOP/COEP triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/login",
            user_id=1,
        )
        context.headers = {"content-type": "text/html"}
        context.html = "<html><body><form><input type='text' name='user'><input type='password' name='pwd'></form></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Cross-Origin Isolation Headers" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_full_isolation_require_corp_clean(plugin: CrossOriginIsolationPlugin):
    """Test fully isolated configuration with require-corp produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
        }
        context.html = "<html><body>App</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0
        assert context.get_metadata("cross_origin_isolated") is True

    asyncio.run(_run())


def test_full_isolation_credentialless_clean(plugin: CrossOriginIsolationPlugin):
    """Test fully isolated configuration with credentialless produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "credentialless",
        }
        context.html = "<html><body>App</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0
        assert context.get_metadata("cross_origin_isolated") is True

    asyncio.run(_run())


def test_json_api_endpoint_ignored(plugin: CrossOriginIsolationPlugin):
    """Test non-document JSON API responses are ignored."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/v1/users",
            user_id=1,
        )
        context.headers = {"content-type": "application/json"}
        context.html = '{"users": []}'

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_coop_coep_with_report_to_parameter_clean(plugin: CrossOriginIsolationPlugin):
    """Test COOP/COEP headers containing ; report-to= parameters are parsed cleanly."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.headers = {
            "content-type": "text/html",
            "cross-origin-opener-policy": 'same-origin; report-to="coop-endpoint"',
            "cross-origin-embedder-policy": 'require-corp; report-to="coep-endpoint"',
        }
        context.html = "<html><body>App</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0
        assert context.get_metadata("cross_origin_isolated") is True

    asyncio.run(_run())


def test_empty_headers_graceful(plugin: CrossOriginIsolationPlugin):
    """Test empty headers handled gracefully."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.headers = {}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


