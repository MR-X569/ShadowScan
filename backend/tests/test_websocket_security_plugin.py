"""
Tests for WebSocketSecurityPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.websocket_security import WebSocketSecurityPlugin


@pytest.fixture
def plugin() -> WebSocketSecurityPlugin:
    return WebSocketSecurityPlugin()


def test_insecure_cleartext_ws_reference_medium(plugin: WebSocketSecurityPlugin):
    """Test detection of unencrypted ws:// reference on an HTTPS application."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/chat",
            user_id=1,
        )
        context.html = '<html><script>const socket = new WebSocket("ws://example.com/ws/live");</script></html>'

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=403, text="Forbidden")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Insecure Cleartext WebSocket" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_cswsh_cross_origin_handshake_accepted_high(plugin: WebSocketSecurityPlugin):
    """Test detection of Cross-Site WebSocket Hijacking when untrusted Origin is accepted in session context."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app",
            user_id=1,
        )
        context.cookies = {"session_id": "xyz123abc"}
        context.html = '<html><script>const ws = new WebSocket("/socket.io/");</script></html>'

        mock_client = AsyncMock()

        async def mock_get(url, headers=None, follow_redirects=False):
            if "socket.io" in url and headers and "evil-attacker.example.com" in headers.get("origin", ""):
                # Server improperly accepts untrusted cross-origin handshake
                return httpx.Response(
                    status_code=101,
                    headers={
                        "upgrade": "websocket",
                        "connection": "Upgrade",
                        "sec-websocket-accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                    },
                    text="",
                )
            return httpx.Response(status_code=403, text="Forbidden")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Cross-Site WebSocket Hijacking" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_cross_origin_handshake_accepted_unauthenticated_medium(plugin: WebSocketSecurityPlugin):
    """Test detection of weak Origin validation on unauthenticated endpoint without session cookies."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/feed",
            user_id=1,
        )
        context.html = '<html><script>const ws = new WebSocket("/ws");</script></html>'

        mock_client = AsyncMock()

        async def mock_get(url, headers=None, follow_redirects=False):
            if "/ws" in url:
                return httpx.Response(
                    status_code=101,
                    headers={
                        "upgrade": "websocket",
                        "connection": "Upgrade",
                        "sec-websocket-accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                    },
                    text="",
                )
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_cross_origin_rejected_no_finding(plugin: WebSocketSecurityPlugin):
    """Test server properly rejecting cross-origin handshake yields no finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/secure-chat",
            user_id=1,
        )
        context.html = '<html><script>const ws = new WebSocket("/ws");</script></html>'

        mock_client = AsyncMock()

        async def mock_get(url, headers=None, follow_redirects=False):
            # Server validates Origin and rejects untrusted cross-origin
            return httpx.Response(status_code=403, text="Cross-origin WebSocket connection forbidden")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_secure_wss_no_findings(plugin: WebSocketSecurityPlugin):
    """Test clean HTTPS application using secure wss:// with strict Origin rejection."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/dashboard",
            user_id=1,
        )
        context.html = '<html><script>const ws = new WebSocket("wss://example.com/cable");</script></html>'

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=403, text="Forbidden")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_endpoint_discovery_multiple(plugin: WebSocketSecurityPlugin):
    """Test discovery of candidate WebSocket endpoints from HTML content."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/portal",
            user_id=1,
        )
        context.html = """
        <html>
        <script>
            const a = new WebSocket("/graphql-ws");
            const b = new WebSocket("wss://example.com/cable");
        </script>
        </html>
        """

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=404, text="Not Found")
        context.session = mock_client

        await plugin.run(context)

        # Verified endpoints discovered without crash
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_error_handling_graceful(plugin: WebSocketSecurityPlugin):
    """Test network timeouts during handshake are caught gracefully."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/live",
            user_id=1,
        )
        context.html = '<html><script>const ws = new WebSocket("/ws");</script></html>'

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ReadTimeout("Timeout reading handshake")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
