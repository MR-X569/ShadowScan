"""
Tests for SourceMapDisclosurePlugin.
"""

import asyncio
import json
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.source_map_disclosure import SourceMapDisclosurePlugin


@pytest.fixture
def plugin() -> SourceMapDisclosurePlugin:
    return SourceMapDisclosurePlugin()


def test_exposed_source_map_with_secrets_high(plugin: SourceMapDisclosurePlugin):
    """Test source map with embedded secret in sourcesContent triggers HIGH finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = '<script src="/static/js/app.js"></script>'

        mock_client = AsyncMock()

        map_payload = {
            "version": 3,
            "sources": ["src/config.ts", "src/auth.ts"],
            "mappings": "AAAA,SAASA...",
            "sourcesContent": [
                'export const API_KEY = "AIzaSyD-Secret123456789";',
                'export function login() { return true; }',
            ],
        }

        async def mock_get(url):
            if url.endswith(".map"):
                return httpx.Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=json.dumps(map_payload),
                )
            return httpx.Response(status_code=404)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Embedded Secrets & Credentials" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_production_source_map_with_sources_content_medium(plugin: SourceMapDisclosurePlugin):
    """Test standard production source map exposing source code triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/portal",
            user_id=1,
        )
        context.html = '<script src="/bundle.js"></script>'

        mock_client = AsyncMock()

        map_payload = {
            "version": 3,
            "sources": ["webpack:///src/components/Header.tsx"],
            "mappings": "AAAA,SAASA...",
            "sourcesContent": [
                "import React from 'react'; export const Header = () => <h1>Welcome</h1>;",
            ],
        }

        async def mock_get(url):
            if url.endswith(".map"):
                return httpx.Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=json.dumps(map_payload),
                )
            return httpx.Response(status_code=404)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Publicly Exposed JavaScript/CSS Source Map" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_internal_paths_disclosed_medium(plugin: SourceMapDisclosurePlugin):
    """Test source map with internal filesystem paths triggers MEDIUM finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = '<script src="/main.js"></script>'

        mock_client = AsyncMock()

        map_payload = {
            "version": 3,
            "sources": ["/home/developer/project/src/index.ts", "C:\\projects\\app\\src\\App.tsx"],
            "mappings": "AAAA...",
        }

        async def mock_get(url):
            if url.endswith(".map"):
                return httpx.Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=json.dumps(map_payload),
                )
            return httpx.Response(status_code=404)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_metadata_only_map_low(plugin: SourceMapDisclosurePlugin):
    """Test metadata-only map without embedded source code triggers LOW finding."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = '<script src="/script.js"></script>'

        mock_client = AsyncMock()

        map_payload = {
            "version": 3,
            "sources": ["app.js"],
            "mappings": "AAAA...",
        }

        async def mock_get(url):
            if url.endswith(".map"):
                return httpx.Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=json.dumps(map_payload),
                )
            return httpx.Response(status_code=404)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Source Map Metadata" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_invalid_json_non_map_suppression(plugin: SourceMapDisclosurePlugin):
    """Test non-map JSON or HTML 404 response produces zero findings."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = '<script src="/app.js"></script>'

        mock_client = AsyncMock()

        async def mock_get(url):
            # Returns regular JSON object that is not a source map
            return httpx.Response(
                status_code=200,
                headers={"content-type": "application/json"},
                text='{"status": "ok", "message": "not a source map"}',
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_sensitive_query_redaction_in_evidence(plugin: SourceMapDisclosurePlugin):
    """Test sensitive tokens in candidate URL are redacted in finding evidence."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/?token=secret_jwt_12345",
            user_id=1,
        )
        context.html = '<script src="/main.js"></script>'

        mock_client = AsyncMock()
        map_payload = {
            "version": 3,
            "sources": ["src/app.tsx"],
            "mappings": "AAAA...",
            "sourcesContent": ["const x = 1;"],
        }

        async def mock_get(url):
            return httpx.Response(status_code=200, text=json.dumps(map_payload))

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert "[REDACTED]" in context.findings[0].evidence or "secret_jwt_12345" not in context.findings[0].evidence

    asyncio.run(_run())


def test_error_handling_graceful(plugin: SourceMapDisclosurePlugin):
    """Test network timeouts and errors are handled without throwing."""
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com",
            user_id=1,
        )
        context.html = '<script src="/app.js"></script>'

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
