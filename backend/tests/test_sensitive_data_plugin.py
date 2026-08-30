"""
Tests for SensitiveDataPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.sensitive_data import SensitiveDataPlugin


@pytest.fixture
def plugin() -> SensitiveDataPlugin:
    return SensitiveDataPlugin()


def test_aws_access_key_detected_critical(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/app.js",
            user_id=1,
        )
        # Real AWS Access Key format (20 alphanumeric characters starting with AKIA)
        context.html = "const aws_config = { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', region: 'us-east-1' };"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "AWS Access Key ID" in finding.title
        assert finding.severity == Severity.CRITICAL

        # Verify secret was properly redacted
        assert "AKIA****MPLE" in finding.evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence

    asyncio.run(_run())


def test_private_key_detected_critical(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/config.json",
            user_id=1,
        )
        context.html = (
            "{\n"
            '  "ssl_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Y...\\n-----END RSA PRIVATE KEY-----"\n'
            "}"
        )

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Private Cryptographic Key" in finding.title
        assert finding.severity == Severity.CRITICAL
        assert "[REDACTED PRIVATE KEY DATA]" in finding.evidence

    asyncio.run(_run())


def test_database_connection_string_critical(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/api/debug",
            user_id=1,
        )
        context.html = "Database initialized at: postgres://app_user:SuperSecretP@ss123@prod-db.internal:5432/app_db"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Database Connection String" in finding.title
        assert finding.severity == Severity.CRITICAL

        # Password must be redacted
        assert ":****@" in finding.evidence
        assert "SuperSecretP@ss123" not in finding.evidence

    asyncio.run(_run())


def test_google_api_key_detected_high(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/index.html",
            user_id=1,
        )
        # Google API Key format (AIza followed by 35 chars)
        context.html = "<script src='https://maps.googleapis.com/maps/api/js?key=AIzaSyD-1234567890abcdefABCDEF_1234567'></script>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Google Cloud API Key" in finding.title
        assert finding.severity == Severity.HIGH
        assert "AIza****4567" in finding.evidence

    asyncio.run(_run())


def test_github_token_detected_high(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/build.json",
            user_id=1,
        )
        context.html = '{"ci_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"}'

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "GitHub Personal Access Token" in finding.title
        assert finding.severity == Severity.HIGH
        assert "ghp_****yzAB" in finding.evidence

    asyncio.run(_run())


def test_same_origin_js_scanning(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/index.html",
            user_id=1,
        )
        context.html = "<html><head><script src='/static/js/bundle.js'></script></head><body></body></html>"

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/static/js/bundle.js"):
                js_content = "const config = { slackWebhook: 'https://hooks.slack.com/services/T12345678/B12345678/abcdef1234567890abcdef12' };"
                return httpx.Response(status_code=200, text=js_content)
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Slack Webhook" in finding.title
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_placeholders_ignored_no_false_positives(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs",
            user_id=1,
        )
        context.html = "Set api_key = 'your_api_key_placeholder' or 'your_secret_key' in your config."

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_response_no_findings(plugin: SensitiveDataPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/about",
            user_id=1,
        )
        context.html = "<html><body>About our company and security posture.</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
