"""
Tests for InfoDisclosurePlugin.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.info_disclosure import InfoDisclosurePlugin


@pytest.fixture
def plugin() -> InfoDisclosurePlugin:
    return InfoDisclosurePlugin()


def test_detailed_server_version_banner(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "server": "Apache/2.4.51 (Unix) OpenSSL/1.1.1l",
        }
        await plugin.run(context)

        assert len(context.findings) == 1
        assert "Detailed Server Version Banner Disclosed" in context.findings[0].title
        assert context.findings[0].severity == Severity.LOW

    asyncio.run(_run())


def test_generic_server_banner_no_false_positive(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "server": "cloudflare",
        }
        await plugin.run(context)

        # Generic server names without version numbers should not generate alerts
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_tech_and_diagnostic_headers(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {
            "x-powered-by": "PHP/8.1.2",
            "x-backend-server": "prod-app-node-04",
        }
        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Technology Banner Disclosed" in t for t in titles)
        assert any("Internal Diagnostic Header Disclosed" in t for t in titles)

    asyncio.run(_run())


def test_python_stack_trace_in_body(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.html = (
            "<html><body>"
            "<h1>Internal Server Error</h1>"
            "<pre>Traceback (most recent call last):\n"
            "  File \"/app/main.py\", line 42, in get_user\n"
            "    user = db.query(User).filter_by(id=uid).one()\n"
            "ZeroDivisionError: division by zero</pre>"
            "</body></html>"
        )
        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Python Stack Trace" in t for t in titles)
        finding = next(f for f in context.findings if "Python Stack Trace" in f.title)
        assert finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_node_js_stack_trace_in_body(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.html = (
            "TypeError: Cannot read properties of undefined (reading 'id')\n"
            "    at /app/routes/users.js:15:24\n"
            "    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)"
        )
        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Node.js Stack Trace" in t for t in titles)

    asyncio.run(_run())


def test_sql_syntax_error_in_body(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.html = "<div>Database Error: SQL syntax error near 'SELECT * FROM users WHERE'</div>"
        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Database Error" in t for t in titles)

    asyncio.run(_run())


def test_exposed_env_file_probe(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com/login", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/.env"):
                return httpx.Response(
                    status_code=200,
                    text="APP_ENV=production\nDB_PASSWORD=SuperSecretPass123!\nJWT_SECRET=xyz987\n",
                )
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Exposed Environment File (.env)" in t for t in titles)
        finding = next(f for f in context.findings if ".env" in f.title)
        assert finding.severity == Severity.CRITICAL

    asyncio.run(_run())


def test_exposed_git_head_probe(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        async def mock_get(url):
            if url.endswith("/.git/HEAD"):
                return httpx.Response(
                    status_code=200,
                    text="ref: refs/heads/main\n",
                )
            return httpx.Response(status_code=404, text="Not Found")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Exposed Git Repository Metadata (.git/HEAD)" in t for t in titles)

    asyncio.run(_run())


def test_spa_200_html_false_positive_suppressed(plugin: InfoDisclosurePlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_client = AsyncMock()

        # SPA returns 200 OK index.html for all paths including /.env
        async def mock_get(url):
            return httpx.Response(
                status_code=200,
                text="<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>",
            )

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        # Should NOT trigger .env or .git finding because HTML anti-signature matched
        assert len(context.findings) == 0

    asyncio.run(_run())
