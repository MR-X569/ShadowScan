"""Integration tests for the bounded Playwright browser scanner."""

import asyncio
import threading
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, MagicMock, patch

from app.scanner.browser import BrowserScanConfig, BrowserScanner
from app.scanner.context import ScanContext
from app.scanner.engine import ScannerEngine


class _BrowserFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/first":
            body = """<!doctype html><title>Dynamic target</title><body><script>
              localStorage.setItem('from_first', 'yes');
              document.body.innerHTML = '<a id="dynamic-link" href="/after-js">after JS</a>' +
                '<form id="dynamic-form" action="/login" method="post"><input name="username"><input name="password" type="password"></form>';
              const asset = document.createElement('script'); asset.src = '/asset.js'; document.head.appendChild(asset);
              fetch('/api/data');
            </script></body>"""
            self._send(200, body, {"Set-Cookie": "browser_test=yes; Path=/"})
        elif self.path == "/second":
            self._send(200, "<!doctype html><title>Second</title>")
        elif self.path == "/ssrf":
            self._send(200, "<script>fetch('http://127.0.0.1:9/private').catch(() => {})</script>")
        elif self.path == "/redirect-private":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:80/private")
            self.end_headers()
        elif self.path == "/api/data":
            self._send(200, '{"ok": true}', {"Content-Type": "application/json"})
        elif self.path == "/asset.js":
            self._send(200, "window.assetLoaded = true;", {"Content-Type": "application/javascript"})
        else:
            self._send(404, "not found")

    def _send(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args) -> None:
        pass


def _server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BrowserFixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://localhost:{server.server_port}"


def _context(url: str) -> ScanContext:
    return ScanContext(scan_id=1, target_url=url, user_id=1)


def test_browser_scanner_collects_rendered_dom_network_and_storage() -> None:
    server, base_url = _server()
    validated: list[str] = []

    def allow_fixture(url: str) -> str:
        validated.append(url)
        return url

    try:
        context = _context(base_url + "/first")
        with patch("app.scanner.browser.validate_url_for_ssrf", side_effect=allow_fixture):
            asyncio.run(BrowserScanner().scan(context))

        browser = context.metadata["browser"]
        assert browser["status"] == "completed"
        assert browser["title"] == "Dynamic target"
        assert any(link["href"].endswith("/after-js") for link in browser["links"])
        assert browser["forms"][0]["action"].endswith("/login")
        assert set(browser["forms"][0]["parameters"]) == {"username", "password"}
        assert any(item["url"].endswith("/api/data") for item in browser["requests"])
        assert any(item["url"].endswith("/api/data") for item in browser["responses"])
        assert browser["storage"]["local_storage_keys"] == ["from_first"]
        assert browser["cookies"][0]["name"] == "browser_test"
        assert "dynamic-form" in context.html
        assert base_url + "/first" in validated
        assert base_url + "/api/data" in validated
    finally:
        server.shutdown()
        server.server_close()


def test_browser_contexts_are_isolated_between_scans() -> None:
    server, base_url = _server()
    try:
        with patch("app.scanner.browser.validate_url_for_ssrf", side_effect=lambda url: url):
            first = _context(base_url + "/first")
            second = _context(base_url + "/second")
            asyncio.run(BrowserScanner().scan(first))
            asyncio.run(BrowserScanner().scan(second))

        assert first.metadata["browser"]["cookies"]
        assert second.metadata["browser"]["cookies"] == []
        assert second.metadata["browser"]["storage"]["local_storage_keys"] == []
    finally:
        server.shutdown()
        server.server_close()


def test_browser_request_ssrf_is_blocked_before_connection() -> None:
    server, base_url = _server()
    from app.scanner.browser import validate_url_for_ssrf as real_validator

    def allow_only_fixture(url: str) -> str:
        if url.startswith(base_url):
            return url
        return real_validator(url)

    try:
        context = _context(base_url + "/ssrf")
        with patch("app.scanner.browser.validate_url_for_ssrf", side_effect=allow_only_fixture):
            asyncio.run(BrowserScanner().scan(context))

        browser = context.metadata["browser"]
        assert any(item["url"].startswith("http://127.0.0.1:9") for item in browser["blocked_requests"])
        assert any(f.plugin == "browser_scanner" for f in context.findings)
    finally:
        server.shutdown()
        server.server_close()


def test_browser_route_blocks_private_redirect_destination_before_continue() -> None:
    route = MagicMock()
    route.request = SimpleNamespace(
        url="http://127.0.0.1:80/private", method="GET", resource_type="document"
    )
    route.abort = AsyncMock()
    route.continue_ = AsyncMock()
    observation = {"requests": [], "responses": [], "blocked_requests": []}

    asyncio.run(BrowserScanner()._route_handler(observation)(route))

    route.abort.assert_awaited_once_with("blockedbyclient")
    route.continue_.assert_not_awaited()
    assert observation["blocked_requests"][0]["url"] == "http://127.0.0.1:80/private"


def test_browser_timeout_is_bounded() -> None:
    server, base_url = _server()
    try:
        context = _context(base_url + "/first")
        config = BrowserScanConfig(settle_timeout_ms=1, total_timeout_seconds=10)
        with patch("app.scanner.browser.validate_url_for_ssrf", side_effect=lambda url: url):
            asyncio.run(BrowserScanner(config).scan(context))
        assert context.metadata["browser"]["status"] == "completed"
        assert context.metadata["browser"].get("settle_timed_out") is True
    finally:
        server.shutdown()
        server.server_close()


def test_browser_request_limit_is_enforced() -> None:
    server, base_url = _server()
    try:
        context = _context(base_url + "/first")
        config = BrowserScanConfig(max_requests=1)
        with patch("app.scanner.browser.validate_url_for_ssrf", side_effect=lambda url: url):
            asyncio.run(BrowserScanner(config).scan(context))
        assert any(
            item["reason"] == "browser request limit reached"
            for item in context.metadata["browser"]["blocked_requests"]
        )
    finally:
        server.shutdown()
        server.server_close()


def test_engine_isolates_browser_failure_from_plugins() -> None:
    plugin = MagicMock()
    plugin.enabled = True
    plugin.name = "still_runs"
    plugin.run = AsyncMock()
    manager = MagicMock()
    manager.get_plugins.return_value = [plugin]
    manager.plugin_count.return_value = 1
    failing_browser = MagicMock()
    failing_browser.scan = AsyncMock(side_effect=RuntimeError("Chromium unavailable"))

    engine = ScannerEngine(manager, browser_scanner=failing_browser)
    asyncio.run(engine.run(scan_id=1, target_url="http://127.0.0.1", user_id=1))
    plugin.run.assert_awaited_once()
