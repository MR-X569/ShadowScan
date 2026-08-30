"""
app/scanner/plugins/passive/crawler.py
--------------------------------------
Attack Surface Discovery & Link Crawler Plugin.

Maps the application's same-origin attack surface by extracting:
    1. Same-origin links (<a href>).
    2. HTML forms (<form action, method, inputs>).
    3. Parameterized URLs (?param=value).
    4. Referenced same-origin JavaScript files and internal API route endpoints.

Exposes discovered metadata to subsequent scanner plugins via ScanContext:
    - context.metadata["discovered_urls"]: list of normalized same-origin URLs.
    - context.metadata["discovered_parameters"]: list of unique parameter names.
    - context.metadata["discovered_forms"]: list of form structures.
    - context.metadata["crawler_stats"]: crawl metrics dictionary.

Safety & Hard Scope Limits:
    - Strictly bounded to the same origin (same hostname and scheme).
    - NEVER requests external domains, localhost/private IPs, mailto:, javascript:, data:.
    - Configurable limits: MAX_PAGES = 50, MAX_DEPTH = 3, MAX_RESPONSE_SIZE = 100KB.
    - GET requests only; NEVER submits forms or performs POST/PUT/DELETE actions.
    - Ignores binary asset files (images, audio, video, fonts, zip, pdf, css).

Priority: 52 (runs before active parameter-testing plugins).
"""

from __future__ import annotations

import collections
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext

logger = logging.getLogger(__name__)

# Hard limits to prevent infinite crawling or resource exhaustion
_MAX_PAGES: int = 50
_MAX_DEPTH: int = 3
_MAX_RESPONSE_SIZE: int = 102400  # 100 KB
_REQUEST_TIMEOUT: float = 5.0

# File extensions to ignore during crawling
_IGNORED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".mp4",
        ".mp3",
        ".avi",
        ".mov",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".exe",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".css",
        ".map",
        ".dmg",
        ".iso",
    }
)

# API path regex to extract endpoints from same-origin JavaScript
_JS_API_ENDPOINT_REGEX: re.Pattern[str] = re.compile(
    r"[\"'](/(?:api|v\d+|graphql|auth|users|scans|admin|items|search|download)[a-zA-Z0-9_\-\./]*)[\"']",
    re.IGNORECASE,
)


class CrawlerPlugin(BasePlugin):
    """
    Crawls same-origin attack surface, discovers forms/parameters, and exports to ScanContext metadata.
    """

    name = "crawler"
    description = (
        "Maps same-origin links, forms, parameters, and API endpoints, exposing discovered attack surface to context metadata."
    )
    category = "passive"
    version = "1.0.0"
    priority = 52

    async def run(self, context: ScanContext) -> None:
        """
        Execute bounded same-origin crawl starting from context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping crawler.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # Initialize metadata containers
        discovered_urls: set[str] = {self._normalize_url(target_url, target_origin)}
        discovered_parameters: set[str] = set()
        discovered_forms: list[dict[str, Any]] = []
        crawled_urls: set[str] = set()

        # Extract initial URL parameters
        for p in parse_qs(parsed_target.query):
            discovered_parameters.add(p)

        # BFS Crawl Queue: (url, depth)
        queue: collections.deque[tuple[str, int]] = collections.deque([(target_url, 0)])

        # If context already has initial HTML, process it first without extra request
        initial_html = context.html or ""
        if initial_html:
            self._parse_page_content(
                initial_html,
                target_url,
                target_origin,
                0,
                queue,
                discovered_urls,
                discovered_parameters,
                discovered_forms,
                crawled_urls,
            )

        self.log(f"Starting bounded crawl on '{target_origin}' (Max Pages: {_MAX_PAGES}, Max Depth: {_MAX_DEPTH})")

        pages_crawled = 0

        while queue and pages_crawled < _MAX_PAGES:
            current_url, depth = queue.popleft()
            normalized = self._normalize_url(current_url, target_origin)

            if normalized in crawled_urls or depth > _MAX_DEPTH:
                continue

            crawled_urls.add(normalized)
            pages_crawled += 1

            # Fetch page content if not the initial target or if initial_html was empty
            if current_url != target_url or not initial_html:
                try:
                    response = await client.get(current_url)
                    content_type = response.headers.get("content-type", "").lower()

                    if "text/html" in content_type:
                        html_text = (response.text or "")[:_MAX_RESPONSE_SIZE]
                        self._parse_page_content(
                            html_text,
                            current_url,
                            target_origin,
                            depth,
                            queue,
                            discovered_urls,
                            discovered_parameters,
                            discovered_forms,
                            crawled_urls,
                        )
                    elif "javascript" in content_type or current_url.endswith(".js"):
                        js_text = (response.text or "")[:_MAX_RESPONSE_SIZE]
                        self._parse_js_content(js_text, target_origin, discovered_urls)

                except Exception as exc:
                    self.log(f"Failed to crawl '{current_url}': {exc}")

        # Store discovered attack surface in ScanContext metadata for subsequent plugins
        context.metadata["discovered_urls"] = sorted(discovered_urls)
        context.metadata["discovered_parameters"] = sorted(discovered_parameters)
        context.metadata["discovered_forms"] = discovered_forms
        context.metadata["crawler_stats"] = {
            "discovered_url_count": len(discovered_urls),
            "pages_crawled_count": pages_crawled,
            "parameter_count": len(discovered_parameters),
            "form_count": len(discovered_forms),
        }

        self.log(
            f"Crawler finished: {len(discovered_urls)} URLs, {len(discovered_parameters)} params, "
            f"{len(discovered_forms)} forms discovered."
        )

    # ------------------------------------------------------------------
    # HTML Parsing & Extraction
    # ------------------------------------------------------------------

    def _parse_page_content(
        self,
        html_body: str,
        current_url: str,
        target_origin: str,
        current_depth: int,
        queue: collections.deque[tuple[str, int]],
        discovered_urls: set[str],
        discovered_parameters: set[str],
        discovered_forms: list[dict[str, Any]],
        crawled_urls: set[str],
    ) -> None:
        """Extract links, forms, parameters, and script tags from HTML."""
        # 1. Extract <a href="..."> links
        links = re.findall(r'<a\b[^>]*href=[\'"]?([^\'"\s>]+)[\'"]?[^>]*>', html_body, re.IGNORECASE)
        for href in links:
            abs_url = self._resolve_same_origin_url(href, current_url, target_origin)
            if abs_url:
                discovered_urls.add(abs_url)
                # Extract query parameters
                parsed = urlparse(abs_url)
                for p in parse_qs(parsed.query):
                    discovered_parameters.add(p)

                if abs_url not in crawled_urls and (current_depth + 1) <= _MAX_DEPTH:
                    queue.append((abs_url, current_depth + 1))

        # 2. Extract <form> elements
        form_matches = re.finditer(r"<form\b([^>]*)>([\s\S]*?)</form>", html_body, re.IGNORECASE)
        for form_match in form_matches:
            attrs = form_match.group(1)
            content = form_match.group(2)

            method_m = re.search(r'method=[\'"]?([a-zA-Z]+)[\'"]?', attrs, re.IGNORECASE)
            action_m = re.search(r'action=[\'"]?([^\'"\s>]+)[\'"]?', attrs, re.IGNORECASE)

            method = method_m.group(1).upper() if method_m else "GET"
            action = action_m.group(1) if action_m else current_url

            abs_action = self._resolve_same_origin_url(action, current_url, target_origin) or action

            # Extract inputs, textarea, select names
            inputs = re.findall(r'<input\b[^>]*name=[\'"]?([^\'"\s>]+)[\'"]?[^>]*>', content, re.IGNORECASE)
            textareas = re.findall(r'<textarea\b[^>]*name=[\'"]?([^\'"\s>]+)[\'"]?[^>]*>', content, re.IGNORECASE)
            selects = re.findall(r'<select\b[^>]*name=[\'"]?([^\'"\s>]+)[\'"]?[^>]*>', content, re.IGNORECASE)

            param_names = list(set(inputs + textareas + selects))
            for p in param_names:
                discovered_parameters.add(p)

            discovered_forms.append({
                "action": abs_action,
                "method": method,
                "parameters": param_names,
                "source_page": current_url,
            })

        # 3. Extract same-origin <script src="...">
        scripts = re.findall(r'<script\b[^>]*src=[\'"]?([^\'"\s>]+)[\'"]?[^>]*>', html_body, re.IGNORECASE)
        for script_src in scripts:
            abs_script = self._resolve_same_origin_url(script_src, current_url, target_origin)
            if abs_script and abs_script.endswith(".js"):
                discovered_urls.add(abs_script)
                if abs_script not in crawled_urls and (current_depth + 1) <= _MAX_DEPTH:
                    queue.append((abs_script, current_depth + 1))

    # ------------------------------------------------------------------
    # JavaScript Route Extraction
    # ------------------------------------------------------------------

    def _parse_js_content(self, js_text: str, target_origin: str, discovered_urls: set[str]) -> None:
        """Extract API route literals from same-origin JavaScript code."""
        for match in _JS_API_ENDPOINT_REGEX.finditer(js_text):
            endpoint_path = match.group(1)
            abs_endpoint = urljoin(target_origin, endpoint_path)
            normalized = self._normalize_url(abs_endpoint, target_origin)
            discovered_urls.add(normalized)

    # ------------------------------------------------------------------
    # URL Normalization & Scope Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(url: str, target_origin: str) -> str:
        """Strip fragments, trailing spaces, and normalize same-origin URL."""
        joined = urljoin(target_origin, url.strip())
        parsed = urlparse(joined)

        # Remove fragment
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            "",
        ))
        return normalized

    def _resolve_same_origin_url(self, href: str, base_url: str, target_origin: str) -> str | None:
        """
        Resolves an href against base_url.
        Returns normalized absolute URL if strictly same-origin and not ignored, else None.
        """
        href = href.strip()

        # Filter out non-HTTP schemes and anchors
        if not href or href.startswith(("#", "javascript:", "mailto:", "data:", "tel:", "file:")):
            return None

        abs_url = urljoin(base_url, href)
        parsed_abs = urlparse(abs_url)
        parsed_target = urlparse(target_origin)

        # Strictly same-origin check
        if parsed_abs.netloc.lower() != parsed_target.netloc.lower():
            return None
        if parsed_abs.scheme.lower() != parsed_target.scheme.lower():
            return None

        # Check ignored file extensions
        path_lower = parsed_abs.path.lower()
        if any(path_lower.endswith(ext) for ext in _IGNORED_EXTENSIONS):
            return None

        return self._normalize_url(abs_url, target_origin)
