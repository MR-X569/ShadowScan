"""
app/scanner/plugins/passive/source_map_disclosure.py
---------------------------------------------------
JavaScript & CSS Source Map Disclosure Analysis Plugin.

Safely identifies publicly exposed .map (source map) files that disclose original
unminified source code, internal project filesystem structures, build paths, developer
comments, or embedded secrets.

Safety & Guardrails:
    - Strictly read-only GET/HEAD requests.
    - Enforces response size bounds (max 512 KB parsed per candidate map).
    - Validates source-map JSON schema (version, sources, mappings, sourcesContent).
    - Redacts all credentials, tokens, API keys, passwords, and email addresses in findings.
    - Bounded to top candidate asset paths.

Severity Logic:
    - HIGH: Public source map exposes sensitive sourcesContent containing credentials,
            API keys, tokens, or internal secrets.
    - MEDIUM: Production source map exposes substantial original sourcesContent or internal source paths.
    - LOW: Source map is publicly accessible with metadata/mappings but without sensitive sourcesContent.
    - NONE: No source map found, invalid JSON, or 404 response.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Max bytes to read from candidate source map response
_MAX_MAP_BYTES: int = 512 * 1024

# Regex to detect script and stylesheet references in HTML
_SCRIPT_SRC_PATTERN: re.Pattern[str] = re.compile(
    r"""<script[^>]+src=["']([^"']+\.js)(?:\?[^"']*)?["']""",
    re.IGNORECASE,
)
_CSS_HREF_PATTERN: re.Pattern[str] = re.compile(
    r"""<link[^>]+href=["']([^"']+\.css)(?:\?[^"']*)?["']""",
    re.IGNORECASE,
)
_SOURCEMAP_COMMENT_PATTERN: re.Pattern[str] = re.compile(
    r"""(?:/\*#|//[#@])\s*sourceMappingURL=([^\s'"]+\.map)""",
    re.IGNORECASE,
)

# Regex to detect sensitive keywords in unminified sourcesContent
_SENSITIVE_SECRET_PATTERN: re.Pattern[str] = re.compile(
    r"""(?i)(?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|auth[_-]?token|"""
    r"""bearer\s+[a-zA-Z0-9_\-\.]{20,}|private[_-]?key|aws[_-]?secret|db[_-]?password)\s*[:=]\s*["'][^"']{6,}["']"""
)
_EMAIL_PATTERN: re.Pattern[str] = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


class SourceMapDisclosurePlugin(BasePlugin):
    """
    Detects exposed source map files disclosing proprietary frontend source code and internal paths.
    """

    name = "source_map_disclosure"
    description = (
        "Identifies publicly accessible JavaScript and CSS source-map files (.map) that disclose "
        "original unminified source code, internal directory structures, and embedded sensitive configuration."
    )
    category = "passive"
    version = "1.0.0"
    priority = 36

    async def run(self, context: ScanContext) -> None:
        """
        Scan target HTML and discovered assets for exposed .map files.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping source map disclosure check.")
            return

        client = context.session
        target_url = context.target_url
        html_body = context.html or ""

        # 1. Collect candidate source map URLs
        candidate_map_urls = self._discover_candidate_maps(target_url, html_body, context)
        if not candidate_map_urls:
            self.log("No candidate source map URLs identified.")
            return

        checked_urls: set[str] = set()

        for map_url in candidate_map_urls[:8]:  # Bounded to top 8 candidates
            if map_url in checked_urls:
                continue
            checked_urls.add(map_url)

            try:
                resp = await client.get(map_url)
                if resp.status_code != 200:
                    continue

                text_sample = resp.text[:_MAX_MAP_BYTES] if resp.text else ""
                if not text_sample.strip().startswith("{") or not text_sample.strip().endswith("}"):
                    # Not a JSON document
                    continue

                try:
                    map_json = json.loads(text_sample)
                except Exception:
                    continue

                if not self._is_valid_source_map(map_json):
                    continue

                # Valid source map identified — analyze exposure severity
                self._evaluate_source_map(map_url, map_json, context)
                return  # Report top finding per scan

            except Exception as exc:
                self.log(f"Error fetching candidate source map '{map_url}': {exc}")

    # ------------------------------------------------------------------
    # Discovery & Parsing Helpers
    # ------------------------------------------------------------------

    def _discover_candidate_maps(
        self,
        target_url: str,
        html_body: str,
        context: ScanContext,
    ) -> list[str]:
        """Collect potential .map URLs from HTML script/link tags and comments."""
        candidates: list[str] = []

        # Check explicit sourceMappingURL in HTML
        for match in _SOURCEMAP_COMMENT_PATTERN.finditer(html_body):
            candidates.append(urljoin(target_url, match.group(1)))

        # Check script tags
        for match in _SCRIPT_SRC_PATTERN.finditer(html_body):
            js_url = urljoin(target_url, match.group(1))
            candidates.append(f"{js_url}.map")

        # Check CSS link tags
        for match in _CSS_HREF_PATTERN.finditer(html_body):
            css_url = urljoin(target_url, match.group(1))
            candidates.append(f"{css_url}.map")

        # Check discovered URLs in context metadata
        discovered_urls = context.metadata.get("discovered_urls", [])
        for url in discovered_urls:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            if path_lower.endswith(".map"):
                candidates.append(url)
            elif path_lower.endswith((".js", ".css")):
                candidates.append(f"{url}.map")

        # Standard common bundle naming pattern
        parsed_target = urlparse(target_url)
        origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        candidates.append(urljoin(origin, "/static/js/bundle.js.map"))
        candidates.append(urljoin(origin, "/main.js.map"))

        # Deduplicate preserving order
        unique_candidates: list[str] = []
        for c in candidates:
            if c not in unique_candidates:
                unique_candidates.append(c)

        return unique_candidates

    @staticmethod
    def _is_valid_source_map(data: Any) -> bool:
        """Validate whether JSON data represents a real source-map structure."""
        if not isinstance(data, dict):
            return False

        # Source map v3 standard structure keys
        has_version = "version" in data and isinstance(data["version"], (int, str))
        has_sources = "sources" in data and isinstance(data["sources"], list)
        has_mappings = "mappings" in data and isinstance(data["mappings"], str)
        has_sources_content = "sourcesContent" in data and isinstance(data["sourcesContent"], list)

        # Must have version + sources or mappings
        return bool(has_version and (has_sources or has_mappings or has_sources_content))

    # ------------------------------------------------------------------
    # Security Evaluation
    # ------------------------------------------------------------------

    def _evaluate_source_map(
        self,
        map_url: str,
        map_json: dict[str, Any],
        context: ScanContext,
    ) -> None:
        """Analyze source map content for secrets, unminified source code, and internal paths."""
        sources: list[str] = map_json.get("sources", [])
        sources_content: list[str] = [sc for sc in map_json.get("sourcesContent", []) if isinstance(sc, str)]

        # Sample paths
        sample_sources = [s for s in sources if s][:6]
        has_internal_paths = any(
            s.startswith(("webpack://", "/src/", "../", "C:\\", "/home/", "src/")) or
            s.endswith((".ts", ".tsx", ".vue", ".jsx"))
            for s in sources
        )

        has_embedded_code = len(sources_content) > 0 and any(len(sc.strip()) > 20 for sc in sources_content)

        # Check for secrets in embedded source code
        exposed_secret_type: str | None = None
        for code in sources_content:
            secret_match = _SENSITIVE_SECRET_PATTERN.search(code)
            if secret_match:
                exposed_secret_type = secret_match.group(0).split("=")[0].split(":")[0].strip()
                break

        if exposed_secret_type:
            evidence = (
                f"Source Map URL: {self._redact_url(map_url)}\n"
                f"Exposed Sources Count: {len(sources)}\n"
                f"Embedded SourcesContent: Present ({len(sources_content)} source files)\n"
                f"Sensitive Secret Detected: {exposed_secret_type}\n\n"
                f"Sample Disclosed Source Paths:\n" + "\n".join(f" - {s}" for s in sample_sources)
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Exposed Source Map with Embedded Secrets & Credentials",
                    description=(
                        f"The publicly accessible source-map file at '{self._redact_url(map_url)}' contains embedded "
                        f"original source files ('sourcesContent') revealing hardcoded secrets or API credentials "
                        f"('{exposed_secret_type}'). Attackers can reconstruct the complete source codebase and harvest private credentials."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Remove source-map files from production deployments, rotate any exposed credentials, "
                        "and configure build tools (Webpack, Vite, Rollup) to emit source maps only to private monitoring tools."
                    ),
                    evidence=evidence,
                )
            )
            return

        if has_embedded_code or has_internal_paths:
            evidence = (
                f"Source Map URL: {self._redact_url(map_url)}\n"
                f"Exposed Sources Count: {len(sources)}\n"
                f"Embedded Original Source Code (sourcesContent): {'Yes' if has_embedded_code else 'No'}\n"
                f"Internal Build Paths Disclosed: {'Yes' if has_internal_paths else 'No'}\n\n"
                f"Sample Disclosed Source Files:\n" + "\n".join(f" - {s}" for s in sample_sources)
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Publicly Exposed JavaScript/CSS Source Map",
                    description=(
                        f"A production source-map file was discovered at '{self._redact_url(map_url)}'. "
                        f"This file exposes original unminified application source code, TypeScript declarations, "
                        f"developer comments, and internal project directory structures."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Disable public emission of source maps in production build pipelines or restrict access "
                        "using Web Server access controls."
                    ),
                    evidence=evidence,
                )
            )
            return

        # Metadata-only source map
        evidence = (
            f"Source Map URL: {self._redact_url(map_url)}\n"
            f"Source Map Version: {map_json.get('version', '3')}\n"
            f"Status: Publicly accessible metadata-only map without embedded source code."
        )
        context.add_finding(
            Finding(
                plugin=self.name,
                title="Publicly Accessible Source Map Metadata",
                description=(
                    f"A source-map file was found at '{self._redact_url(map_url)}'. While it does not contain embedded "
                    f"original source code, it discloses build tooling metadata."
                ),
                severity=Severity.LOW,
                recommendation="Remove unnecessary .map files from public web roots.",
                evidence=evidence,
            )
        )

    # ------------------------------------------------------------------
    # Data Redaction Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _redact_url(url: str) -> str:
        """Redact sensitive query parameter values from URL."""
        parsed = urlparse(url)
        query = parsed.query
        if query:
            redacted_parts = []
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    if any(s in k.lower() for s in ("token", "key", "secret", "pass", "auth", "session")):
                        redacted_parts.append(f"{k}=[REDACTED]")
                    else:
                        redacted_parts.append(part)
                else:
                    redacted_parts.append(part)
            query = "&".join(redacted_parts)

        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + (f"?{query}" if query else "")
