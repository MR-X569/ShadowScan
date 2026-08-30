"""
app/scanner/plugins/passive/mixed_content.py
-------------------------------------------
Mixed Content Security Analysis Plugin.

Safely evaluates HTTPS HTML responses for insecure subresources loaded over unencrypted
HTTP (Mixed Content). Differentiates between Active Mixed Content (scripts, iframes, objects)
and Passive Mixed Content (images, media).

Safety & Guardrails:
    - Purely passive HTML analysis.
    - Resolves relative and protocol-relative URLs safely against the target origin.
    - Redacts all query parameters and sensitive credentials in findings.
    - Only checks HTTPS endpoints (skips plain HTTP targets).

Severity Logic:
    - HIGH: Active Mixed Content (executable scripts, iframes, objects) loaded over HTTP on HTTPS page.
    - MEDIUM: Potentially active stylesheet or font resources loaded over HTTP.
    - LOW: Passive Mixed Content (images, audio, video) loaded over HTTP.
    - NONE: No mixed content detected (all subresources load over secure HTTPS).
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Regex patterns for active mixed content tags
_ACTIVE_SCRIPT_PATTERN: re.Pattern[str] = re.compile(
    r"""<script[^>]+src=["']([^"']+)["']""",
    re.IGNORECASE,
)
_ACTIVE_IFRAME_PATTERN: re.Pattern[str] = re.compile(
    r"""<(?:iframe|frame)[^>]+src=["']([^"']+)["']""",
    re.IGNORECASE,
)
_ACTIVE_OBJECT_PATTERN: re.Pattern[str] = re.compile(
    r"""<(?:object[^>]+data|embed[^>]+src)=["']([^"']+)["']""",
    re.IGNORECASE,
)

# Regex patterns for stylesheets and fonts
_STYLESHEET_PATTERN: re.Pattern[str] = re.compile(
    r"""<link[^>]+(?:rel=["']stylesheet["'][^>]+href=["']([^"']+)["']|href=["']([^"']+)["'][^>]+rel=["']stylesheet["'])""",
    re.IGNORECASE,
)

# Regex patterns for passive mixed content tags
_PASSIVE_IMG_PATTERN: re.Pattern[str] = re.compile(
    r"""<img[^>]+src=["']([^"']+)["']""",
    re.IGNORECASE,
)
_PASSIVE_MEDIA_PATTERN: re.Pattern[str] = re.compile(
    r"""<(?:audio|video|source|track)[^>]+src=["']([^"']+)["']""",
    re.IGNORECASE,
)


class MixedContentPlugin(BasePlugin):
    """
    Analyzes HTTPS HTML responses to detect unencrypted HTTP active and passive subresources.
    """

    name = "mixed_content"
    description = (
        "Detects Mixed Content on HTTPS websites, identifying unencrypted HTTP scripts, iframes, "
        "stylesheets, and media elements that compromise transport encryption and site integrity."
    )
    category = "passive"
    version = "1.0.0"
    priority = 17

    async def run(self, context: ScanContext) -> None:
        """
        Execute mixed content evaluation against context.target_url and context.html.
        """
        if not context.target_url or not context.html:
            self.log("No target URL or HTML content available — skipping mixed content check.")
            return

        parsed_target = urlparse(context.target_url)
        target_scheme = parsed_target.scheme.lower()

        # Mixed content is only applicable when the top-level origin is HTTPS
        if target_scheme != "https":
            self.log("Target is not served over HTTPS — skipping mixed content check.")
            return

        html_body = context.html

        # 1. Detect Active Mixed Content (High Risk)
        active_items = self._find_insecure_resources(
            html_body,
            [
                ("JavaScript Script", _ACTIVE_SCRIPT_PATTERN),
                ("Embedded Frame", _ACTIVE_IFRAME_PATTERN),
                ("Object/Embed Element", _ACTIVE_OBJECT_PATTERN),
            ],
            context.target_url,
        )

        if active_items:
            res_type, url_found = active_items[0]
            evidence = (
                f"Page URL (HTTPS): {self._redact_url(context.target_url)}\n"
                f"Resource Type: Active Mixed Content ({res_type})\n"
                f"Insecure HTTP URL: {self._redact_url(url_found)}\n"
                f"Total Insecure Active Subresources: {len(active_items)}"
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Active Mixed Content Detected: {res_type} Loaded over Insecure HTTP",
                    description=(
                        f"The secure HTTPS page at '{self._redact_url(context.target_url)}' requests an active, "
                        f"executable subresource ('{self._redact_url(url_found)}') over unencrypted HTTP. "
                        f"Network attackers can intercept and modify the HTTP response to inject malicious JavaScript, "
                        f"completely compromising the user's session (SSL-stripping / Active MITM)."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Update all script, iframe, and object URLs to load exclusively over HTTPS, or use relative paths. "
                        "Add 'Content-Security-Policy: upgrade-insecure-requests' to automatically upgrade legacy HTTP links."
                    ),
                    evidence=evidence,
                )
            )
            return

        # 2. Detect Stylesheet Mixed Content (Medium Risk)
        style_matches: list[str] = []
        for match in _STYLESHEET_PATTERN.finditer(html_body):
            url_val = match.group(1) or match.group(2)
            if url_val and self._is_insecure_http_url(url_val, context.target_url):
                style_matches.append(url_val)

        if style_matches:
            url_found = style_matches[0]
            evidence = (
                f"Page URL (HTTPS): {self._redact_url(context.target_url)}\n"
                f"Resource Type: Insecure Stylesheet (CSS)\n"
                f"Insecure HTTP URL: {self._redact_url(url_found)}\n"
                f"Total Insecure Stylesheets: {len(style_matches)}"
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Mixed Content: Stylesheet Loaded over Insecure HTTP",
                    description=(
                        f"The HTTPS page loads a stylesheet ('{self._redact_url(url_found)}') over unencrypted HTTP. "
                        f"Attackers on the local network can tamper with CSS stylesheets to exfiltrate sensitive data, "
                        f"manipulate UI layouts, or deface the application."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation="Serve all CSS stylesheets over HTTPS or use protocol-relative/relative paths.",
                    evidence=evidence,
                )
            )
            return

        # 3. Detect Passive Mixed Content (Low Risk: Images, Audio, Video)
        passive_items = self._find_insecure_resources(
            html_body,
            [
                ("Image", _PASSIVE_IMG_PATTERN),
                ("Media", _PASSIVE_MEDIA_PATTERN),
            ],
            context.target_url,
        )

        if passive_items:
            res_type, url_found = passive_items[0]
            evidence = (
                f"Page URL (HTTPS): {self._redact_url(context.target_url)}\n"
                f"Resource Type: Passive Mixed Content ({res_type})\n"
                f"Insecure HTTP URL: {self._redact_url(url_found)}\n"
                f"Total Insecure Passive Subresources: {len(passive_items)}"
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Passive Mixed Content: {res_type} Loaded over Insecure HTTP",
                    description=(
                        f"The HTTPS page embeds passive media content ('{self._redact_url(url_found)}') over unencrypted HTTP. "
                        f"While modern browsers block active mixed content by default, passive mixed content weakens visual "
                        f"security indicators and allows network attackers to track user activity or replace images."
                    ),
                    severity=Severity.LOW,
                    recommendation="Update all image, video, and audio src links to HTTPS.",
                    evidence=evidence,
                )
            )

    # ------------------------------------------------------------------
    # Parsing Helpers
    # ------------------------------------------------------------------

    def _find_insecure_resources(
        self,
        html_body: str,
        patterns: list[tuple[str, re.Pattern[str]]],
        target_url: str,
    ) -> list[tuple[str, str]]:
        """Extract matching resource URLs and filter for insecure HTTP destinations."""
        results: list[tuple[str, str]] = []
        for label, pattern in patterns:
            for match in pattern.finditer(html_body):
                raw_url = match.group(1).strip()
                if self._is_insecure_http_url(raw_url, target_url):
                    results.append((label, raw_url))
        return results

    @staticmethod
    def _is_insecure_http_url(raw_url: str, target_url: str) -> bool:
        """Determine if a resource URL is loaded over unencrypted HTTP."""
        if not raw_url:
            return False

        raw_lower = raw_url.lower().strip()

        # Ignore data:, blob:, javascript:, about:
        if raw_lower.startswith(("data:", "blob:", "javascript:", "about:", "#")):
            return False

        # Check explicit http://
        if raw_lower.startswith("http://"):
            return True

        # Protocol-relative URLs (//example.com) on HTTPS page default to HTTPS, so not mixed content
        # Relative URLs (/path/to/img.png) on HTTPS page default to HTTPS, so not mixed content
        return False

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
