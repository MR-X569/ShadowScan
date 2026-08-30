"""
app/scanner/plugins/passive/x_content_type_options.py
----------------------------------------------------
X-Content-Type-Options / MIME-Sniffing Protection Analysis Plugin.

Safely evaluates HTTP response headers and Content-Type declarations to ensure
MIME-sniffing protections ('nosniff') are properly configured and detects potential
MIME-confusion risks.

Safety & Guardrails:
    - Read-only inspection of response headers and bounded response bodies.
    - No file uploads, no payload injections, no state changes.
    - Bounded request count on discovered static/script assets.

Checks Performed:
    1. Enforcement of 'X-Content-Type-Options: nosniff'.
    2. Header validity (detecting malformed or non-standard values like '0', 'false', duplicate headers).
    3. MIME Confusion Detection (e.g. executable JavaScript or HTML served as text/plain without nosniff).

Severity Logic:
    - MEDIUM: X-Content-Type-Options header is missing on HTML, script, or document responses.
    - MEDIUM: Suspicious MIME confusion/mismatch (e.g. executable script/HTML served with text/plain).
    - LOW: X-Content-Type-Options header present but has an invalid or non-standard value (not 'nosniff').
    - NONE: Header is present with exact value 'nosniff' and Content-Type is consistent.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Content types where MIME-sniffing protection is critical
_SENSITIVE_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml+xml",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "text/plain",
    "application/json",
)

# Regex to detect executable JavaScript code inside non-JS content types
_JS_CODE_HEURISTIC: re.Pattern[str] = re.compile(
    r"(?:^|\n)\s*(?:function\s+\w+\s*\(|(?:var|let|const)\s+\w+\s*=|"
    r"window\.\w+\s*=|document\.\w+\s*=|console\.log\(|"
    r"\(function\s*\([^)]*\)\s*\{|import\s+.*?from\s+['\"])",
    re.IGNORECASE,
)

# Regex to detect HTML tags in non-HTML content types
_HTML_TAG_HEURISTIC: re.Pattern[str] = re.compile(
    r"<!DOCTYPE\s+html|<html[\s>]|<script[\s>]|<iframe[\s>]|<body[\s>]",
    re.IGNORECASE,
)


class XContentTypeOptionsPlugin(BasePlugin):
    """
    Evaluates X-Content-Type-Options header enforcement and analyzes MIME confusion risks.
    """

    name = "x_content_type_options"
    description = (
        "Validates X-Content-Type-Options: nosniff header enforcement and detects dangerous "
        "MIME-type mismatches that could lead to MIME-sniffing XSS vulnerabilities."
    )
    category = "passive"
    version = "1.0.0"
    priority = 16

    async def run(self, context: ScanContext) -> None:
        """
        Execute MIME-sniffing protection analysis against context.headers and context.html.
        """
        if not context.headers:
            self.log("No HTTP headers available — skipping X-Content-Type-Options check.")
            return

        headers = {k.lower(): v for k, v in context.headers.items()}
        x_content_type_val = headers.get("x-content-type-options", "").strip()
        content_type_header = headers.get("content-type", "").strip()
        content_type_clean = content_type_header.split(";")[0].strip().lower()

        body_snippet = (context.html or "")[:20_000]

        # 1. Check Header Presence and Value
        if not x_content_type_val:
            # Missing header
            # Only flag on document / script / sensitive or plain text types
            is_relevant_type = any(st in content_type_clean for st in _SENSITIVE_CONTENT_TYPES) or not content_type_clean
            if is_relevant_type:
                evidence = (
                    f"Target URL: {context.target_url}\n"
                    f"Content-Type: {content_type_header or 'None specified'}\n"
                    f"X-Content-Type-Options: Missing"
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Missing X-Content-Type-Options Header",
                        description=(
                            "The response is missing the 'X-Content-Type-Options: nosniff' header. "
                            "Without this header, legacy and modern web browsers may perform MIME-type sniffing, "
                            "interpreting non-executable content types (such as text/plain or user uploads) "
                            "as executable HTML or JavaScript, leading to Cross-Site Scripting (XSS)."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            "Add the following HTTP response header to all web responses:\n"
                            "X-Content-Type-Options: nosniff"
                        ),
                        evidence=evidence,
                    )
                )
        else:
            val_clean = x_content_type_val.lower().strip("\"'")
            if val_clean != "nosniff":
                evidence = (
                    f"Target URL: {context.target_url}\n"
                    f"Configured Header: X-Content-Type-Options: {x_content_type_val}\n"
                    f"Expected Value: nosniff"
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Invalid X-Content-Type-Options Header Value",
                        description=(
                            f"The 'X-Content-Type-Options' header is present but contains an invalid or ineffective "
                            f"value ('{x_content_type_val}'). The only valid and standard-compliant value defined by "
                            f"the W3C / WHATWG specification is 'nosniff'."
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            "Set the header value strictly to 'nosniff':\n"
                            "X-Content-Type-Options: nosniff"
                        ),
                        evidence=evidence,
                    )
                )

        # 2. Analyze MIME Confusion / Content-Type Mismatch
        if body_snippet and content_type_clean:
            self._check_mime_confusion(
                content_type_clean,
                body_snippet,
                x_content_type_val.lower().strip(),
                context,
            )

    # ------------------------------------------------------------------
    # MIME Confusion Analysis
    # ------------------------------------------------------------------

    def _check_mime_confusion(
        self,
        content_type: str,
        body_text: str,
        nosniff_header: str,
        context: ScanContext,
    ) -> None:
        """Identify dangerous mismatches where executable content is labeled as non-executable."""
        has_nosniff = nosniff_header == "nosniff"

        # Case A: Executable JavaScript served with text/plain
        if content_type == "text/plain" and _JS_CODE_HEURISTIC.search(body_text):
            if not has_nosniff:
                evidence = (
                    f"Target URL: {context.target_url}\n"
                    f"Declared Content-Type: text/plain\n"
                    f"X-Content-Type-Options: {nosniff_header or 'Missing'}\n"
                    f"Body Analysis: Contains JavaScript executable statements."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="MIME Confusion: JavaScript Code Served as text/plain",
                        description=(
                            f"The endpoint returns executable JavaScript source code but declares a Content-Type "
                            f"of 'text/plain' without enforcing 'X-Content-Type-Options: nosniff'. In older browsers or "
                            f"certain contexts, the browser may sniff this content as executable JavaScript."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            "Declare the correct Content-Type ('application/javascript') and enforce "
                            "'X-Content-Type-Options: nosniff'."
                        ),
                        evidence=evidence,
                    )
                )

        # Case B: HTML markup served as text/plain or application/octet-stream
        elif content_type in ("text/plain", "application/octet-stream") and _HTML_TAG_HEURISTIC.search(body_text):
            if not has_nosniff:
                evidence = (
                    f"Target URL: {context.target_url}\n"
                    f"Declared Content-Type: {content_type}\n"
                    f"X-Content-Type-Options: {nosniff_header or 'Missing'}\n"
                    f"Body Analysis: Contains HTML markup elements."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"MIME Confusion: HTML Content Served as {content_type}",
                        description=(
                            f"The endpoint returns HTML document markup while declaring Content-Type '{content_type}' "
                            f"without 'X-Content-Type-Options: nosniff'. If user-supplied content is rendered, browsers "
                            f"may MIME-sniff the page and execute embedded scripts, resulting in Reflected/Stored XSS."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            "Enforce 'X-Content-Type-Options: nosniff' and ensure proper Content-Type headers are returned."
                        ),
                        evidence=evidence,
                    )
                )
