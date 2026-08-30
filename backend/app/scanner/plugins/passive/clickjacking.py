"""
app/scanner/plugins/passive/clickjacking.py
-------------------------------------------
Clickjacking & UI Redressing Analysis Plugin.

Evaluates HTTP response headers for proper anti-framing protections:
    1. X-Frame-Options header (DENY, SAMEORIGIN).
    2. Content-Security-Policy: frame-ancestors directive ('none', 'self', trusted origins).

Security Evaluation:
    - Valid X-Frame-Options (DENY/SAMEORIGIN) or CSP frame-ancestors ('none'/'self') -> Strong Protection (No finding).
    - Missing both X-Frame-Options and CSP frame-ancestors -> MEDIUM Severity finding.
    - Weak / Wildcard CSP frame-ancestors (e.g. frame-ancestors *) -> MEDIUM Severity finding.
    - Deprecated or Invalid X-Frame-Options (e.g. ALLOW-FROM or malformed values) -> LOW Severity finding.

Priority: 12 (runs early alongside header inspections).
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


class ClickjackingPlugin(BasePlugin):
    """
    Evaluates HTTP response headers for Clickjacking / UI Redressing protections.
    """

    name = "clickjacking"
    description = (
        "Detects missing or weak anti-framing protections (X-Frame-Options and CSP frame-ancestors) "
        "to prevent Clickjacking and UI Redressing attacks."
    )
    category = "passive"
    version = "1.0.0"
    priority = 12

    async def run(self, context: ScanContext) -> None:
        """
        Evaluate headers in context.headers for anti-framing directives.
        """
        headers = context.headers
        if not headers:
            self.log("No HTTP headers available in context — skipping clickjacking analysis.")
            return

        # Normalize headers to lowercase keys
        headers_lower = {k.lower(): v for k, v in headers.items()}

        xfo_value = headers_lower.get("x-frame-options", "").strip()
        csp_values = self._extract_csp_headers(headers_lower)

        # 1. Parse CSP frame-ancestors directive
        has_frame_ancestors, frame_ancestors_val, is_csp_wildcard = self._parse_frame_ancestors(csp_values)

        # 2. Parse X-Frame-Options
        has_strong_xfo, is_deprecated_xfo, is_invalid_xfo = self._evaluate_xfo(xfo_value)

        # 3. Decision Logic
        # If CSP frame-ancestors is strong ('none', 'self', or specific origin list), framing is fully prevented
        if has_frame_ancestors and not is_csp_wildcard:
            self.log(f"Strong CSP frame-ancestors protection detected: {frame_ancestors_val}")
            return

        # If X-Frame-Options is strong (DENY, SAMEORIGIN) and no conflicting wildcard CSP
        if has_strong_xfo and not is_csp_wildcard:
            self.log(f"Strong X-Frame-Options protection detected: {xfo_value}")
            return

        # Case A: Wildcard CSP frame-ancestors (* or http:)
        if is_csp_wildcard:
            evidence = (
                f"Content-Security-Policy: {frame_ancestors_val}\n"
                f"X-Frame-Options: {xfo_value or 'Not Set'}\n"
                f"Evaluation: Wildcard frame-ancestors directive explicitly permits framing from any origin."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Weak Anti-Framing Protection: CSP frame-ancestors Wildcard",
                    description=(
                        "The application's Content-Security-Policy includes a wildcard frame-ancestors directive (*), "
                        "allowing any external domain to embed this application inside an <iframe>. "
                        "This leaves users vulnerable to Clickjacking and UI Redressing attacks."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Restrict the CSP frame-ancestors directive to 'none' or 'self' (e.g. "
                        "Content-Security-Policy: frame-ancestors 'self')."
                    ),
                    evidence=evidence,
                )
            )
            return

        # Case B: Completely Missing Both Protections
        if not has_strong_xfo and not has_frame_ancestors:
            if is_deprecated_xfo or is_invalid_xfo:
                evidence = (
                    f"X-Frame-Options: {xfo_value}\n"
                    f"Content-Security-Policy frame-ancestors: None\n"
                    f"Evaluation: '{xfo_value}' is invalid or deprecated (ALLOW-FROM is no longer supported in modern browsers)."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Invalid or Deprecated X-Frame-Options Header",
                        description=(
                            f"The X-Frame-Options header is set to '{xfo_value}', which is either invalid or deprecated. "
                            f"Modern browsers ignore invalid XFO headers and 'ALLOW-FROM', rendering anti-framing protection ineffective."
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            "Replace deprecated or invalid X-Frame-Options headers with 'X-Frame-Options: SAMEORIGIN' "
                            "or modern CSP directive 'Content-Security-Policy: frame-ancestors 'self''."
                        ),
                        evidence=evidence,
                    )
                )
                return

            evidence = (
                "X-Frame-Options: Not Set\n"
                "Content-Security-Policy frame-ancestors: Not Set\n"
                "Evaluation: Target page contains no framing restrictions and can be embedded in arbitrary iframes."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Missing Anti-Framing Protection (Clickjacking / UI Redressing Risk)",
                    description=(
                        "The target page does not define an 'X-Frame-Options' header or a Content-Security-Policy "
                        "'frame-ancestors' directive. An attacker can embed the target application in an invisible <iframe> "
                        "on an attacker-controlled website to deceive users into clicking buttons or executing unintended actions (Clickjacking)."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Implement anti-framing controls by adding 'X-Frame-Options: SAMEORIGIN' (or DENY) "
                        "and modern CSP: 'Content-Security-Policy: frame-ancestors 'self''. "
                        "For sensitive authenticated or transaction pages, consider 'frame-ancestors 'none''."
                    ),
                    evidence=evidence,
                )
            )

    # ------------------------------------------------------------------
    # Parsing Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_csp_headers(headers_lower: dict[str, str]) -> list[str]:
        """Collect all CSP header directives across possible headers."""
        csp_list = []
        for k, v in headers_lower.items():
            if k in ("content-security-policy", "content-security-policy-report-only"):
                csp_list.append(v)
        return csp_list

    @staticmethod
    def _parse_frame_ancestors(csp_headers: list[str]) -> tuple[bool, str, bool]:
        """
        Parses CSP headers for frame-ancestors directive.
        Returns: (has_frame_ancestors, directive_value, is_wildcard)
        """
        for csp in csp_headers:
            directives = [d.strip() for d in csp.split(";")]
            for directive in directives:
                if directive.lower().startswith("frame-ancestors"):
                    val = directive[len("frame-ancestors"):].strip()
                    val_lower = val.lower()
                    is_wildcard = "*" in val_lower or val_lower == "http:" or val_lower == "https:"
                    return True, directive, is_wildcard
        return False, "", False

    @staticmethod
    def _evaluate_xfo(xfo_value: str) -> tuple[bool, bool, bool]:
        """
        Evaluates X-Frame-Options value.
        Returns: (is_strong, is_deprecated, is_invalid)
        """
        if not xfo_value:
            return False, False, False

        val_upper = xfo_value.upper().strip()

        if val_upper in ("DENY", "SAMEORIGIN"):
            return True, False, False

        if val_upper.startswith("ALLOW-FROM"):
            return False, True, False

        return False, False, True
