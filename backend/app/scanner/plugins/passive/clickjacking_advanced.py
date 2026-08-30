"""
app/scanner/plugins/passive/clickjacking_advanced.py
---------------------------------------------------
Advanced Clickjacking & Framing Policy Analysis Plugin.

Performs in-depth analysis of anti-framing policies, evaluating Content-Security-Policy
frame-ancestors directives, X-Frame-Options headers, directive conflicts, broad origin
wildcards, and framing protection on sensitive HTML endpoints.

Safety & Guardrails:
    - Purely passive inspection of response headers and content.
    - Accurately distinguishes non-frameable content (APIs, JSON, images, CSS, JS) from HTML documents.
    - Evaluates effective browser precedence rules (CSP frame-ancestors overrides X-Frame-Options).

Detection Checks:
    1. HTML / Document Verification: Filters out JSON, APIs, images, and static assets.
    2. Effective Framing Policy Determination: Evaluates modern CSP frame-ancestors vs legacy XFO.
    3. Conflicting Policies: Flags cases where CSP and XFO contradict each other.
    4. Broad / Ineffective Policies: Detects wildcard frame-ancestors (*, https://*, broad TLD wildcards).
    5. Sensitive Page Framing Risk: Identifies sensitive pages (login forms, inputs, account pages)
       lacking effective anti-framing restrictions.

Severity Logic:
    - HIGH: Clearly frameable sensitive HTML application with no effective framing restriction.
    - MEDIUM: Weak/broad frame-ancestors (* or overly permissive) or ineffective/malformed protection.
    - LOW: Conflicting framing configurations or legacy-only configurations requiring review.
    - NONE: Strong, unambiguous anti-framing policy (DENY, SAMEORIGIN, or restrictive frame-ancestors).
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

# Content types representing frameable HTML documents
_FRAMEABLE_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml+xml",
)

# Content types that are non-frameable and should be excluded from clickjacking alerts
_NON_FRAMEABLE_CONTENT_TYPES: tuple[str, ...] = (
    "application/json",
    "application/xml",
    "text/xml",
    "text/javascript",
    "application/javascript",
    "text/css",
    "image/",
    "font/",
    "audio/",
    "video/",
    "application/pdf",
    "application/octet-stream",
)

# Broad / wildcard patterns in frame-ancestors
_BROAD_ANCESTOR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\*$", re.IGNORECASE),
    re.compile(r"^https?:\/\/\*$", re.IGNORECASE),
    re.compile(r"^https?:$", re.IGNORECASE),
    re.compile(r"^\*\.[a-z]{2,6}$", re.IGNORECASE),
]

# Sensitive HTML indicators (forms, passwords, auth tokens, dashboard inputs)
_SENSITIVE_HTML_INDICATOR: re.Pattern[str] = re.compile(
    r"""(?i)(?:<form[\s>]|<input\s+[^>]*type=["'](?:password|email|text|submit)["']|"""
    r"""<button[\s>]|login|signin|dashboard|account|checkout|creditcard|passcode)"""
)


class ClickjackingAdvancedPlugin(BasePlugin):
    """
    Performs deep framing policy analysis, CSP frame-ancestors evaluation, and conflict detection.
    """

    name = "clickjacking_advanced"
    description = (
        "Performs in-depth framing policy analysis, inspecting CSP frame-ancestors, "
        "X-Frame-Options precedence, policy conflicts, and sensitive HTML page framing exposure."
    )
    category = "passive"
    version = "1.0.0"
    priority = 18

    async def run(self, context: ScanContext) -> None:
        """
        Execute advanced clickjacking analysis against context.headers and context.html.
        """
        if not context.headers:
            self.log("No HTTP headers available — skipping advanced clickjacking analysis.")
            return

        headers = {k.lower(): v for k, v in context.headers.items()}
        content_type_header = headers.get("content-type", "").lower().strip()
        content_type_clean = content_type_header.split(";")[0].strip()

        # 1. Filter out non-frameable resources (APIs, JSON, images, CSS, scripts, binary files)
        if any(content_type_clean.startswith(nft) for nft in _NON_FRAMEABLE_CONTENT_TYPES):
            self.log(f"Content-Type '{content_type_clean}' is non-frameable — skipping clickjacking check.")
            return

        # If content type is explicitly specified and not frameable HTML, skip
        if content_type_clean and not any(content_type_clean.startswith(fct) for fct in _FRAMEABLE_CONTENT_TYPES):
            self.log(f"Content-Type '{content_type_clean}' is not an HTML document — skipping.")
            return

        html_body = context.html or ""

        # 2. Extract CSP frame-ancestors directives
        csp_headers = self._extract_csp_headers(headers)
        frame_ancestors_directives = self._parse_all_frame_ancestors(csp_headers)

        # 3. Extract X-Frame-Options
        xfo_header = headers.get("x-frame-options", "").strip()

        # 4. Evaluate effective browser policy & conflicts
        self._evaluate_framing_security(
            frame_ancestors_directives,
            xfo_header,
            html_body,
            content_type_header,
            context,
        )

    # ------------------------------------------------------------------
    # Policy Evaluation Logic
    # ------------------------------------------------------------------

    def _evaluate_framing_security(
        self,
        frame_ancestors: list[str],
        xfo: str,
        html_body: str,
        content_type: str,
        context: ScanContext,
    ) -> None:
        """Analyze combined framing protections and emit targeted findings."""
        xfo_upper = xfo.upper().strip()
        has_csp_fa = len(frame_ancestors) > 0
        has_strong_xfo = xfo_upper in ("DENY", "SAMEORIGIN")

        # Parse CSP frame-ancestors sources
        all_sources: list[str] = []
        is_wildcard_csp = False
        is_restrictive_csp = False

        for directive in frame_ancestors:
            sources = [s.strip() for s in directive.split() if s.strip()]
            all_sources.extend(sources)

            # Check if directive contains 'none' or 'self' without wildcards
            sources_lower = [s.lower() for s in sources]
            if "'none'" in sources_lower or "'self'" in sources_lower:
                is_restrictive_csp = True

            for s in sources:
                if any(pat.match(s) for pat in _BROAD_ANCESTOR_PATTERNS) or s == "*":
                    is_wildcard_csp = True

        # Check for Conflict: CSP frame-ancestors vs X-Frame-Options
        # Note: In modern browsers, CSP frame-ancestors takes complete precedence over XFO.
        if has_csp_fa and xfo:
            if is_wildcard_csp and has_strong_xfo:
                # Dangerous conflict: XFO says DENY/SAMEORIGIN, but CSP says wildcard!
                evidence = (
                    f"Content-Security-Policy: frame-ancestors {' '.join(all_sources)}\n"
                    f"X-Frame-Options: {xfo}\n"
                    f"Effective Browser Precedence: Modern browsers obey CSP frame-ancestors and IGNORE X-Frame-Options.\n"
                    f"Result: The page remains frameable by any origin despite X-Frame-Options: {xfo}."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Anti-Framing Policy Conflict: Permissive CSP Overrides Restrictive X-Frame-Options",
                        description=(
                            f"The application specifies a restrictive 'X-Frame-Options: {xfo}' header, but also "
                            f"defines a permissive Content-Security-Policy 'frame-ancestors' directive ('{' '.join(all_sources)}'). "
                            f"According to W3C specifications, modern browsers ignore X-Frame-Options when CSP frame-ancestors "
                            f"is present. Because the CSP policy is permissive, the page can be framed, bypassing X-Frame-Options."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            "Align CSP and X-Frame-Options policies. Restrict the CSP frame-ancestors directive to 'self' "
                            "or 'none' to match the intended restrictive framing posture."
                        ),
                        evidence=evidence,
                    )
                )
                return

            if is_restrictive_csp and not has_strong_xfo and xfo_upper != "":
                # Informational / Low conflict: CSP is strong, but XFO is malformed or missing
                evidence = (
                    f"Content-Security-Policy: frame-ancestors {' '.join(all_sources)}\n"
                    f"X-Frame-Options: {xfo}\n"
                    f"Evaluation: Modern browsers are protected via CSP, but legacy browsers without CSP support may ignore '{xfo}'."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Legacy Anti-Framing Conflict: Ineffective X-Frame-Options alongside CSP",
                        description=(
                            f"The page defines a restrictive CSP frame-ancestors policy ('{' '.join(all_sources)}'), but "
                            f"specifies an invalid, deprecated, or contradictory X-Frame-Options header ('{xfo}'). "
                            f"While modern browsers enforce CSP, older user-agents without CSP support remain unprotected."
                        ),
                        severity=Severity.LOW,
                        recommendation="Set 'X-Frame-Options: SAMEORIGIN' or 'DENY' alongside CSP frame-ancestors for legacy compatibility.",
                        evidence=evidence,
                    )
                )
                return

        # Case 1: Broad / Permissive CSP frame-ancestors (without XFO conflict)
        if has_csp_fa and is_wildcard_csp:
            evidence = (
                f"Content-Security-Policy: frame-ancestors {' '.join(all_sources)}\n"
                f"Effective Framing Policy: Permissive wildcard allows arbitrary embedding."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Permissive Anti-Framing Policy: Broad CSP frame-ancestors Wildcard",
                    description=(
                        f"The Content-Security-Policy 'frame-ancestors' directive contains a wildcard or broad origin "
                        f"pattern ('{' '.join(all_sources)}'), allowing third-party origins to embed this application inside iframes."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation="Restrict CSP frame-ancestors to explicit trusted origins, 'self', or 'none'.",
                    evidence=evidence,
                )
            )
            return

        # Case 2: Restrictive CSP or Restrictive XFO is present -> Secure (NONE)
        if has_csp_fa and is_restrictive_csp and not is_wildcard_csp:
            self.log(f"Effective framing protection confirmed via CSP frame-ancestors: {' '.join(all_sources)}")
            return

        if not has_csp_fa and has_strong_xfo:
            self.log(f"Effective framing protection confirmed via X-Frame-Options: {xfo_upper}")
            return

        # Case 3: Ineffective / Malformed XFO alone (e.g. duplicate, ALLOW-FROM, invalid value)
        if not has_csp_fa and xfo:
            if xfo_upper.startswith("ALLOW-FROM") or xfo_upper in ("0", "FALSE", "ALLOW", "NONE"):
                evidence = (
                    f"X-Frame-Options: {xfo}\n"
                    f"Content-Security-Policy frame-ancestors: Not configured\n"
                    f"Issue: Value '{xfo}' is deprecated or non-standard and is ignored by modern web browsers."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Ineffective / Deprecated Anti-Framing Protection Header",
                        description=(
                            f"The X-Frame-Options header is set to '{xfo}', which is not recognized or supported by modern browsers. "
                            f"'ALLOW-FROM' has been deprecated and removed from modern browser engines."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation="Replace deprecated headers with 'Content-Security-Policy: frame-ancestors <sources>'.",
                        evidence=evidence,
                    )
                )
                return

        # Case 4: Completely Unprotected HTML Application
        if not has_csp_fa and not has_strong_xfo:
            is_sensitive_page = bool(_SENSITIVE_HTML_INDICATOR.search(html_body))
            severity = Severity.HIGH if is_sensitive_page else Severity.MEDIUM

            evidence = (
                f"Content-Type: {content_type or 'text/html'}\n"
                f"X-Frame-Options: {xfo or 'Not Set'}\n"
                f"CSP frame-ancestors: Not Set\n"
                f"Page Classification: {'Sensitive Interactive Page (Forms / Credentials / Inputs detected)' if is_sensitive_page else 'General HTML Document'}\n"
                f"Effective Framing Policy: Unrestricted — any external website can embed this page."
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Unrestricted Framing on {'Sensitive ' if is_sensitive_page else ''}HTML Document (Clickjacking Exposure)",
                    description=(
                        f"The HTML document at '{context.target_url}' provides no anti-framing restrictions "
                        f"(no X-Frame-Options header and no CSP frame-ancestors directive). "
                        f"An attacker can load this page inside an opaque or invisible iframe on a malicious website, "
                        f"tricking authenticated users into clicking buttons, altering settings, or submitting unauthorized transactions."
                    ),
                    severity=severity,
                    recommendation=(
                        "Implement anti-framing controls by setting:\n"
                        "1. Content-Security-Policy: frame-ancestors 'self' (or 'none')\n"
                        "2. X-Frame-Options: SAMEORIGIN (or DENY)"
                    ),
                    evidence=evidence,
                )
            )

    # ------------------------------------------------------------------
    # Parsing Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_csp_headers(headers: dict[str, str]) -> list[str]:
        """Extract all CSP response header values."""
        results = []
        for k, v in headers.items():
            if k in ("content-security-policy", "content-security-policy-report-only"):
                results.append(v)
        return results

    @staticmethod
    def _parse_all_frame_ancestors(csp_headers: list[str]) -> list[str]:
        """Collect all frame-ancestors directive argument strings."""
        directives = []
        for header in csp_headers:
            for piece in header.split(";"):
                piece = piece.strip()
                if piece.lower().startswith("frame-ancestors"):
                    args = piece[len("frame-ancestors"):].strip()
                    directives.append(args)
        return directives
