"""
app/scanner/plugins/passive/headers.py
---------------------------------------
Security Headers Plugin — checks HTTP response headers for missing or
misconfigured security directives.

Checks performed:
    - Content-Security-Policy       (missing → HIGH)
    - Strict-Transport-Security     (missing → HIGH; weak max-age → MEDIUM)
    - X-Frame-Options               (missing → MEDIUM)
    - X-Content-Type-Options        (missing or not 'nosniff' → MEDIUM)
    - Referrer-Policy               (missing → LOW)
    - Permissions-Policy            (missing → LOW)

This plugin requires no additional HTTP requests — it inspects the headers
already captured by the engine in ``ScanContext.headers``.
"""

from __future__ import annotations

import logging

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Minimum acceptable HSTS max-age: 1 year in seconds (OWASP recommendation).
_MIN_HSTS_MAX_AGE: int = 31_536_000


class SecurityHeadersPlugin(BasePlugin):
    """
    Inspects HTTP response headers for missing or misconfigured security
    directives.

    Runs early (priority=10) because it requires no extra network calls —
    the engine already populated ``context.headers`` during the initial fetch.
    """

    name = "security_headers"
    description = (
        "Checks for missing or misconfigured HTTP security response headers"
    )
    category = "passive"
    version = "1.0.0"
    priority = 10

    async def run(self, context: ScanContext) -> None:
        """
        Evaluate each security header against best-practice expectations.

        Args:
            context: Shared scan context. Reads ``context.headers``.
                     Writes findings via ``context.add_finding()``.
        """
        if not context.headers:
            self.log(
                "No headers available in context — skipping header checks.",
                logging.WARNING,
            )
            return

        # Normalise header names to lower-case for case-insensitive lookup.
        headers = {k.lower(): v for k, v in context.headers.items()}

        self._check_csp(headers, context)
        self._check_hsts(headers, context)
        self._check_x_frame_options(headers, context)
        self._check_x_content_type_options(headers, context)
        self._check_referrer_policy(headers, context)
        self._check_permissions_policy(headers, context)

        # Record which headers were inspected for downstream plugins / reports.
        context.set_metadata(
            "headers_checked",
            [
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            ],
        )

        self.log(
            f"Header inspection complete — "
            f"{len(context.findings)} finding(s) so far."
        )

    # ------------------------------------------------------------------
    # Individual header checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_csp(
        headers: dict[str, str],
        context: ScanContext,
    ) -> None:
        """Content-Security-Policy — prevents XSS and data-injection attacks."""
        if "content-security-policy" not in headers:
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Missing Content-Security-Policy Header",
                    description=(
                        "The Content-Security-Policy (CSP) header was not "
                        "found in the HTTP response. CSP is the primary "
                        "defence against Cross-Site Scripting (XSS) attacks "
                        "by restricting which resources the browser is allowed "
                        "to load."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Add a Content-Security-Policy header with a strict "
                        "policy. At minimum: "
                        "\"Content-Security-Policy: default-src 'self'\". "
                        "Refine the policy to allow only trusted sources for "
                        "scripts, styles, images, and fonts."
                    ),
                    evidence="Header 'Content-Security-Policy' not present in response.",
                )
            )

    @staticmethod
    def _check_hsts(
        headers: dict[str, str],
        context: ScanContext,
    ) -> None:
        """Strict-Transport-Security — enforces HTTPS connections."""
        hsts_value = headers.get("strict-transport-security", "")

        if not hsts_value:
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Missing Strict-Transport-Security Header",
                    description=(
                        "The Strict-Transport-Security (HSTS) header was not "
                        "found. Without HSTS, browsers may make initial "
                        "connections over HTTP, exposing users to SSL-stripping "
                        "attacks and man-in-the-middle interception."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Add the HSTS header with a minimum max-age of "
                        "31536000 (1 year) and include subdomains: "
                        "\"Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload\"."
                    ),
                    evidence="Header 'Strict-Transport-Security' not present in response.",
                )
            )
            return

        # Header is present — validate max-age value.
        max_age: int | None = None
        for directive in hsts_value.split(";"):
            directive = directive.strip()
            if directive.lower().startswith("max-age="):
                try:
                    max_age = int(directive.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    pass
                break

        if max_age is not None and max_age < _MIN_HSTS_MAX_AGE:
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Weak Strict-Transport-Security max-age",
                    description=(
                        f"The HSTS header is present but the max-age directive "
                        f"({max_age} seconds) is below the recommended minimum "
                        f"of {_MIN_HSTS_MAX_AGE:,} seconds (1 year). A short "
                        f"max-age weakens HSTS protection."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        f"Increase the HSTS max-age to at least "
                        f"{_MIN_HSTS_MAX_AGE:,} seconds (1 year)."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                )
            )

    @staticmethod
    def _check_x_frame_options(
        headers: dict[str, str],
        context: ScanContext,
    ) -> None:
        """X-Frame-Options — prevents clickjacking attacks."""
        if "x-frame-options" not in headers:
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Missing X-Frame-Options Header",
                    description=(
                        "The X-Frame-Options header was not found. Without "
                        "this header, the page can be embedded in an "
                        "<iframe>, making it vulnerable to clickjacking attacks "
                        "that trick users into performing unintended actions."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Add 'X-Frame-Options: DENY' to prevent all framing, "
                        "or 'SAMEORIGIN' to allow framing only from the same "
                        "origin. Alternatively, use the Content-Security-Policy "
                        "'frame-ancestors' directive."
                    ),
                    evidence="Header 'X-Frame-Options' not present in response.",
                )
            )

    @staticmethod
    def _check_x_content_type_options(
        headers: dict[str, str],
        context: ScanContext,
    ) -> None:
        """X-Content-Type-Options — prevents MIME-type sniffing."""
        value = headers.get("x-content-type-options", "").strip().lower()

        if not value:
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Missing X-Content-Type-Options Header",
                    description=(
                        "The X-Content-Type-Options header was not found. "
                        "Without this header, browsers may MIME-sniff the "
                        "content type of a response, potentially allowing "
                        "malicious scripts to be interpreted as executable code."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Add 'X-Content-Type-Options: nosniff' to all "
                        "responses to prevent browsers from MIME-sniffing."
                    ),
                    evidence="Header 'X-Content-Type-Options' not present in response.",
                )
            )
        elif value != "nosniff":
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Invalid X-Content-Type-Options Value",
                    description=(
                        "The X-Content-Type-Options header is present but has "
                        f"an unexpected value: '{value}'. The only valid and "
                        "effective value is 'nosniff'."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Set X-Content-Type-Options to exactly 'nosniff'."
                    ),
                    evidence=f"X-Content-Type-Options: {value}",
                )
            )

    @staticmethod
    def _check_referrer_policy(
        headers: dict[str, str],
        context: ScanContext,
    ) -> None:
        """Referrer-Policy — controls referrer information leakage."""
        if "referrer-policy" not in headers:
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Missing Referrer-Policy Header",
                    description=(
                        "The Referrer-Policy header was not found. Without "
                        "this header, the browser may send the full URL of "
                        "the current page as the 'Referer' header on all "
                        "outgoing requests, potentially leaking sensitive "
                        "URL parameters or internal paths."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Add a Referrer-Policy header. Recommended values: "
                        "'no-referrer', 'strict-origin', or "
                        "'strict-origin-when-cross-origin'."
                    ),
                    evidence="Header 'Referrer-Policy' not present in response.",
                )
            )

    @staticmethod
    def _check_permissions_policy(
        headers: dict[str, str],
        context: ScanContext,
    ) -> None:
        """Permissions-Policy — restricts access to browser features."""
        if "permissions-policy" not in headers:
            context.add_finding(
                Finding(
                    plugin="security_headers",
                    title="Missing Permissions-Policy Header",
                    description=(
                        "The Permissions-Policy header (formerly "
                        "Feature-Policy) was not found. This header allows "
                        "the site to control which browser features and APIs "
                        "can be used. Without it, third-party scripts and "
                        "iframes may be able to access sensitive features "
                        "such as geolocation, camera, or microphone."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Add a Permissions-Policy header to explicitly "
                        "restrict access to browser features not required "
                        "by your application. Example: "
                        "'Permissions-Policy: geolocation=(), "
                        "camera=(), microphone=()'."
                    ),
                    evidence="Header 'Permissions-Policy' not present in response.",
                )
            )
