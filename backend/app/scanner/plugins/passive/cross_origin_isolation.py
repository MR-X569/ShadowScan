"""
app/scanner/plugins/passive/cross_origin_isolation.py
----------------------------------------------------
Cross-Origin Isolation (COOP, COEP, CORP) Security Analysis Plugin.

Safely evaluates Cross-Origin Opener Policy (COOP), Cross-Origin Embedder Policy (COEP),
and Cross-Origin Resource Policy (CORP) headers to assess window isolation, Spectre
mitigations, and cross-origin resource leakage protections.

Safety & Guardrails:
    - Purely passive HTTP header inspection.
    - Excludes non-document content types (JSON APIs, images, CSS, JS).
    - Recognizes WHATWG/W3C standard directive tokens.

Standard Values:
    COOP: unsafe-none, same-origin, same-origin-allow-popups
    COEP: unsafe-none, require-corp, credentialless
    CORP: same-origin, same-site, cross-origin

Severity Logic:
    - HIGH: Broken or contradictory isolation policy on a sensitive/authenticated application
            (e.g. COOP same-origin combined with COEP unsafe-none or broken tokens).
    - MEDIUM: Invalid/malformed COOP/COEP/CORP header values.
    - LOW: Missing COOP or COEP isolation headers on interactive HTML applications where
           defense-in-depth against cross-origin attacks (Spectre/XS-Leaks) is recommended.
    - NONE: Valid, internally consistent cross-origin isolation or non-applicable endpoint.
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

# Valid standardized header directive values
_VALID_COOP_VALUES: frozenset[str] = frozenset(
    {"unsafe-none", "same-origin", "same-origin-allow-popups"}
)
_VALID_COEP_VALUES: frozenset[str] = frozenset(
    {"unsafe-none", "require-corp", "credentialless"}
)
_VALID_CORP_VALUES: frozenset[str] = frozenset(
    {"same-origin", "same-site", "cross-origin"}
)

# Content types representing frameable HTML documents
_DOCUMENT_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml+xml",
)

# Sensitive interactive application keywords
_SENSITIVE_APP_INDICATOR: re.Pattern[str] = re.compile(
    r"""(?i)(?:<form[\s>]|<input\s+[^>]*type=["'](?:password|email|text)["']|"""
    r"""login|signin|dashboard|account|checkout|payment|admin|portal)"""
)


class CrossOriginIsolationPlugin(BasePlugin):
    """
    Evaluates COOP, COEP, and CORP response headers for cross-origin isolation and policy consistency.
    """

    name = "cross_origin_isolation"
    description = (
        "Analyzes Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), and "
        "Cross-Origin-Resource-Policy (CORP) headers to assess cross-origin isolation and Spectre defenses."
    )
    category = "passive"
    version = "1.0.0"
    priority = 19

    async def run(self, context: ScanContext) -> None:
        """
        Evaluate COOP, COEP, and CORP headers in context.headers.
        """
        if not context.headers:
            self.log("No HTTP headers available — skipping cross-origin isolation checks.")
            return

        headers = {k.lower(): v for k, v in context.headers.items()}
        content_type = headers.get("content-type", "").lower().split(";")[0].strip()

        # Only evaluate HTML documents or responses without declared content-type
        if content_type and not any(content_type.startswith(ct) for ct in _DOCUMENT_CONTENT_TYPES):
            self.log(f"Content-Type '{content_type}' is not an HTML document — skipping isolation check.")
            return

        coop_raw = headers.get("cross-origin-opener-policy", "").strip()
        coep_raw = headers.get("cross-origin-embedder-policy", "").strip()
        corp_raw = headers.get("cross-origin-resource-policy", "").strip()

        coop_clean = coop_raw.split(";")[0].strip().lower().strip("\"'")
        coep_clean = coep_raw.split(";")[0].strip().lower().strip("\"'")
        corp_clean = corp_raw.split(";")[0].strip().lower().strip("\"'")

        # 1. Check for Invalid or Malformed Policy Values (MEDIUM)
        invalid_headers: list[str] = []
        if coop_clean and coop_clean not in _VALID_COOP_VALUES:
            invalid_headers.append(f"Cross-Origin-Opener-Policy: {coop_raw} (Invalid value)")
        if coep_clean and coep_clean not in _VALID_COEP_VALUES:
            invalid_headers.append(f"Cross-Origin-Embedder-Policy: {coep_raw} (Invalid value)")
        if corp_clean and corp_clean not in _VALID_CORP_VALUES:
            invalid_headers.append(f"Cross-Origin-Resource-Policy: {corp_raw} (Invalid value)")

        if invalid_headers:
            evidence = (
                f"Target URL: {context.target_url}\n"
                f"Invalid Directives Detected:\n" + "\n".join(f" - {h}" for h in invalid_headers)
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Invalid Cross-Origin Isolation Policy Header Value",
                    description=(
                        f"The application specifies non-standard or malformed values in its cross-origin isolation headers. "
                        f"Browsers ignore unrecognized directives, causing isolation policies to fail silently."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Correct the header values to standard W3C specifications:\n"
                        "Cross-Origin-Opener-Policy: same-origin\n"
                        "Cross-Origin-Embedder-Policy: require-corp (or credentialless)"
                    ),
                    evidence=evidence,
                )
            )
            return

        # 2. Check for Contradictory / Broken Isolation Configuration (HIGH)
        # When COOP is same-origin (requesting isolation) but COEP is explicitly unsafe-none
        html_body = context.html or ""
        is_sensitive_page = bool(_SENSITIVE_APP_INDICATOR.search(html_body))

        if coop_clean == "same-origin" and coep_clean == "unsafe-none":
            evidence = (
                f"Target URL: {context.target_url}\n"
                f"Cross-Origin-Opener-Policy: {coop_raw}\n"
                f"Cross-Origin-Embedder-Policy: {coep_raw}\n"
                f"Assessment: Contradictory policy prevents browser cross-origin isolation."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Contradictory Cross-Origin Isolation Configuration (COOP vs COEP Conflict)",
                    description=(
                        f"The application sets 'Cross-Origin-Opener-Policy: same-origin' but pairs it with "
                        f"'Cross-Origin-Embedder-Policy: unsafe-none'. Because COEP is set to unsafe-none, the browser "
                        f"refuses to grant a cross-origin isolated execution environment (window.crossOriginIsolated remains false)."
                    ),
                    severity=Severity.HIGH if is_sensitive_page else Severity.MEDIUM,
                    recommendation="Set 'Cross-Origin-Embedder-Policy: require-corp' or 'credentialless' alongside COOP same-origin.",
                    evidence=evidence,
                )
            )
            return

        # 3. Check for Full Cross-Origin Isolation Status (Secure / NONE)
        is_isolated = coop_clean == "same-origin" and coep_clean in ("require-corp", "credentialless")
        if is_isolated:
            context.set_metadata("cross_origin_isolated", True)
            self.log("Target application is fully configured for browser cross-origin isolation.")
            return

        # 4. Check for Missing Isolation Policies on Sensitive Applications (LOW)
        if is_sensitive_page and not coop_clean and not coep_clean:
            evidence = (
                f"Target URL: {context.target_url}\n"
                f"Cross-Origin-Opener-Policy: Not Set\n"
                f"Cross-Origin-Embedder-Policy: Not Set\n"
                f"Page Classification: Interactive Sensitive Application (Forms/Credentials detected)"
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Missing Cross-Origin Isolation Headers (COOP / COEP)",
                    description=(
                        f"The interactive web application at '{context.target_url}' does not set Cross-Origin-Opener-Policy "
                        f"(COOP) or Cross-Origin-Embedder-Policy (COEP) headers. While not all applications require full isolation, "
                        f"configuring COOP ('same-origin') prevents cross-origin window reference attacks (e.g. window.opener tampering "
                        f"and XS-Leaks) and enables high-precision timer protections against Spectre side-channel attacks."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Implement cross-origin isolation headers for defense-in-depth:\n"
                        "Cross-Origin-Opener-Policy: same-origin\n"
                        "Cross-Origin-Embedder-Policy: require-corp"
                    ),
                    evidence=evidence,
                )
            )
