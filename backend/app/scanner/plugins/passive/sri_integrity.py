"""
app/scanner/plugins/passive/sri_integrity.py
-------------------------------------------
Subresource Integrity (SRI) Security Analysis Plugin.

Safely evaluates HTML <script> and <link rel="stylesheet"> subresources for proper
Subresource Integrity (SRI) enforcement, detecting unpinned external CDN scripts,
missing integrity hashes, weak cryptographic digests, and missing crossorigin attributes.

Safety & Guardrails:
    - Purely passive HTML analysis.
    - Accurately differentiates third-party/external CDNs from same-origin resources.
    - Redacts all query parameters and sensitive credentials in findings.
    - Only flags external subresources where SRI is recommended.

Standard Hash Algorithms:
    - sha256, sha384, sha512 (Recommended: sha384 or sha512)

Severity Logic:
    - HIGH: External third-party executable JavaScript script without Subresource Integrity (SRI).
    - MEDIUM: External third-party stylesheet (CSS) without Subresource Integrity (SRI).
    - LOW: Invalid/weak hash algorithm (e.g. md5, sha1), malformed hash, or missing crossorigin attribute.
    - NONE: Valid, cryptographically strong SRI hash with appropriate crossorigin configuration.
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

# Valid standardized SRI cryptographic hash algorithm prefixes
_VALID_SRI_PREFIXES: tuple[str, ...] = ("sha256-", "sha384-", "sha512-")
_WEAK_SRI_PREFIXES: tuple[str, ...] = ("sha1-", "md5-")

# Regex to match script tags with attributes
_SCRIPT_TAG_PATTERN: re.Pattern[str] = re.compile(
    r"""<script\b([^>]*)>""",
    re.IGNORECASE,
)

# Regex to match stylesheet link tags
_STYLESHEET_TAG_PATTERN: re.Pattern[str] = re.compile(
    r"""<link\b([^>]*)>""",
    re.IGNORECASE,
)

# Regex attribute extractors
_SRC_ATTR: re.Pattern[str] = re.compile(r"""\bsrc=["']([^"']+)["']""", re.IGNORECASE)
_HREF_ATTR: re.Pattern[str] = re.compile(r"""\bhref=["']([^"']+)["']""", re.IGNORECASE)
_REL_ATTR: re.Pattern[str] = re.compile(r"""\brel=["']([^"']+)["']""", re.IGNORECASE)
_INTEGRITY_ATTR: re.Pattern[str] = re.compile(r"""\bintegrity=["']([^"']+)["']""", re.IGNORECASE)
_CROSSORIGIN_ATTR: re.Pattern[str] = re.compile(r"""\bcrossorigin(?:=["']([^"']*)["'])?""", re.IGNORECASE)


class SRIIntegrityPlugin(BasePlugin):
    """
    Evaluates external script and stylesheet tags for Subresource Integrity (SRI) attributes.
    """

    name = "sri_integrity"
    description = (
        "Validates Subresource Integrity (SRI) on external scripts and stylesheets, preventing "
        "supply-chain attacks and malicious code injection via compromised third-party CDNs."
    )
    category = "passive"
    version = "1.0.0"
    priority = 21

    async def run(self, context: ScanContext) -> None:
        """
        Scan context.html for external subresources and inspect their integrity attributes.
        """
        if not context.html or not context.target_url:
            self.log("No HTML content or target URL available — skipping SRI analysis.")
            return

        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_host = (parsed_target.hostname or "").lower()

        html_body = context.html

        # 1. Analyze External JavaScript <script> tags
        self._analyze_scripts(html_body, target_url, target_host, context)

        # 2. If no script finding was added, analyze External Stylesheets
        if not context.findings:
            self._analyze_stylesheets(html_body, target_url, target_host, context)

    # ------------------------------------------------------------------
    # Script Analysis
    # ------------------------------------------------------------------

    def _analyze_scripts(
        self,
        html_body: str,
        target_url: str,
        target_host: str,
        context: ScanContext,
    ) -> None:
        """Scan <script> tags for missing or invalid SRI integrity attributes."""
        for match in _SCRIPT_TAG_PATTERN.finditer(html_body):
            attrs = match.group(1)
            src_m = _SRC_ATTR.search(attrs)
            if not src_m:
                continue  # Inline script

            src_val = src_m.group(1).strip()
            if src_val.lower().startswith(("data:", "blob:", "javascript:", "about:")):
                continue

            resolved_url = urljoin(target_url, src_val)
            parsed_src = urlparse(resolved_url)
            src_host = (parsed_src.hostname or "").lower()

            # Only check external third-party origins
            if not src_host or src_host == target_host:
                continue

            integrity_m = _INTEGRITY_ATTR.search(attrs)
            crossorigin_m = _CROSSORIGIN_ATTR.search(attrs)

            if not integrity_m:
                evidence = (
                    f"Page URL: {self._redact_url(target_url)}\n"
                    f"External Script URL: {self._redact_url(resolved_url)}\n"
                    f"CDN Host: {src_host}\n"
                    f"Integrity Attribute: Missing\n"
                    f"Tag Snippet: <script src=\"{self._redact_url(src_val)}\">"
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Missing Subresource Integrity (SRI) on External Script ({src_host})",
                        description=(
                            f"The application loads an external JavaScript library from a third-party origin "
                            f"('{src_host}') without a Subresource Integrity ('integrity') cryptographic hash. "
                            f"If the external CDN or vendor is compromised or subject to DNS hijacking, an attacker can "
                            f"inject malicious code into the script, executing arbitrary JavaScript in the context of all visitors."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            "Add cryptographic hash verification and CORS attributes to external script tags:\n"
                            '<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>'
                        ),
                        evidence=evidence,
                    )
                )
                return  # Report top critical finding

            # Validate integrity hash algorithm
            integrity_val = integrity_m.group(1).strip()
            self._validate_integrity_format(
                "script",
                integrity_val,
                bool(crossorigin_m),
                resolved_url,
                target_url,
                src_host,
                context,
            )
            if context.findings:
                return

    # ------------------------------------------------------------------
    # Stylesheet Analysis
    # ------------------------------------------------------------------

    def _analyze_stylesheets(
        self,
        html_body: str,
        target_url: str,
        target_host: str,
        context: ScanContext,
    ) -> None:
        """Scan <link rel="stylesheet"> tags for missing or invalid SRI attributes."""
        for match in _STYLESHEET_TAG_PATTERN.finditer(html_body):
            attrs = match.group(1)
            rel_m = _REL_ATTR.search(attrs)
            if not rel_m or "stylesheet" not in rel_m.group(1).lower():
                continue

            href_m = _HREF_ATTR.search(attrs)
            if not href_m:
                continue

            href_val = href_m.group(1).strip()
            if href_val.lower().startswith(("data:", "blob:", "about:")):
                continue

            resolved_url = urljoin(target_url, href_val)
            parsed_href = urlparse(resolved_url)
            href_host = (parsed_href.hostname or "").lower()

            # Only check external origins
            if not href_host or href_host == target_host:
                continue

            integrity_m = _INTEGRITY_ATTR.search(attrs)
            crossorigin_m = _CROSSORIGIN_ATTR.search(attrs)

            if not integrity_m:
                evidence = (
                    f"Page URL: {self._redact_url(target_url)}\n"
                    f"External Stylesheet URL: {self._redact_url(resolved_url)}\n"
                    f"CDN Host: {href_host}\n"
                    f"Integrity Attribute: Missing"
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Missing Subresource Integrity (SRI) on External Stylesheet ({href_host})",
                        description=(
                            f"The application loads an external stylesheet from '{href_host}' without an 'integrity' attribute. "
                            f"A compromised third-party host could serve malicious CSS to manipulate page appearance or exfiltrate data."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            "Add an 'integrity' hash and 'crossorigin=\"anonymous\"' to external stylesheet <link> tags."
                        ),
                        evidence=evidence,
                    )
                )
                return

            integrity_val = integrity_m.group(1).strip()
            self._validate_integrity_format(
                "stylesheet",
                integrity_val,
                bool(crossorigin_m),
                resolved_url,
                target_url,
                href_host,
                context,
            )
            if context.findings:
                return

    # ------------------------------------------------------------------
    # Integrity Format Validation
    # ------------------------------------------------------------------

    def _validate_integrity_format(
        self,
        res_type: str,
        integrity_val: str,
        has_crossorigin: bool,
        resolved_url: str,
        target_url: str,
        host: str,
        context: ScanContext,
    ) -> None:
        """Check for weak hash algorithms, malformed digests, or missing crossorigin attributes."""
        hash_tokens = [tok.strip() for tok in integrity_val.split() if tok.strip()]
        if not hash_tokens:
            return

        has_strong_hash = any(any(tok.lower().startswith(vp) for vp in _VALID_SRI_PREFIXES) for tok in hash_tokens)
        has_weak_hash = any(any(tok.lower().startswith(wp) for wp in _WEAK_SRI_PREFIXES) for tok in hash_tokens)

        # Check for exclusively weak algorithms (md5, sha1)
        if has_weak_hash and not has_strong_hash:
            evidence = (
                f"Resource URL: {self._redact_url(resolved_url)}\n"
                f"Integrity Value: {integrity_val}\n"
                f"Issue: Deprecated/weak hash algorithm used."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Weak Cryptographic Hash Algorithm in Subresource Integrity (SRI)",
                    description=(
                        f"The external {res_type} specifies a deprecated or collision-vulnerable hash algorithm "
                        f"('{integrity_val}'). Browsers and security standards require SHA-256, SHA-384, or SHA-512."
                    ),
                    severity=Severity.LOW,
                    recommendation="Use SHA-384 or SHA-512 for SRI hashes (e.g. 'integrity=\"sha384-...\"').",
                    evidence=evidence,
                )
            )
            return

        # Check for unparseable/malformed SHA prefix
        if not has_strong_hash:
            evidence = (
                f"Resource URL: {self._redact_url(resolved_url)}\n"
                f"Integrity Value: {integrity_val}\n"
                f"Issue: Unrecognized or malformed SRI hash format."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Malformed Subresource Integrity (SRI) Attribute Format",
                    description=(
                        f"The {res_type} tag contains a malformed 'integrity' value ('{integrity_val}'). "
                        f"Browsers will fail to validate the hash or reject the subresource."
                    ),
                    severity=Severity.LOW,
                    recommendation="Ensure the integrity attribute adheres to standard SRI format: 'sha384-<base64-hash>'.",
                    evidence=evidence,
                )
            )
            return

        # Check for missing crossorigin attribute on cross-origin SRI resource
        if not has_crossorigin:
            evidence = (
                f"Resource URL: {self._redact_url(resolved_url)}\n"
                f"Integrity Value: {integrity_val}\n"
                f"Missing Attribute: crossorigin=\"anonymous\""
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Missing 'crossorigin' Attribute on Cross-Origin SRI {res_type.capitalize()}",
                    description=(
                        f"The external {res_type} defines an 'integrity' hash but lacks the 'crossorigin' attribute. "
                        f"For security reasons, browsers require cross-origin SRI resources to be requested with CORS "
                        f"('crossorigin=\"anonymous\"'); otherwise, integrity verification is blocked or fails."
                    ),
                    severity=Severity.LOW,
                    recommendation="Add 'crossorigin=\"anonymous\"' to the tag.",
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
