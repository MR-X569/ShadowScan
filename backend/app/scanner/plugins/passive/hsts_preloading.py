"""
app/scanner/plugins/passive/hsts_preloading.py
---------------------------------------------
HSTS Strict Transport Security & Preload Analysis Plugin.

Safely analyzes the Strict-Transport-Security (HSTS) configuration on HTTPS targets
to evaluate policy strength, directive validity, and eligibility for browser HSTS preloading.

Safety & Guardrails:
    - Passive and read-only inspection.
    - NEVER performs external preload submissions or state-changing actions.
    - Local eligibility assessment only.
    - Safe redirect inspection without aggressive enumeration.

Directives Evaluated:
    - max-age (recommended minimum: 31,536,000 seconds / 1 year)
    - includeSubDomains (protection across all subdomains)
    - preload (browser HSTS preload list eligibility)

Severity Logic:
    - HIGH: HTTPS target has no HSTS header at all.
    - MEDIUM: HSTS header present but max-age is below 31,536,000s, lacks includeSubDomains,
              or contains conflicting/malformed max-age directives.
    - LOW: HSTS has max-age >= 31,536,000s and includeSubDomains, but lacks the 'preload' directive.
    - NONE: Strong HSTS policy with max-age >= 31,536,000s, includeSubDomains, and preload.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Minimum recommended max-age for strong HSTS (1 year in seconds)
_MIN_HSTS_MAX_AGE_SECONDS: int = 31_536_000


class HstsPreloadingPlugin(BasePlugin):
    """
    Evaluates HSTS header strength, directive syntax, and browser preload eligibility.
    """

    name = "hsts_preloading"
    description = (
        "Analyzes HTTP Strict Transport Security (HSTS) configuration, verifying max-age duration, "
        "subdomain coverage, and browser preload list readiness."
    )
    category = "passive"
    version = "1.0.0"
    priority = 14

    async def run(self, context: ScanContext) -> None:
        """
        Execute HSTS and preload analysis against context.target_url and context.headers.
        """
        if not context.target_url:
            self.log("No target URL available — skipping HSTS preloading check.")
            return

        parsed = urlparse(context.target_url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()

        # 1. Skip localhost / private IP hostnames
        if self._is_internal_hostname(hostname):
            self.log(f"Hostname '{hostname}' is internal/private — skipping HSTS check.")
            return

        # 2. If target is plain HTTP, check if it redirects to HTTPS
        if scheme == "http":
            if context.session is not None:
                try:
                    resp = await context.session.get(context.target_url, follow_redirects=False)
                    loc = resp.headers.get("location", "")
                    if resp.status_code in (301, 302, 307, 308) and loc.lower().startswith("https://"):
                        self.log(f"HTTP target redirects to HTTPS ({loc}).")
                except Exception as exc:
                    self.log(f"Failed to check HTTP-to-HTTPS redirect: {exc}")
            return

        # 3. Read Strict-Transport-Security header
        headers = {k.lower(): v for k, v in context.headers.items()}
        hsts_raw = headers.get("strict-transport-security", "").strip()

        # Check for missing HSTS on HTTPS target
        if not hsts_raw:
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description=(
                        f"The HTTPS target '{hostname}' does not provide a Strict-Transport-Security (HSTS) header. "
                        f"Without HSTS, web browsers may connect via unencrypted HTTP on initial visits, "
                        f"leaving users vulnerable to SSL-stripping and Man-In-The-Middle (MITM) attacks."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Implement HSTS on all HTTPS responses by adding the header:\n"
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ),
                    evidence="Strict-Transport-Security header not present in response headers.",
                )
            )
            return

        # 4. Parse and validate HSTS directives
        self._analyze_hsts_directives(hsts_raw, hostname, context)

    # ------------------------------------------------------------------
    # Directive Parsing & Validation
    # ------------------------------------------------------------------

    def _analyze_hsts_directives(
        self,
        hsts_raw: str,
        hostname: str,
        context: ScanContext,
    ) -> None:
        """Parse HSTS tokens and evaluate security posture and preload eligibility."""
        directives = [d.strip() for d in hsts_raw.split(";") if d.strip()]
        max_age_values: list[int] = []
        has_invalid_max_age = False
        has_include_subdomains = False
        has_preload = False

        for directive in directives:
            d_lower = directive.lower()
            if d_lower.startswith("max-age"):
                if "=" in directive:
                    val_str = directive.split("=", 1)[1].strip().strip("\"'")
                    try:
                        val_int = int(val_str)
                        if val_int < 0:
                            has_invalid_max_age = True
                        else:
                            max_age_values.append(val_int)
                    except ValueError:
                        has_invalid_max_age = True
                else:
                    has_invalid_max_age = True

            elif d_lower == "includesubdomains":
                has_include_subdomains = True
            elif d_lower == "preload":
                has_preload = True

        # Check for malformed or conflicting max-age values
        if has_invalid_max_age or len(max_age_values) > 1:
            evidence = (
                f"Hostname: {hostname}\n"
                f"Strict-Transport-Security Header: {hsts_raw}\n"
                f"Issue: {'Duplicate/conflicting max-age directives' if len(max_age_values) > 1 else 'Non-numeric or negative max-age value'}"
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Malformed Strict-Transport-Security (HSTS) Header",
                    description=(
                        f"The HSTS header on '{hostname}' contains malformed, non-numeric, or conflicting max-age directives "
                        f"('{hsts_raw}'). Browsers will ignore invalid HSTS headers, leaving connections unprotected."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Correct the HSTS header syntax. Ensure a single valid integer is specified for max-age: "
                        "'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
                    ),
                    evidence=evidence,
                )
            )
            return

        if not max_age_values:
            evidence = f"Hostname: {hostname}\nStrict-Transport-Security Header: {hsts_raw}"
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Missing max-age Directive in HSTS Header",
                    description=f"The HSTS header '{hsts_raw}' is missing the required 'max-age' directive.",
                    severity=Severity.MEDIUM,
                    recommendation="Specify a valid max-age directive of at least 31536000 seconds.",
                    evidence=evidence,
                )
            )
            return

        max_age = max_age_values[0]

        # Check for insufficient duration (< 1 year)
        if max_age < _MIN_HSTS_MAX_AGE_SECONDS:
            evidence = (
                f"Hostname: {hostname}\n"
                f"Configured max-age: {max_age} seconds\n"
                f"Recommended Minimum: {_MIN_HSTS_MAX_AGE_SECONDS} seconds (1 year)\n"
                f"Full Header: {hsts_raw}"
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Short Strict-Transport-Security (HSTS) max-age Duration",
                    description=(
                        f"The HSTS header on '{hostname}' specifies a max-age of {max_age} seconds, which is less "
                        f"than the recommended minimum of 31,536,000 seconds (1 year). Short HSTS durations fail "
                        f"to protect users who infrequently visit the domain."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        f"Increase the HSTS max-age duration to at least {_MIN_HSTS_MAX_AGE_SECONDS} seconds (1 year) "
                        f"or 63,072,000 seconds (2 years)."
                    ),
                    evidence=evidence,
                )
            )
            return

        # Check for missing includeSubDomains
        if not has_include_subdomains:
            evidence = (
                f"Hostname: {hostname}\n"
                f"Strict-Transport-Security Header: {hsts_raw}\n"
                f"Missing Directive: includeSubDomains"
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="HSTS Header Missing 'includeSubDomains' Directive",
                    description=(
                        f"The HSTS policy on '{hostname}' does not include the 'includeSubDomains' directive. "
                        f"Subdomains of this origin are not enforced to use HTTPS, allowing attackers to perform "
                        f"SSL-stripping attacks on sibling or child subdomains."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Add 'includeSubDomains' to the HSTS header once all subdomains are confirmed to support HTTPS:\n"
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ),
                    evidence=evidence,
                )
            )
            return

        # Check for missing preload directive
        if not has_preload:
            evidence = (
                f"Hostname: {hostname}\n"
                f"Strict-Transport-Security Header: {hsts_raw}\n"
                f"Status: Valid strong HSTS policy, but lacks 'preload' directive for browser preloading."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="HSTS Configuration Not Preload-Ready (Missing 'preload')",
                    description=(
                        f"The domain '{hostname}' has a strong HSTS configuration (max-age >= 1 year with includeSubDomains), "
                        f"but does not include the 'preload' directive. Without 'preload', first-time visitors are still "
                        f"theoretically vulnerable on their very first request before receiving the HSTS policy."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Add the 'preload' directive to the HSTS header and submit the domain to the Chromium HSTS "
                        "Preload list (https://hstspreload.org/) to hard-code HTTPS enforcement into major browsers."
                    ),
                    evidence=evidence,
                )
            )
            return

        # If all criteria are met (max-age >= 1 yr, includeSubDomains, preload)
        context.set_metadata("hsts_preload_ready", True)
        self.log(f"Hostname '{hostname}' has optimal HSTS configuration eligible for browser preloading.")

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _is_internal_hostname(hostname: str) -> bool:
        """Check if hostname is localhost or private/internal."""
        hostname_lower = hostname.lower().strip()
        if hostname_lower in ("localhost", "127.0.0.1", "::1"):
            return True
        if hostname_lower.endswith((".local", ".internal", ".localhost", ".test", ".example", ".invalid")):
            return True
        try:
            ip = ipaddress.ip_address(hostname_lower)
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        except ValueError:
            return False
