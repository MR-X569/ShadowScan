"""
app/scanner/plugins/passive/security_policy.py
---------------------------------------------
Security Policy & security.txt (RFC 9116) Analysis Plugin.

Discovers and analyzes standard security policy disclosure endpoints:
    1. /.well-known/security.txt and /security.txt (RFC 9116).
    2. Parses Contact, Expires, Encryption, Policy, Acknowledgments, Canonical.
    3. Evaluates expired policies or missing Contact directives.
    4. Extracts security-relevant paths from robots.txt into context.metadata.

Safety & Guardrails:
    - Purely read-only GET requests on same-origin standard paths.
    - NEVER follows external Contact URLs, PGP encryption links, or external canonical URIs.
    - NEVER exposes sensitive personal contact emails inappropriately.
    - Low-noise reporting (missing security.txt is treated as informational/low).
"""

from __future__ import annotations

import datetime
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Standard RFC 9116 paths
_SECURITY_TXT_PATHS: tuple[str, ...] = (
    "/.well-known/security.txt",
    "/security.txt",
)

# High-interest security keywords in robots.txt disallow rules
_SENSITIVE_PATH_KEYWORDS: tuple[str, ...] = (
    "admin",
    "backup",
    "internal",
    "debug",
    "private",
    "api",
    "secret",
    "config",
    "db",
    "dump",
)


class SecurityPolicyPlugin(BasePlugin):
    """
    Evaluates RFC 9116 security.txt policies and security metadata disclosures.
    """

    name = "security_policy"
    description = (
        "Discovers and validates security policy disclosure files (security.txt RFC 9116) "
        "and extracts security-relevant paths from robots.txt."
    )
    category = "passive"
    version = "1.0.0"
    priority = 48

    async def run(self, context: ScanContext) -> None:
        """
        Execute security.txt discovery and policy validation.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping security policy analysis.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # 1. Inspect security.txt
        await self._check_security_txt(client, target_origin, context)

        # 2. Extract and record security paths from robots.txt into metadata
        await self._inspect_robots_txt_paths(client, target_origin, context)

    # ------------------------------------------------------------------
    # RFC 9116 security.txt Verification
    # ------------------------------------------------------------------

    async def _check_security_txt(
        self,
        client: Any,
        target_origin: str,
        context: ScanContext,
    ) -> None:
        """Probe for /.well-known/security.txt and /security.txt."""
        found_policy = False

        for path in _SECURITY_TXT_PATHS:
            sec_url = urljoin(target_origin, path)
            try:
                response = await client.get(sec_url)
                if response.status_code == 200 and response.text:
                    content = response.text.strip()

                    # Validate content has RFC 9116 directive syntax (e.g. Contact:, Expires:)
                    if "contact:" in content.lower() or "expires:" in content.lower():
                        found_policy = True
                        self._analyze_security_txt_content(content, sec_url, context)
                        break
            except Exception as exc:
                self.log(f"Probe on '{sec_url}' failed: {exc}")

        if not found_policy:
            self.log("No valid RFC 9116 security.txt file found on target.")
            context.metadata["has_security_txt"] = False

    def _analyze_security_txt_content(
        self,
        content: str,
        sec_url: str,
        context: ScanContext,
    ) -> None:
        """Parse security.txt directives and evaluate expiration and required fields."""
        context.metadata["has_security_txt"] = True

        directives: dict[str, list[str]] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                k = key.strip().lower()
                v = val.strip()
                directives.setdefault(k, []).append(v)

        context.metadata["security_txt_directives"] = list(directives.keys())

        # Check A: Missing Contact Directive (RFC 9116 mandatory)
        if "contact" not in directives:
            evidence = f"File URL: {sec_url}\nFound Directives: {list(directives.keys())}\nIssue: Missing required 'Contact:' directive."
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="RFC 9116 security.txt Missing Required Contact Directive",
                    description=(
                        f"The security policy file at '{sec_url}' does not define a 'Contact:' directive. "
                        f"RFC 9116 requires at least one Contact field to enable security researchers to report vulnerabilities."
                    ),
                    severity=Severity.LOW,
                    recommendation="Add a valid Contact directive with a security reporting email or web form URL.",
                    evidence=evidence,
                )
            )

        # Check B: Expired Policy (Expires directive in the past)
        if "expires" in directives:
            expires_str = directives["expires"][0]
            try:
                # Parse ISO 8601 / RFC 3339 timestamp (e.g. 2024-01-01T00:00:00.000Z or 2024-01-01)
                exp_clean = expires_str.replace("Z", "+00:00")
                exp_dt = datetime.datetime.fromisoformat(exp_clean)

                now_utc = datetime.datetime.now(datetime.timezone.utc)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)

                if exp_dt < now_utc:
                    evidence = (
                        f"File URL: {sec_url}\n"
                        f"Configured Expiration Date: {expires_str}\n"
                        f"Current UTC Time: {now_utc.isoformat()}\n"
                        f"Evaluation: The security.txt policy has expired."
                    )
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title="RFC 9116 security.txt Policy Expired",
                            description=(
                                f"The security policy file at '{sec_url}' has an 'Expires:' timestamp ({expires_str}) "
                                f"that is in the past. Expired policies may cause security researchers to consider the "
                                f"disclosure program inactive or unmaintained."
                            ),
                            severity=Severity.LOW,
                            recommendation="Update the 'Expires:' field in security.txt with a future renewal date.",
                            evidence=evidence,
                        )
                    )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Robots.txt Security Path Discovery
    # ------------------------------------------------------------------

    async def _inspect_robots_txt_paths(
        self,
        client: Any,
        target_origin: str,
        context: ScanContext,
    ) -> None:
        """Fetch robots.txt and collect security-relevant paths into context metadata."""
        robots_url = urljoin(target_origin, "/robots.txt")
        try:
            resp = await client.get(robots_url)
            if resp.status_code == 200 and resp.text:
                paths: set[str] = set()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        _, path = line.split(":", 1)
                        p = path.strip()
                        if p and any(kw in p.lower() for kw in _SENSITIVE_PATH_KEYWORDS):
                            paths.add(p)

                if paths:
                    context.metadata["security_policy_discovered_paths"] = sorted(paths)
                    self.log(f"Discovered {len(paths)} security-relevant path(s) in robots.txt: {paths}")
        except Exception as exc:
            self.log(f"Robots.txt path inspection failed: {exc}")
