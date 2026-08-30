"""
app/scanner/plugins/passive/subdomain_takeover.py
------------------------------------------------
Subdomain Takeover / Orphaned Cloud Service Analysis Plugin.

Safely evaluates target hostname DNS records and HTTP response fingerprints
to identify dangling CNAME pointers to unclaimed third-party cloud services.

Safety & Guardrails:
    - DETECTION ONLY.
    - NEVER attempts to claim, register, or provision cloud resources.
    - NEVER creates provider accounts, uploads files, or modifies DNS records.
    - NEVER performs brute-force subdomain enumeration or DNS zone transfers.
    - Uses safe DNS CNAME queries and passive HTTP response correlation.

Supported Cloud Providers & Signatures:
    - GitHub Pages (*.github.io)
    - Amazon S3 Website (*.s3.amazonaws.com, *.s3-website*.amazonaws.com)
    - Heroku (*.herokuapp.com, *.herokudns.com)
    - Microsoft Azure (*.azurewebsites.net, *.cloudapp.net, *.trafficmanager.net)
    - Shopify (shops.myshopify.com)
    - Fastly (*.fastly.net)
    - Netlify (*.netlify.app, *.netlify.com)
    - Vercel (cname.vercel-dns.com, *.vercel.app)
    - Ghost (ghost.io)
    - Surge (*.surge.sh)

Severity Logic:
    - HIGH: Recognizable cloud provider CNAME combined with provider-specific orphan fingerprint.
    - MEDIUM: Suspicious external CNAME pointing to an unresolvable or unconfigured service.
    - LOW: Potentially abandoned external service relationship requiring manual review.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import dns.resolver

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)


@dataclass
class _CloudProvider:
    name: str
    cname_patterns: list[re.Pattern[str]]
    orphan_fingerprints: list[re.Pattern[str]]


_PROVIDERS: list[_CloudProvider] = [
    _CloudProvider(
        name="GitHub Pages",
        cname_patterns=[
            re.compile(r"^.*\.github\.io\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"There isn't a GitHub Pages site here", re.IGNORECASE),
            re.compile(r"404 There isn't a GitHub Pages site here\.", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Amazon S3",
        cname_patterns=[
            re.compile(r"^.*\.s3(?:-website)?(?:[.-][\w-]+)?\.amazonaws\.com\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"<Code>NoSuchBucket</Code>", re.IGNORECASE),
            re.compile(r"The specified bucket does not exist", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Heroku",
        cname_patterns=[
            re.compile(r"^.*\.herokuapp\.com\.?$", re.IGNORECASE),
            re.compile(r"^.*\.herokudns\.com\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"herokucdn\.com/error-pages/no-such-app\.html", re.IGNORECASE),
            re.compile(r"There's nothing here, yet\.", re.IGNORECASE),
            re.compile(r"<title>No such app</title>", re.IGNORECASE),
            re.compile(r"No such app", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Microsoft Azure",
        cname_patterns=[
            re.compile(r"^.*\.azurewebsites\.net\.?$", re.IGNORECASE),
            re.compile(r"^.*\.cloudapp\.net\.?$", re.IGNORECASE),
            re.compile(r"^.*\.trafficmanager\.net\.?$", re.IGNORECASE),
            re.compile(r"^.*\.azurefd\.net\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"404 Web Site not found", re.IGNORECASE),
            re.compile(r"The resource you are looking for has been removed", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Shopify",
        cname_patterns=[
            re.compile(r"^shops\.myshopify\.com\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"Sorry, this shop is currently unavailable", re.IGNORECASE),
            re.compile(r"Only one step left to start selling", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Fastly",
        cname_patterns=[
            re.compile(r"^.*\.fastly\.net\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"Fastly error: unknown domain", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Netlify",
        cname_patterns=[
            re.compile(r"^.*\.netlify\.app\.?$", re.IGNORECASE),
            re.compile(r"^.*\.netlify\.com\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"Not Found - Request ID", re.IGNORECASE),
            re.compile(r"Netlify: Page not found", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Vercel",
        cname_patterns=[
            re.compile(r"^cname\.vercel-dns\.com\.?$", re.IGNORECASE),
            re.compile(r"^.*\.vercel\.app\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"The deployment could not be found on Vercel", re.IGNORECASE),
            re.compile(r"DEPLOYMENT_NOT_FOUND", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Ghost",
        cname_patterns=[
            re.compile(r"^.*\.ghost\.io\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"The thing you were looking for is no longer here", re.IGNORECASE),
            re.compile(r"Site not found", re.IGNORECASE),
        ],
    ),
    _CloudProvider(
        name="Surge.sh",
        cname_patterns=[
            re.compile(r"^.*\.surge\.sh\.?$", re.IGNORECASE),
        ],
        orphan_fingerprints=[
            re.compile(r"project not found", re.IGNORECASE),
        ],
    ),
]


class SubdomainTakeoverPlugin(BasePlugin):
    """
    Safely inspects DNS CNAME records and HTTP fingerprints for dangling cloud service pointers.
    """

    name = "subdomain_takeover"
    description = (
        "Detects potential subdomain takeover vulnerabilities by checking DNS CNAME records "
        "and correlating with provider-specific orphaned service fingerprints."
    )
    category = "passive"
    version = "1.0.0"
    priority = 38

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe subdomain takeover analysis against context.target_url.
        """
        if not context.target_url:
            self.log("No target URL available — skipping subdomain takeover checks.")
            return

        parsed = urlparse(context.target_url)
        hostname = parsed.hostname or ""

        if not hostname:
            return

        # 1. Skip private / internal hostnames
        if self._is_internal_hostname(hostname):
            self.log(f"Hostname '{hostname}' is internal/private — skipping subdomain takeover check.")
            return

        # 2. Perform bounded DNS CNAME resolution
        cname_targets = await self._resolve_cnames(hostname)
        if not cname_targets:
            self.log(f"No CNAME records found for '{hostname}'.")
            return

        self.log(f"Discovered CNAME record(s) for '{hostname}': {cname_targets}")

        # 3. Match against known cloud providers
        matched_provider: _CloudProvider | None = None
        matched_cname: str = ""

        for cname in cname_targets:
            cname_clean = cname.rstrip(".")
            for provider in _PROVIDERS:
                if any(pattern.match(cname_clean) for pattern in provider.cname_patterns):
                    matched_provider = provider
                    matched_cname = cname_clean
                    break
            if matched_provider:
                break

        if not matched_provider:
            self.log(f"CNAME targets for '{hostname}' do not match monitored cloud providers.")
            return

        # 4. Correlate with HTTP response body / fingerprints
        response_text = context.html or ""
        if not response_text and context.session is not None:
            try:
                resp = await context.session.get(context.target_url)
                response_text = resp.text or ""
            except Exception as exc:
                self.log(f"Failed to fetch HTTP content for orphan verification: {exc}")

        # 5. Check for provider-specific orphan fingerprints
        is_orphaned = False
        matched_fingerprint = ""

        for fp_regex in matched_provider.orphan_fingerprints:
            match = fp_regex.search(response_text)
            if match:
                is_orphaned = True
                matched_fingerprint = match.group(0)
                break

        if is_orphaned:
            evidence = (
                f"Target Hostname: {hostname}\n"
                f"Resolved CNAME Target: {matched_cname}\n"
                f"Identified Cloud Provider: {matched_provider.name}\n"
                f"Matched Orphan Fingerprint: '{matched_fingerprint}'\n"
                f"Correlation: DNS CNAME points to third-party provider and HTTP response confirms unclaimed resource."
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Potential Subdomain Takeover: {hostname} ({matched_provider.name})",
                    description=(
                        f"The hostname '{hostname}' points via CNAME record to an external cloud service "
                        f"('{matched_cname}' - {matched_provider.name}) that appears to be unconfigured or deleted. "
                        f"The HTTP response returned a provider-specific orphan signature ('{matched_fingerprint}'). "
                        f"An attacker can register the unclaimed resource name on {matched_provider.name} to take "
                        f"full control of this subdomain, intercept traffic, steal session cookies, or conduct phishing."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        f"Either remove the dangling DNS CNAME record for '{hostname}' or claim/re-create the corresponding "
                        f"resource on {matched_provider.name} to secure the subdomain."
                    ),
                    evidence=evidence,
                )
            )
        else:
            self.log(f"Hostname '{hostname}' has CNAME to {matched_provider.name}, but active/healthy response observed.")

    # ------------------------------------------------------------------
    # DNS Resolution & Network Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _resolve_cnames(hostname: str) -> list[str]:
        """Perform asynchronous, bounded DNS CNAME query."""
        def _sync_cname_lookup() -> list[str]:
            results: list[str] = []
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 2.0
                answers = resolver.resolve(hostname, "CNAME")
                for rdata in answers:
                    results.append(str(rdata.target).rstrip("."))
            except Exception:
                pass
            return results

        return await asyncio.to_thread(_sync_cname_lookup)

    @staticmethod
    def _is_internal_hostname(hostname: str) -> bool:
        """Check if hostname is localhost, internal IP, or private domain."""
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
