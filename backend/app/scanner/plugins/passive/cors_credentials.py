"""
app/scanner/plugins/passive/cors_credentials.py
-----------------------------------------------
Credentialed CORS Security & Origin Trust Analysis Plugin.

Safely evaluates Cross-Origin Resource Sharing (CORS) configurations with specific focus
on credentialed access (Access-Control-Allow-Credentials: true), origin reflection,
null-origin trust, and preflight header/method exposure on sensitive endpoints.

Safety & Guardrails:
    - Safe GET and OPTIONS queries only.
    - NEVER sends credentials, auth tokens, or cookies to third-party domains.
    - NEVER attempts authenticated state-changing requests.
    - Redacts all sensitive cookies, tokens, and authorization headers in findings.

Checks Performed:
    1. Arbitrary Origin Reflection + Credentials: Evaluates whether arbitrary origins
       receive Access-Control-Allow-Credentials: true.
    2. Null-Origin Credentialed Trust: Evaluates if 'Origin: null' is trusted with credentials.
    3. Prefix/Subdomain Trust Bypass + Credentials: Tests flawed regex origin matching.
    4. Permissive Preflight Headers/Methods under credentialed policies.

Severity Logic:
    - HIGH: Untrusted arbitrary origin is reflected/accepted with credentials enabled on a sensitive/API endpoint.
    - MEDIUM: Credentialed CORS accepts prefix/subdomain bypass origins or null origin.
    - LOW: Suspicious permissive CORS configuration (e.g. wildcard preflight headers with credentials).
    - NONE: Strict allowlist with appropriate credential handling.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Controlled benign test origins for evaluation
_TEST_ARBITRARY_ORIGIN: str = "https://shadowscan-eval.test"
_TEST_NULL_ORIGIN: str = "null"


class CorsCredentialsPlugin(BasePlugin):
    """
    Evaluates credentialed CORS configurations, origin validation rigor, and preflight exposure.
    """

    name = "cors_credentials"
    description = (
        "Analyzes credentialed CORS security, detecting arbitrary origin reflection with credentials, "
        "null-origin credential trust, and permissive preflight header configurations."
    )
    category = "passive"
    version = "1.0.0"
    priority = 27

    async def run(self, context: ScanContext) -> None:
        """
        Execute credentialed CORS analysis against context.target_url and context.headers.
        """
        if not context.target_url:
            self.log("No target URL available — skipping credentialed CORS checks.")
            return

        parsed = urlparse(context.target_url)
        hostname = parsed.hostname or ""

        # 1. Passive Header Analysis
        self._analyze_initial_credentialed_headers(context)

        # 2. Active Controlled Origin Probing (only if session available)
        if context.session is not None:
            await self._probe_credentialed_origins(hostname, context)

    # ------------------------------------------------------------------
    # Passive Analysis
    # ------------------------------------------------------------------

    def _analyze_initial_credentialed_headers(self, context: ScanContext) -> None:
        """Analyze initial response headers for dangerous credentialed CORS settings."""
        if not context.headers:
            return

        headers = {k.lower(): v for k, v in context.headers.items()}
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()
        acah = headers.get("access-control-allow-headers", "").strip()
        acam = headers.get("access-control-allow-methods", "").strip()

        # Check for Wildcard preflight headers combined with credentials
        if acac == "true" and acah == "*":
            evidence = (
                f"Target URL: {self._redact_url(context.target_url)}\n"
                f"Access-Control-Allow-Origin: {acao or 'Not Set'}\n"
                f"Access-Control-Allow-Credentials: true\n"
                f"Access-Control-Allow-Headers: *\n"
                f"Issue: Wildcard allowed headers combined with credentialed access."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Permissive Preflight Headers in Credentialed CORS Configuration",
                    description=(
                        "The server specifies 'Access-Control-Allow-Headers: *' while permitting credentialed "
                        "requests ('Access-Control-Allow-Credentials: true'). While modern browser CORS specifications "
                        "disallow wildcard headers with credentials, this permissive policy may expose custom auth "
                        "headers to unauthorized third-party scripts."
                    ),
                    severity=Severity.LOW,
                    recommendation="Explicitly list required request headers instead of using a wildcard when credentials are enabled.",
                    evidence=evidence,
                )
            )

    # ------------------------------------------------------------------
    # Active Controlled Origin Probing
    # ------------------------------------------------------------------

    async def _probe_credentialed_origins(self, hostname: str, context: ScanContext) -> None:
        """Probe endpoint with controlled benign origins to evaluate credentialed reflection."""
        client = context.session
        target_url = context.target_url

        probes: list[tuple[str, str, str]] = [
            (_TEST_ARBITRARY_ORIGIN, "arbitrary", "Arbitrary External Origin"),
            (_TEST_NULL_ORIGIN, "null", "Null Origin (Sandboxed Iframes)"),
        ]

        if hostname:
            prefix_origin = f"https://{hostname}.shadowscan-eval.test"
            probes.append((prefix_origin, "prefix", "Hostname Prefix Bypass Origin"))

        has_session_context = bool(context.cookies) or "cookie" in context.headers or "authorization" in context.headers

        for origin_val, probe_type, probe_label in probes:
            try:
                # 1. Send GET request with controlled Origin
                resp = await client.get(target_url, headers={"Origin": origin_val})
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                acao = resp_headers.get("access-control-allow-origin", "").strip()
                acac = resp_headers.get("access-control-allow-credentials", "").strip().lower()

                is_creds_enabled = acac == "true"
                is_reflected = acao.lower() == origin_val.lower()

                if is_reflected and is_creds_enabled:
                    if probe_type == "arbitrary":
                        severity = Severity.HIGH if has_session_context or "api" in target_url.lower() else Severity.MEDIUM
                        evidence = (
                            f"Tested Endpoint: {self._redact_url(target_url)}\n"
                            f"Supplied Origin: {origin_val} ({probe_label})\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: true\n"
                            f"Session Context: {'Yes (Ambient cookies or auth detected)' if has_session_context else 'API Endpoint'}\n"
                            f"Evaluation: Arbitrary external origin is trusted for credentialed cross-origin read access."
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Dangerous Credentialed CORS: Arbitrary Origin Reflection with Credentials",
                                description=(
                                    f"The endpoint reflects any arbitrary requested Origin ('{origin_val}') into "
                                    f"'Access-Control-Allow-Origin' while setting 'Access-Control-Allow-Credentials: true'. "
                                    f"A malicious website can execute authenticated cross-origin requests using the victim's "
                                    f"session cookies, reading sensitive profile data, private messages, or API tokens."
                                ),
                                severity=severity,
                                recommendation=(
                                    "Validate the 'Origin' request header against a strict, server-side allowlist of trusted HTTPS domains. "
                                    "Never dynamically mirror untrusted Origin headers when Access-Control-Allow-Credentials is true."
                                ),
                                evidence=evidence,
                            )
                        )
                        return  # High-priority finding recorded

                    elif probe_type == "null":
                        evidence = (
                            f"Tested Endpoint: {self._redact_url(target_url)}\n"
                            f"Supplied Origin: null\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: true\n"
                            f"Evaluation: 'null' origin is trusted with credentials."
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Insecure Credentialed CORS: Null Origin Allowed with Credentials",
                                description=(
                                    "The server accepted 'Origin: null' and enabled 'Access-Control-Allow-Credentials: true'. "
                                    "Attackers can leverage sandboxed iframes, local file schemes, or data: URLs "
                                    "to trigger requests with a null origin and access authenticated user responses."
                                ),
                                severity=Severity.MEDIUM,
                                recommendation="Do not accept 'null' in Access-Control-Allow-Origin. Enforce explicit HTTPS origin validation.",
                                evidence=evidence,
                            )
                        )
                        return

                    elif probe_type == "prefix":
                        evidence = (
                            f"Tested Endpoint: {self._redact_url(target_url)}\n"
                            f"Supplied Origin: {origin_val}\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: true\n"
                            f"Evaluation: Hostname prefix bypass origin accepted with credentials."
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Credentialed CORS Trust Bypass: Prefix Domain Matching with Credentials",
                                description=(
                                    f"The server accepted an attacker-controlled origin containing the target hostname as a prefix "
                                    f"('{origin_val}') with credentials enabled. This indicates a flawed regular expression or string "
                                    f"prefix check during origin validation."
                                ),
                                severity=Severity.MEDIUM,
                                recommendation="Ensure origin validation matches the full domain name with strict regex anchors.",
                                evidence=evidence,
                            )
                        )
                        return

            except Exception as exc:
                self.log(f"CORS credentials probe for '{origin_val}' failed: {exc}")

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
