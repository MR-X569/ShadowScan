"""
app/scanner/plugins/passive/cors.py
------------------------------------
CORS Misconfiguration Plugin — analyzes Cross-Origin Resource Sharing (CORS)
configurations and actively evaluates target endpoints for origin reflection,
wildcard exposures, and credential leakage.

Checks performed:
    - Wildcard Access-Control-Allow-Origin ('*')
    - Wildcard combined with Access-Control-Allow-Credentials: true (invalid / misconfigured)
    - Arbitrary Origin Reflection (evaluating origin probes against the target)
    - Arbitrary Origin Reflection with Credentials enabled (CRITICAL)
    - Insecure 'null' Origin reflection and credential trust (HIGH)
    - Subdomain/Prefix trust bypass reflection (CRITICAL / HIGH)
    - Insecure HTTP Origin accepted on HTTPS target (MEDIUM)

Severity Logic:
    - Arbitrary origin reflection + credentials -> CRITICAL
    - Flawed regex origin bypass + credentials -> CRITICAL
    - Null origin allowed + credentials -> HIGH
    - Arbitrary origin reflection without credentials -> HIGH
    - Wildcard origin (*) with credentials -> HIGH
    - Null origin allowed without credentials -> MEDIUM
    - Insecure HTTP origin accepted on HTTPS target with credentials -> MEDIUM
    - Permissive Wildcard origin (*) -> LOW / MEDIUM
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

# Test origins used for safe active reflection probing
_TEST_ATTACKER_ORIGIN: str = "https://attacker-cors-eval.test"
_TEST_NULL_ORIGIN: str = "null"


class CorsMisconfigurationPlugin(BasePlugin):
    """
    Analyzes CORS security posture from response headers and performs safe,
    controlled origin probing against the target URL.
    """

    name = "cors_misconfiguration"
    description = (
        "Analyzes Cross-Origin Resource Sharing (CORS) headers and detects "
        "arbitrary origin reflection, wildcard exposures, and credential leakage."
    )
    category = "passive"
    version = "1.0.0"
    priority = 25

    async def run(self, context: ScanContext) -> None:
        """
        Evaluate CORS headers and perform targeted reflection checks.
        """
        # 1. Passive Header Analysis on initial response
        self._analyze_initial_headers(context)

        # 2. Active Probing (only if HTTP session is available)
        if context.session is not None and context.target_url:
            await self._probe_cors_reflections(context)

    # ------------------------------------------------------------------
    # Passive Initial Header Inspection
    # ------------------------------------------------------------------

    def _analyze_initial_headers(self, context: ScanContext) -> None:
        """Inspect initial response headers for basic CORS anomalies."""
        if not context.headers:
            return

        headers = {k.lower(): v for k, v in context.headers.items()}
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()

        if not acao:
            return

        evidence_base = f"Access-Control-Allow-Origin: {acao}"
        if acac:
            evidence_base += f"\nAccess-Control-Allow-Credentials: {acac}"

        if acao == "*":
            if acac == "true":
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Invalid CORS Configuration: Wildcard Origin With Credentials",
                        description=(
                            "The server responded with 'Access-Control-Allow-Origin: *' and "
                            "'Access-Control-Allow-Credentials: true'. According to the CORS specification, "
                            "browsers reject responses that combine a wildcard origin with credentials. "
                            "However, this indicates a broken security configuration that may cause functional "
                            "issues or expose data to non-browser API clients."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            "Never set Access-Control-Allow-Credentials to true when using a wildcard origin. "
                            "Specify explicit, trusted origins if authenticated cross-origin requests are required."
                        ),
                        evidence=evidence_base,
                    )
                )
            else:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Permissive CORS Policy: Wildcard Origin Allowed",
                        description=(
                            "The server responded with 'Access-Control-Allow-Origin: *'. This allows any external "
                            "website to execute cross-origin requests and read response data via browser scripts. "
                            "If this endpoint serves public, non-sensitive content, this may be intended; "
                            "however, if the response contains sensitive or user-specific data, it represents a risk."
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            "If the endpoint returns private or sensitive information, replace the wildcard "
                            "with an explicit whitelist of trusted origins."
                        ),
                        evidence=evidence_base,
                    )
                )
        elif acao.lower() == "null":
            if acac == "true":
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Dangerous CORS Configuration: Null Origin Allowed With Credentials",
                        description=(
                            "The server responded with 'Access-Control-Allow-Origin: null' and "
                            "'Access-Control-Allow-Credentials: true'. Attackers can use sandboxed iframes "
                            "or 'data:' URLs (which execute in a 'null' origin) to issue authenticated "
                            "cross-origin requests and exfiltrate user responses."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            "Never allow the 'null' origin in Access-Control-Allow-Origin, especially with "
                            "Access-Control-Allow-Credentials enabled. Whitelist explicit HTTPS origins only."
                        ),
                        evidence=evidence_base,
                    )
                )
            else:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Insecure CORS Policy: Null Origin Allowed",
                        description=(
                            "The server returned 'Access-Control-Allow-Origin: null'. Sandboxed iframes and "
                            "local files produce a 'null' origin, which can allow untrusted local or embedded "
                            "contexts to read responses."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation="Remove 'null' from permitted origins. Specify trusted origin domains explicitly.",
                        evidence=evidence_base,
                    )
                )

    # ------------------------------------------------------------------
    # Active CORS Origin Probing
    # ------------------------------------------------------------------

    async def _probe_cors_reflections(self, context: ScanContext) -> None:
        """
        Send controlled HTTP requests with varying Origin headers to detect
        origin reflection and authorization bypasses.
        """
        client = context.session
        target_url = context.target_url
        target_host = self._get_host(target_url)

        # Probes list: (origin_value, probe_type_label)
        probes: list[tuple[str, str]] = [
            (_TEST_ATTACKER_ORIGIN, "arbitrary_origin"),
            (_TEST_NULL_ORIGIN, "null_origin"),
        ]

        if target_host:
            # Subdomain / prefix reflection probe (e.g., target.com.attacker.test)
            prefix_origin = f"https://{target_host}.attacker-cors-eval.test"
            probes.append((prefix_origin, "prefix_bypass"))

            # Insecure HTTP version of target (if target is HTTPS)
            if target_url.lower().startswith("https://"):
                http_origin = f"http://{target_host}"
                probes.append((http_origin, "http_trust_inversion"))

        findings_emitted: set[str] = set()

        for origin, probe_type in probes:
            try:
                response = await client.get(
                    target_url,
                    headers={"Origin": origin},
                )
                headers = {k.lower(): v for k, v in response.headers.items()}
                acao = headers.get("access-control-allow-origin", "").strip()
                acac = headers.get("access-control-allow-credentials", "").strip().lower()

                if not acao:
                    continue

                is_reflected = acao.lower() == origin.lower()
                is_creds_enabled = acac == "true"

                evidence = (
                    f"Request Origin: {origin}\n"
                    f"Response Access-Control-Allow-Origin: {acao}\n"
                    f"Response Access-Control-Allow-Credentials: {acac or 'not set'}"
                )

                if probe_type == "arbitrary_origin" and is_reflected:
                    if is_creds_enabled and "arbitrary_creds" not in findings_emitted:
                        findings_emitted.add("arbitrary_creds")
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                                description=(
                                    f"The server dynamically reflects any supplied Origin header ('{origin}') "
                                    f"into 'Access-Control-Allow-Origin' AND enables 'Access-Control-Allow-Credentials: true'. "
                                    f"This is a severe vulnerability: an attacker hosting a malicious site can issue "
                                    f"authenticated background requests using the victim's session cookies and read "
                                    f"confidential response data directly."
                                ),
                                severity=Severity.CRITICAL,
                                recommendation=(
                                    "Do NOT dynamically reflect the request 'Origin' header into Access-Control-Allow-Origin. "
                                    "Maintain a strict server-side whitelist of trusted origins and validate against it. "
                                    "Never pair reflected origins with Access-Control-Allow-Credentials: true."
                                ),
                                evidence=evidence,
                            )
                        )
                    elif not is_creds_enabled and "arbitrary_no_creds" not in findings_emitted:
                        findings_emitted.add("arbitrary_no_creds")
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Insecure CORS Policy: Arbitrary Origin Reflection",
                                description=(
                                    f"The server reflects arbitrary requested Origin headers ('{origin}') in "
                                    f"'Access-Control-Allow-Origin' without credentials. Any third-party domain "
                                    f"can read unauthenticated responses from this endpoint."
                                ),
                                severity=Severity.HIGH,
                                recommendation=(
                                    "Validate the 'Origin' request header against a fixed whitelist of authorized domains."
                                ),
                                evidence=evidence,
                            )
                        )

                elif probe_type == "null_origin" and (is_reflected or acao.lower() == "null"):
                    if is_creds_enabled and "null_creds" not in findings_emitted:
                        findings_emitted.add("null_creds")
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Dangerous CORS Configuration: Null Origin Allowed with Credentials",
                                description=(
                                    "When queried with 'Origin: null', the server returned 'Access-Control-Allow-Origin: null' "
                                    "with 'Access-Control-Allow-Credentials: true'. Attackers can exploit sandboxed iframes "
                                    "or local context attacks to access authenticated user data."
                                ),
                                severity=Severity.HIGH,
                                recommendation=(
                                    "Do not accept the 'null' origin. Ensure origins are strictly validated against trusted HTTPS domains."
                                ),
                                evidence=evidence,
                            )
                        )

                elif probe_type == "prefix_bypass" and is_reflected:
                    if is_creds_enabled and "prefix_creds" not in findings_emitted:
                        findings_emitted.add("prefix_creds")
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Critical CORS Misconfiguration: Prefix/Subdomain Trust Bypass with Credentials",
                                description=(
                                    f"The server accepted an attacker-controlled origin containing the target hostname as a prefix "
                                    f"('{origin}') and returned Access-Control-Allow-Credentials: true. "
                                    f"This typically indicates a flawed regular expression or string prefix check (e.g. matching "
                                    f"'example.com' against 'example.com.attacker.com')."
                                ),
                                severity=Severity.CRITICAL,
                                recommendation=(
                                    "Ensure origin validation parses the host component properly and requires exact domain matching "
                                    "or strict regex anchors (e.g., r'^https://([a-zA-Z0-9-]+\\.)?example\\.com$')."
                                ),
                                evidence=evidence,
                            )
                        )

                elif probe_type == "http_trust_inversion" and is_reflected and is_creds_enabled:
                    if "http_trust" not in findings_emitted:
                        findings_emitted.add("http_trust")
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="CORS Trust Inversion: Insecure HTTP Origin Allowed on HTTPS Target",
                                description=(
                                    f"The HTTPS target accepted the unencrypted HTTP origin ('{origin}') with credentials. "
                                    f"A network attacker who can intercept HTTP traffic or execute a Man-in-the-Middle (MitM) "
                                    f"attack can inject malicious scripts into the unencrypted origin and read data from this HTTPS endpoint."
                                ),
                                severity=Severity.MEDIUM,
                                recommendation=(
                                    "Only allow HTTPS origins in CORS headers when serving over HTTPS."
                                ),
                                evidence=evidence,
                            )
                        )

            except Exception as exc:
                self.log(f"CORS probe for origin '{origin}' failed or timed out: {exc}")

        # Store CORS analysis metadata
        context.set_metadata(
            "cors_probes_executed",
            [origin for origin, _ in probes],
        )

    @staticmethod
    def _get_host(target_url: str) -> str:
        """Extract the hostname from the target URL."""
        try:
            return urlparse(target_url).hostname or ""
        except Exception:
            return ""
