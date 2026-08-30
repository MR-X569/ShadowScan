"""
app/scanner/plugins/passive/http_methods.py
-------------------------------------------
HTTP Methods Security Plugin — analyzes allowed and exposed HTTP methods
(OPTIONS, TRACE, PUT, DELETE, CONNECT) on the target endpoint.

Checks performed:
    - Queries OPTIONS and parses Allow & Access-Control-Allow-Methods headers
    - Safely verifies TRACE method execution and response header reflection (XST)
    - Identifies potentially risky HTTP methods (PUT, DELETE, CONNECT)
    - Strictly non-destructive: never deletes resources or uploads files

Severity Logic:
    - TRACE method actively echoing headers (Cross-Site Tracing - XST) -> MEDIUM
    - Potentially dangerous methods (PUT / DELETE) advertised in Allow header -> LOW
    - TRACE method advertised in Allow header but not active -> LOW
    - CONNECT method advertised in Allow header -> LOW
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Test probe header used for safe TRACE verification
_TRACE_PROBE_HEADER: str = "X-ShadowScan-Trace-Probe"
_TRACE_PROBE_VALUE: str = "xst-active-verification-probe"


class HttpMethodsPlugin(BasePlugin):
    """
    Evaluates exposed HTTP methods via OPTIONS requests and safe TRACE probes.
    """

    name = "http_methods"
    description = (
        "Analyzes supported and exposed HTTP methods (OPTIONS, TRACE, PUT, DELETE, CONNECT) for security risks."
    )
    category = "passive"
    version = "1.0.0"
    priority = 70

    async def run(self, context: ScanContext) -> None:
        """
        Execute HTTP methods evaluation against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping HTTP methods checks.")
            return

        client = context.session
        target_url = context.target_url

        # 1. Send OPTIONS request to inspect Allow headers
        allowed_methods = await self._query_options_methods(client, target_url)

        if allowed_methods:
            context.set_metadata("allowed_http_methods", list(allowed_methods))
            self.log(f"Target '{target_url}' advertises methods: {allowed_methods}")

        # 2. Test TRACE Method (Cross-Site Tracing / XST)
        await self._test_trace_method(client, target_url, allowed_methods, context)

        # 3. Assess Risky Methods Advertised (PUT, DELETE, CONNECT)
        self._assess_advertised_methods(allowed_methods, target_url, context)

    # ------------------------------------------------------------------
    # OPTIONS Probing
    # ------------------------------------------------------------------

    async def _query_options_methods(
        self,
        client: Any,
        target_url: str,
    ) -> set[str]:
        """Send an OPTIONS request and parse the Allow header."""
        allowed: set[str] = set()

        try:
            response = await client.request("OPTIONS", target_url)

            # 1. Parse 'Allow' response header
            allow_hdr = response.headers.get("allow", "")
            if allow_hdr:
                for method in allow_hdr.split(","):
                    clean = method.strip().upper()
                    if clean:
                        allowed.add(clean)

            # 2. Parse 'Access-Control-Allow-Methods' header
            acao_methods = response.headers.get("access-control-allow-methods", "")
            if acao_methods:
                for method in acao_methods.split(","):
                    clean = method.strip().upper()
                    if clean:
                        allowed.add(clean)

        except Exception as exc:
            self.log(f"OPTIONS request failed for '{target_url}': {exc}")

        return allowed

    # ------------------------------------------------------------------
    # TRACE Testing (XST)
    # ------------------------------------------------------------------

    async def _test_trace_method(
        self,
        client: Any,
        target_url: str,
        allowed_methods: set[str],
        context: ScanContext,
    ) -> None:
        """
        Safely test if the TRACE method is enabled and echoes request headers.
        """
        try:
            response = await client.request(
                "TRACE",
                target_url,
                headers={_TRACE_PROBE_HEADER: _TRACE_PROBE_VALUE},
            )

            # If TRACE returned 200 OK and echoed the probe header or request body
            if response.status_code == 200:
                resp_text = response.text or ""

                if _TRACE_PROBE_VALUE in resp_text or "TRACE" in resp_text:
                    evidence = (
                        f"Target URL: {target_url}\n"
                        f"Request Method: TRACE\n"
                        f"Probe Header: {_TRACE_PROBE_HEADER}: {_TRACE_PROBE_VALUE}\n"
                        f"Response Status: HTTP 200 OK\n\n"
                        f"Response Body Echo:\n{resp_text[:300].strip()}"
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title="HTTP TRACE Method Enabled (Cross-Site Tracing - XST)",
                            description=(
                                "The HTTP TRACE method is enabled on the web server and actively echoes request headers "
                                "in the response body. If the application has any Cross-Site Scripting (XSS) flaws, "
                                "an attacker can issue a client-side TRACE request to steal sensitive 'HttpOnly' session "
                                "cookies and authentication headers directly from the reflected response (Cross-Site Tracing / XST)."
                            ),
                            severity=Severity.MEDIUM,
                            recommendation=(
                                "Disable the HTTP TRACE method across all web server configurations. "
                                "For Apache, add 'TraceEnable Off' to httpd.conf. For Nginx, ensure only required methods "
                                "are routed (e.g. limit_except GET POST HEAD). For IIS, remove TRACE from request filtering."
                            ),
                            evidence=evidence,
                        )
                    )
                    return
                else:
                    evidence = f"Target URL: {target_url}\nRequest Method: TRACE\nResponse Status: HTTP 200 OK"
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title="HTTP TRACE Method Enabled",
                            description=(
                                "The HTTP TRACE method responded with HTTP 200 OK on the target. "
                                "To prevent potential Cross-Site Tracing (XST) exposure, the TRACE method should be disabled."
                            ),
                            severity=Severity.LOW,
                            recommendation="Disable the HTTP TRACE method in web server configuration (e.g. 'TraceEnable Off' in Apache).",
                            evidence=evidence,
                        )
                    )
                    return

            # If TRACE is advertised in Allow header but returned 405/403/501
            if "TRACE" in allowed_methods and response.status_code in (405, 403, 501):
                evidence = f"Allow Header: {', '.join(sorted(allowed_methods))}\nTRACE Request Status: HTTP {response.status_code}"
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="HTTP TRACE Method Advertised in Allow Header",
                        description=(
                            "The server's Allow header lists 'TRACE' as a supported method, although the server currently "
                            "rejects active TRACE requests. To adhere to defense-in-depth, TRACE should be completely unmapped."
                        ),
                        severity=Severity.LOW,
                        recommendation="Explicitly disable the TRACE method in web server settings.",
                        evidence=evidence,
                    )
                )

        except Exception as exc:
            self.log(f"TRACE method check for '{target_url}' failed: {exc}")

    # ------------------------------------------------------------------
    # Advertised Methods Assessment (PUT, DELETE, CONNECT)
    # ------------------------------------------------------------------

    def _assess_advertised_methods(
        self,
        allowed_methods: set[str],
        target_url: str,
        context: ScanContext,
    ) -> None:
        """Inspect Allow header list for potentially risky methods."""
        risky_found = [m for m in ("PUT", "DELETE") if m in allowed_methods]

        if risky_found:
            evidence = (
                f"Target URL: {target_url}\n"
                f"Advertised Allowed Methods: {', '.join(sorted(allowed_methods))}\n"
                f"Flagged Methods: {', '.join(risky_found)}"
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Potentially Risky HTTP Methods Advertised ({', '.join(risky_found)})",
                    description=(
                        f"The server advertises support for the HTTP methods {', '.join(risky_found)} in its Allow header. "
                        f"While REST APIs may legitimately use PUT and DELETE with strict authentication, exposing these "
                        f"methods without authorization could allow arbitrary file modification or deletion."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Verify that PUT and DELETE methods require strict authentication and authorization checks. "
                        "If not required on public endpoints, restrict the web server to only allow GET, POST, and HEAD."
                    ),
                    evidence=evidence,
                )
            )

        if "CONNECT" in allowed_methods:
            evidence = (
                f"Target URL: {target_url}\n"
                f"Advertised Allowed Methods: {', '.join(sorted(allowed_methods))}"
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="HTTP CONNECT Method Advertised",
                    description=(
                        "The server advertises the HTTP CONNECT method in its Allow header. The CONNECT method is "
                        "used for establishing two-way HTTP tunnels (typically by proxies) and should not be enabled "
                        "on standard web applications."
                    ),
                    severity=Severity.LOW,
                    recommendation="Disable the HTTP CONNECT method in web server / reverse proxy configurations.",
                    evidence=evidence,
                )
            )
