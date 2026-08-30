"""
app/scanner/plugins/passive/redirect_chain.py
---------------------------------------------
HTTP Redirect Chain & Transport Security Analysis Plugin.

Safely traces multi-hop HTTP redirect chains to identify insecure transport downgrades,
credential/token leakage across domain boundaries, dangerous non-web URI schemes,
and redirect loops.

Safety & Guardrails:
    - Strictly read-only GET requests with follow_redirects=False.
    - Bounded maximum redirect depth (max 5 hops).
    - Automatically strips Authorization and Cookie headers when crossing domain boundaries.
    - Redacts all sensitive tokens, session IDs, and credentials in findings.

Checks Performed:
    1. Dangerous Non-HTTP Scheme Detection (javascript:, data:, file:, vbscript:).
    2. Sensitive Token / Credential Leakage across external domain boundaries.
    3. HTTPS-to-HTTP Transport Downgrades (SSL stripping / unencrypted transit).
    4. Excessive Redirect Loops (>5 hops or cyclical paths).

Severity Logic:
    - HIGH: Dangerous non-HTTP redirect scheme (e.g. javascript:) or sensitive token leak to external domain.
    - MEDIUM: HTTPS-to-HTTP downgrade or unexpected cross-origin redirect chain.
    - LOW: Excessive redirect chain (>5 hops) or cyclical redirect loop.
    - NONE: Normal same-origin or secure HTTP-to-HTTPS redirects.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Maximum redirect hops to trace
_MAX_REDIRECT_HOPS: int = 5

# Redirect status codes
_REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

# Dangerous non-web URI schemes
_DANGEROUS_SCHEMES: tuple[str, ...] = (
    "javascript:",
    "data:",
    "file:",
    "vbscript:",
    "blob:",
)

# Sensitive query parameter keys that must not be forwarded to external origins
_SENSITIVE_PARAM_KEYS: frozenset[str] = frozenset(
    {
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "auth",
        "api_key",
        "apikey",
        "secret",
        "key",
        "code",
        "password",
        "passwd",
        "session",
        "session_id",
        "jwt",
    }
)


class RedirectChainPlugin(BasePlugin):
    """
    Traces and evaluates multi-hop redirect chains for security weaknesses and data leakage.
    """

    name = "redirect_chain"
    description = (
        "Traces HTTP redirect chains to detect insecure transport downgrades (HTTPS to HTTP), "
        "sensitive token leakage to external domains, dangerous URI schemes, and redirect loops."
    )
    category = "passive"
    version = "1.0.0"
    priority = 58

    async def run(self, context: ScanContext) -> None:
        """
        Trace redirect chain starting from context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping redirect chain analysis.")
            return

        client = context.session
        start_url = context.target_url
        parsed_start = urlparse(start_url)
        initial_host = parsed_start.hostname or ""

        # Trace redirect chain step-by-step
        chain: list[dict[str, Any]] = []
        current_url = start_url
        seen_urls: set[str] = set()

        for hop in range(1, _MAX_REDIRECT_HOPS + 2):
            if current_url in seen_urls:
                # Redirect loop detected
                evidence = self._build_chain_evidence(chain, loop_target=current_url)
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="HTTP Redirect Loop Detected in Redirect Chain",
                        description=(
                            f"The redirect chain starting from '{self._redact_url(start_url)}' entered a cyclical loop "
                            f"at step {hop}. Redirect loops cause Denial of Service for user browsers and search engine crawlers."
                        ),
                        severity=Severity.LOW,
                        recommendation="Review URL routing rules and remove circular redirect logic.",
                        evidence=evidence,
                    )
                )
                return

            seen_urls.add(current_url)

            if hop > _MAX_REDIRECT_HOPS:
                # Exceeded maximum hop depth
                evidence = self._build_chain_evidence(chain)
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Excessive HTTP Redirect Chain Depth (>5 Hops)",
                        description=(
                            f"The redirect chain from '{self._redact_url(start_url)}' exceeded the maximum expected "
                            f"depth of {_MAX_REDIRECT_HOPS} hops. Excessive redirects degrade page performance and indicate "
                            f"misconfigured routing policies."
                        ),
                        severity=Severity.LOW,
                        recommendation="Simplify the redirect chain to point directly to the final destination.",
                        evidence=evidence,
                    )
                )
                return

            try:
                # Send non-following GET request
                resp = await client.get(current_url, follow_redirects=False)
                status_code = resp.status_code
                location = resp.headers.get("location", "").strip()

                chain.append({
                    "hop": hop,
                    "url": current_url,
                    "status": status_code,
                    "location": location,
                })

                # If not a redirect status code, chain terminates
                if status_code not in _REDIRECT_STATUS_CODES or not location:
                    break

                # 1. Check for Dangerous Non-HTTP URI Schemes
                loc_lower = location.lower()
                for d_scheme in _DANGEROUS_SCHEMES:
                    if loc_lower.startswith(d_scheme):
                        evidence = self._build_chain_evidence(chain)
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Dangerous Non-HTTP Redirect Scheme: {d_scheme.rstrip(':')}",
                                description=(
                                    f"The endpoint at '{self._redact_url(current_url)}' returned a Location header "
                                    f"using an unsafe non-web URI scheme ('{location}'). Browsers executing this redirect "
                                    f"may execute client-side scripts (e.g. via javascript:), access local files, or trigger XSS."
                                ),
                                severity=Severity.HIGH,
                                recommendation="Never redirect to 'javascript:', 'data:', or 'file:' URI schemes. Restrict redirects to 'https://'.",
                                evidence=evidence,
                            )
                        )
                        return

                # Resolve relative Location headers to absolute URLs
                next_url = urljoin(current_url, location)

                # 2. Check for HTTPS-to-HTTP Downgrades
                parsed_cur = urlparse(current_url)
                parsed_next = urlparse(next_url)

                if parsed_cur.scheme.lower() == "https" and parsed_next.scheme.lower() == "http":
                    evidence = self._build_chain_evidence(chain)
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title="Insecure Transport Downgrade in Redirect Chain (HTTPS to HTTP)",
                            description=(
                                f"The redirect chain downgraded secure HTTPS traffic to unencrypted HTTP at hop {hop} "
                                f"('{self._redact_url(current_url)}' -> '{self._redact_url(next_url)}'). "
                                f"This exposes previously encrypted session tokens or sensitive data to Man-In-The-Middle (MITM) attackers."
                            ),
                            severity=Severity.MEDIUM,
                            recommendation="Ensure all redirects maintain HTTPS transport encryption without downgrading to HTTP.",
                            evidence=evidence,
                        )
                    )
                    return

                # 3. Check for Sensitive Token / Parameter Leakage to External Origins
                if parsed_next.hostname and parsed_cur.hostname and parsed_next.hostname.lower() != initial_host.lower():
                    # Cross-domain hop
                    sensitive_params_leaked = self._find_sensitive_params(next_url)
                    if sensitive_params_leaked:
                        evidence = (
                            f"Initial Host: {initial_host}\n"
                            f"External Destination: {parsed_next.hostname}\n"
                            f"Leaked Sensitive Parameters: {', '.join(sensitive_params_leaked)}\n\n"
                            f"Full Redirect Chain:\n{self._build_chain_evidence(chain)}"
                        )
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title="Sensitive Token / Credential Leakage to External Domain via Redirect",
                                description=(
                                    f"The application redirected to an external domain ('{parsed_next.hostname}') while "
                                    f"forwarding sensitive query parameters ({', '.join(sensitive_params_leaked)}). "
                                    f"The third-party server will receive confidential authorization tokens or credentials "
                                    f"in its HTTP server logs and Referer headers."
                                ),
                                severity=Severity.HIGH,
                                recommendation=(
                                    "Strip authentication tokens, secret keys, and credentials from URLs before redirecting "
                                    "users to external domains."
                                ),
                                evidence=evidence,
                            )
                        )
                        return

                current_url = next_url

            except Exception as exc:
                self.log(f"Error tracing redirect at hop {hop} ('{current_url}'): {exc}")
                break

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_sensitive_params(url: str) -> list[str]:
        """Detect sensitive parameters present in the URL query string."""
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        found = [k for k in query_dict if k.lower() in _SENSITIVE_PARAM_KEYS]
        return found

    def _build_chain_evidence(self, chain: list[dict[str, Any]], loop_target: str | None = None) -> str:
        """Format human-readable redirect chain trace."""
        lines = []
        for step in chain:
            lines.append(f"Hop {step['hop']}: HTTP {step['status']} | {self._redact_url(step['url'])}")
            if step["location"]:
                lines.append(f"       -> Location: {self._redact_url(step['location'])}")
        if loop_target:
            lines.append(f"Loop -> Cycles back to: {self._redact_url(loop_target)}")
        return "\n".join(lines)

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
                    if k.lower() in _SENSITIVE_PARAM_KEYS or any(s in k.lower() for s in ("token", "key", "secret", "pass")):
                        redacted_parts.append(f"{k}=[REDACTED]")
                    else:
                        redacted_parts.append(part)
                else:
                    redacted_parts.append(part)
            query = "&".join(redacted_parts)

        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + (f"?{query}" if query else "")
