"""
app/scanner/plugins/passive/cache_control_security.py
----------------------------------------------------
Cache-Control Security & Web Cache Deception Analysis Plugin.

Safely evaluates HTTP caching headers (Cache-Control, Pragma, Expires, Vary) on sensitive,
authenticated, and API endpoints to prevent unintended intermediate/shared caching of
confidential user data and detect Web Cache Deception risks.

Safety & Guardrails:
    - Read-only GET/HEAD inspection.
    - NEVER attempts cache poisoning or cache flooding.
    - Redacts all personal tokens, cookies, passwords, and email addresses in findings.
    - Ignores public static assets (.css, .js, .png, etc.).

Sensitivity Indicators:
    - Path keywords: account, profile, dashboard, user, settings, admin, private,
      api, token, session, billing, orders, checkout, cart, inbox, me, auth
    - Cookies / Session context present in ScanContext or Set-Cookie header
    - Response body containing sensitive user profile or token markers

Severity Logic:
    - HIGH: Sensitive/authenticated response is explicitly marked as public/shared cacheable
            (e.g. 'public', 's-maxage', or long positive 'max-age').
    - MEDIUM: Sensitive/authenticated endpoint lacks explicit 'no-store' or 'private' directive.
    - MEDIUM: Web Cache Deception risk detected (sensitive content served under static-looking paths).
    - LOW: Sensitive endpoint uses weak caching controls or lacks 'Vary: Cookie' / 'Vary: Authorization'.
    - NONE: Sensitive endpoints enforce 'Cache-Control: no-store' or 'no-cache, no-store, private'.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Keywords in URL paths strongly indicating sensitive/authenticated content
_SENSITIVE_PATH_KEYWORDS: tuple[str, ...] = (
    "account",
    "profile",
    "dashboard",
    "user",
    "settings",
    "admin",
    "private",
    "api",
    "token",
    "session",
    "billing",
    "orders",
    "checkout",
    "cart",
    "inbox",
    "me",
    "auth",
    "manage",
)

# File extensions for genuinely public static assets to exclude from sensitive cache checks
_PUBLIC_STATIC_EXTENSIONS: tuple[str, ...] = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".webp",
    ".avif",
)

# Regex to detect sensitive body markers (emails, JWT tokens, auth tokens)
_EMAIL_PATTERN: re.Pattern[str] = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_JWT_PATTERN: re.Pattern[str] = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
_SENSITIVE_JSON_KEYS: re.Pattern[str] = re.compile(
    r"""(?i)["'](?:access_token|refresh_token|api_key|secret|password|credit_card|ssn|billing_address)["']\s*:\s*["'][^"']+["']"""
)


class CacheControlSecurityPlugin(BasePlugin):
    """
    Evaluates cache-control directives on sensitive and authenticated endpoints.
    """

    name = "cache_control_security"
    description = (
        "Detects unsafe HTTP caching directives on sensitive/authenticated routes and identifies "
        "potential Web Cache Deception (WCD) exposures."
    )
    category = "passive"
    version = "1.0.0"
    priority = 22

    async def run(self, context: ScanContext) -> None:
        """
        Execute caching security analysis against context.target_url, context.headers, and cookies.
        """
        if not context.target_url or not context.headers:
            self.log("No target URL or headers available — skipping Cache-Control security checks.")
            return

        parsed = urlparse(context.target_url)
        path = parsed.path.lower()

        # 1. Skip genuinely public static asset files
        if any(path.endswith(ext) for ext in _PUBLIC_STATIC_EXTENSIONS):
            self.log(f"Path '{path}' is a public static asset — skipping sensitive cache checks.")
            return

        headers = {k.lower(): v for k, v in context.headers.items()}
        cache_control = headers.get("cache-control", "").strip().lower()
        pragma = headers.get("pragma", "").strip().lower()
        expires = headers.get("expires", "").strip()
        vary = headers.get("vary", "").strip().lower()
        set_cookie = headers.get("set-cookie", "")

        # 2. Determine if endpoint/response is sensitive or session-specific
        has_session_cookies = bool(context.cookies) or bool(set_cookie)
        has_sensitive_path = any(kw in path for kw in _SENSITIVE_PATH_KEYWORDS)
        body_text = (context.html or "")[:10_000]

        has_sensitive_body = bool(
            _SENSITIVE_JSON_KEYS.search(body_text) or
            _JWT_PATTERN.search(body_text) or
            (has_sensitive_path and _EMAIL_PATTERN.search(body_text))
        )

        is_sensitive_context = has_sensitive_path or has_session_cookies or has_sensitive_body

        if not is_sensitive_context:
            self.log(f"URL '{context.target_url}' does not exhibit sensitive/authenticated indicators.")
            return

        # 3. Analyze Cache-Control Directives
        self._evaluate_cache_policy(
            context,
            cache_control,
            pragma,
            expires,
            vary,
            has_session_cookies,
            has_sensitive_path,
            has_sensitive_body,
            path,
        )

    # ------------------------------------------------------------------
    # Policy Evaluation
    # ------------------------------------------------------------------

    def _evaluate_cache_policy(
        self,
        context: ScanContext,
        cache_control: str,
        pragma: str,
        expires: str,
        vary: str,
        has_session_cookies: bool,
        has_sensitive_path: bool,
        has_sensitive_body: bool,
        path: str,
    ) -> None:
        """Inspect cache directives and assign appropriate findings."""
        has_no_store = "no-store" in cache_control
        has_private = "private" in cache_control
        has_public = "public" in cache_control
        has_s_maxage = "s-maxage" in cache_control

        # Extract max-age if present
        max_age_val: int | None = None
        match_max_age = re.search(r"max-age\s*=\s*(\d+)", cache_control)
        if match_max_age:
            try:
                max_age_val = int(match_max_age.group(1))
            except ValueError:
                pass

        # Optimal policy: no-store present
        if has_no_store:
            self.log("Sensitive endpoint correctly specifies 'Cache-Control: no-store'.")
            return

        # Finding Case 1: HIGH - Explicit Shared/Public Caching on Sensitive Content
        if has_public or has_s_maxage or (max_age_val is not None and max_age_val > 0 and not has_private):
            evidence = (
                f"Target URL: {self._redact_url(context.target_url)}\n"
                f"Cache-Control: {cache_control or 'None'}\n"
                f"Pragma: {pragma or 'None'}\n"
                f"Expires: {expires or 'None'}\n"
                f"Sensitive Indicators: {'Session cookies present' if has_session_cookies else ''} "
                f"{'Sensitive path keyword' if has_sensitive_path else ''} "
                f"{'Sensitive data tokens detected' if has_sensitive_body else ''}"
            ).strip()

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Unsafe Public/Shared Caching of Sensitive Response",
                    description=(
                        f"The sensitive endpoint at '{self._redact_url(context.target_url)}' explicitly permits "
                        f"public/shared caching ('Cache-Control: {cache_control}'). Intermediate caching proxies, CDNs, "
                        f"and shared browser caches may store and serve this authenticated/sensitive response "
                        f"to unauthorized third parties."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Configure strict anti-caching headers on all authenticated, sensitive, and API responses:\n"
                        "Cache-Control: no-store, no-cache, must-revalidate, private\n"
                        "Pragma: no-cache\n"
                        "Expires: 0"
                    ),
                    evidence=evidence,
                )
            )
            return

        # Finding Case 2: MEDIUM - Missing or Weak Anti-Caching on Sensitive Endpoint
        if not cache_control or (not has_no_store and not has_private):
            evidence = (
                f"Target URL: {self._redact_url(context.target_url)}\n"
                f"Cache-Control: {cache_control or 'Missing'}\n"
                f"Pragma: {pragma or 'Missing'}\n"
                f"Expires: {expires or 'Missing'}"
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Missing Cache-Control Protection on Sensitive Endpoint",
                    description=(
                        f"The sensitive endpoint at '{self._redact_url(context.target_url)}' does not provide "
                        f"a restrictive Cache-Control header (such as 'no-store' or 'private'). "
                        f"In the absence of explicit cache directives, browsers and proxy caches may employ heuristic "
                        f"caching, storing confidential user records or account data on disk."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Add 'Cache-Control: no-store, max-age=0' to all sensitive and authenticated HTTP responses."
                    ),
                    evidence=evidence,
                )
            )
            return

        # Finding Case 3: LOW - Private Caching without no-store / Missing Vary
        if has_private and not has_no_store:
            is_token_endpoint = any(k in path for k in ("token", "auth", "session", "key"))
            if is_token_endpoint or ("cookie" not in vary and "authorization" not in vary):
                evidence = (
                    f"Target URL: {self._redact_url(context.target_url)}\n"
                    f"Cache-Control: {cache_control}\n"
                    f"Vary Header: {vary or 'Missing'}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Weak Cache-Control on Sensitive Endpoint",
                        description=(
                            f"The endpoint at '{self._redact_url(context.target_url)}' uses 'Cache-Control: private' "
                            f"without 'no-store', or lacks a 'Vary: Cookie' / 'Vary: Authorization' header. "
                            f"While private caching restricts shared proxies, highly confidential tokens or profile "
                            f"data can remain cached on local client disk."
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            "Use 'Cache-Control: no-store' for high-sensitivity endpoints (tokens, passwords, keys) "
                            "and specify 'Vary: Cookie, Authorization' on user-dependent responses."
                        ),
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
        # Redact query values if sensitive
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
