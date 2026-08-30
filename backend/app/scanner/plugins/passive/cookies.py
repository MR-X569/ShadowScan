"""
app/scanner/plugins/passive/cookies.py
---------------------------------------
Cookie Security Analysis Plugin — analyzes HTTP response cookies for missing
or insecure attributes and sensitive cookie exposure.

Checks performed:
    - Missing HttpOnly attribute (sensitive session vs general cookies)
    - Missing Secure attribute over HTTPS (sensitive session vs general cookies)
    - Missing SameSite attribute or SameSite=None without Secure
    - Insecure sensitive session cookies without proper protection
    - Cookie prefix violations (__Secure- and __Host-)

Severity Logic:
    - Sensitive session cookie missing HttpOnly -> HIGH
    - Sensitive session cookie missing Secure (over HTTPS) -> HIGH
    - SameSite=None without Secure -> HIGH
    - Sensitive session cookie missing SameSite -> MEDIUM
    - General cookie missing HttpOnly / Secure / SameSite -> LOW
    - Cookie prefix misconfiguration -> MEDIUM
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Patterns matching sensitive cookie names (sessions, auth tokens, identities)
_SENSITIVE_COOKIE_NAME_REGEX: re.Pattern[str] = re.compile(
    r"^(?:session|sessionid|sess|sid|auth|token|jwt|access_token|refresh_token|"
    r"id_token|remember|remember_me|user_session|account|login|logged_in|"
    r"phpsessid|jsessionid|aspsessionid|connect\.sid|authtoken|user|sso)$"
    r"|(?:session|sessid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|"
    r"jwt|authtoken|auth_token|access_token|refresh_token)",
    re.IGNORECASE,
)

# Common analytics or non-sensitive functional cookie prefixes / names
_ANALYTICS_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        "_ga",
        "_gid",
        "_gat",
        "_gat_gtag",
        "__cf_bm",
        "_cfuvid",
        "_pk_id",
        "_pk_ses",
        "theme",
        "dark_mode",
        "lang",
        "locale",
        "timezone",
    }
)

# CSRF cookie patterns (may legitimately omit HttpOnly in Double-Submit Cookie patterns)
_CSRF_COOKIE_NAME_REGEX: re.Pattern[str] = re.compile(
    r"^(?:csrf|xsrf|_csrf|csrftoken|xsrf-token|antiforgery|_xsrf)$",
    re.IGNORECASE,
)


@dataclass
class ParsedCookie:
    """Represents a parsed HTTP response cookie with its security flags."""

    name: str
    value: str
    httponly: bool = False
    secure: bool = False
    samesite: str | None = None
    domain: str | None = None
    path: str | None = None
    raw_header: str = ""
    is_sensitive: bool = False
    is_csrf: bool = False
    is_analytics: bool = False


class CookieSecurityPlugin(BasePlugin):
    """
    Evaluates all cookies returned in HTTP response headers for security best practices.
    """

    name = "cookie_security"
    description = (
        "Analyzes cookie security flags (HttpOnly, Secure, SameSite) and detects "
        "insecure sensitive session cookies."
    )
    category = "passive"
    version = "1.0.0"
    priority = 15

    async def run(self, context: ScanContext) -> None:
        """
        Execute cookie security analysis against response data in ``context``.
        """
        raw_cookie_headers = self._extract_raw_cookie_headers(context)

        if not raw_cookie_headers:
            self.log("No Set-Cookie headers found in response — skipping cookie checks.")
            return

        parsed_cookies: list[ParsedCookie] = []
        for header_str in raw_cookie_headers:
            cookie = self._parse_set_cookie(header_str)
            if cookie:
                parsed_cookies.append(cookie)

        if not parsed_cookies:
            self.log("No valid cookies could be parsed from headers.")
            return

        is_https = self._is_target_https(context.target_url)

        for cookie in parsed_cookies:
            self._analyze_cookie(cookie, is_https, context)

        # Store metadata for downstream plugins or reporting
        context.set_metadata(
            "cookies_analyzed",
            [
                {
                    "name": c.name,
                    "httponly": c.httponly,
                    "secure": c.secure,
                    "samesite": c.samesite,
                    "is_sensitive": c.is_sensitive,
                }
                for c in parsed_cookies
            ],
        )

        self.log(
            f"Cookie analysis complete for {len(parsed_cookies)} cookie(s) — "
            f"{len(context.findings)} total finding(s)."
        )

    # ------------------------------------------------------------------
    # Analysis & Finding Generation
    # ------------------------------------------------------------------

    def _analyze_cookie(
        self,
        cookie: ParsedCookie,
        is_https: bool,
        context: ScanContext,
    ) -> None:
        """Evaluate a single cookie and generate appropriate findings."""
        cookie_name = cookie.name
        evidence_snippet = f"Set-Cookie: {cookie.raw_header}"

        # 1. HttpOnly Flag Analysis
        if not cookie.httponly:
            if cookie.is_csrf:
                # CSRF cookies frequently omit HttpOnly by design for Double Submit Cookie JS reading
                self.log(f"Cookie '{cookie_name}' appears to be a CSRF token; HttpOnly omission is common.")
            elif cookie.is_sensitive:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Sensitive Cookie Missing HttpOnly Flag: {cookie_name}",
                        description=(
                            f"The cookie '{cookie_name}' appears to be an authentication or session identifier "
                            f"but was set without the 'HttpOnly' flag. If the application is vulnerable to "
                            f"Cross-Site Scripting (XSS), malicious scripts executing in the browser can read "
                            f"this cookie and hijack the user session."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            f"Add the 'HttpOnly' directive to the Set-Cookie header for '{cookie_name}' "
                            f"(e.g., Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax)."
                        ),
                        evidence=evidence_snippet,
                    )
                )
            elif not cookie.is_analytics:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                        description=(
                            f"The cookie '{cookie_name}' was set without the 'HttpOnly' flag. This allows "
                            f"client-side JavaScript to access the cookie value via 'document.cookie'."
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            f"If '{cookie_name}' does not need to be accessed by client-side JavaScript, "
                            f"set the 'HttpOnly' attribute."
                        ),
                        evidence=evidence_snippet,
                    )
                )

        # 2. Secure Flag Analysis
        if not cookie.secure:
            if is_https:
                if cookie.is_sensitive:
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Sensitive Cookie Missing Secure Flag: {cookie_name}",
                            description=(
                                f"The sensitive cookie '{cookie_name}' was issued over an HTTPS connection "
                                f"without the 'Secure' attribute. Browsers may transmit this cookie over "
                                f"unencrypted HTTP connections if the user follows an unencrypted link or "
                                f"encounters an active network attacker (SSL stripping), exposing credentials."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                f"Add the 'Secure' flag to the Set-Cookie header for '{cookie_name}' so that "
                                f"the browser only transmits it over encrypted HTTPS connections."
                            ),
                            evidence=evidence_snippet,
                        )
                    )
                elif not cookie.is_analytics:
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Cookie Missing Secure Flag: {cookie_name}",
                            description=(
                                f"The cookie '{cookie_name}' was served over HTTPS but lacks the 'Secure' flag, "
                                f"allowing the browser to transmit it over unencrypted HTTP requests."
                            ),
                            severity=Severity.LOW,
                            recommendation=(
                                f"Add the 'Secure' attribute to '{cookie_name}' to restrict its transmission "
                                f"to encrypted HTTPS connections."
                            ),
                            evidence=evidence_snippet,
                        )
                    )

        # 3. SameSite Attribute Analysis
        if cookie.samesite is None:
            if cookie.is_sensitive or cookie.is_csrf:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Sensitive Cookie Missing SameSite Attribute: {cookie_name}",
                        description=(
                            f"The sensitive cookie '{cookie_name}' does not specify a 'SameSite' attribute. "
                            f"Omitting SameSite makes cross-origin request behavior dependent on browser defaults "
                            f"and leaves legacy clients exposed to Cross-Site Request Forgery (CSRF) attacks."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            f"Explicitly configure 'SameSite=Lax' or 'SameSite=Strict' on '{cookie_name}' "
                            f"to prevent the cookie from being sent in untrusted third-party cross-site contexts."
                        ),
                        evidence=evidence_snippet,
                    )
                )
            elif not cookie.is_analytics:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                        description=(
                            f"The cookie '{cookie_name}' does not declare a 'SameSite' attribute."
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            f"Set 'SameSite=Lax' or 'SameSite=Strict' on '{cookie_name}' to clarify cross-site behavior."
                        ),
                        evidence=evidence_snippet,
                    )
                )
        elif cookie.samesite.lower() == "none" and not cookie.secure:
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Insecure SameSite=None Without Secure Flag: {cookie_name}",
                    description=(
                        f"The cookie '{cookie_name}' specifies 'SameSite=None' but does not specify the "
                        f"'Secure' attribute. Modern web standards require all 'SameSite=None' cookies to "
                        f"be marked 'Secure'; non-compliant cookies are rejected by modern browsers and "
                        f"expose cross-site transmission to plaintext inspection."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        f"Ensure all cookies with 'SameSite=None' also have the 'Secure' attribute set, "
                        f"or switch to 'SameSite=Lax' if cross-site usage is not required."
                    ),
                    evidence=evidence_snippet,
                )
            )

        # 4. Cookie Prefix Validation (__Secure- and __Host-)
        if cookie_name.startswith("__Secure-"):
            if not cookie.secure:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Invalid __Secure- Cookie Prefix: {cookie_name}",
                        description=(
                            f"The cookie '{cookie_name}' uses the '__Secure-' name prefix but lacks the 'Secure' "
                            f"attribute. Browsers implementing cookie prefixes will reject this cookie."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=f"Add the 'Secure' attribute to '{cookie_name}'.",
                        evidence=evidence_snippet,
                    )
                )
        elif cookie_name.startswith("__Host-"):
            prefix_issues = []
            if not cookie.secure:
                prefix_issues.append("missing 'Secure' attribute")
            if cookie.domain is not None:
                prefix_issues.append("must not have a 'Domain' attribute")
            if cookie.path != "/":
                prefix_issues.append("must have 'Path=/'")

            if prefix_issues:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Invalid __Host- Cookie Prefix: {cookie_name}",
                        description=(
                            f"The cookie '{cookie_name}' uses the '__Host-' prefix but violates RFC 6265bis "
                            f"requirements: {', '.join(prefix_issues)}. Modern browsers will reject this cookie."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            f"Ensure '{cookie_name}' is set with 'Secure', 'Path=/', and without any 'Domain' attribute."
                        ),
                        evidence=evidence_snippet,
                    )
                )

    # ------------------------------------------------------------------
    # Parsing Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_raw_cookie_headers(context: ScanContext) -> list[str]:
        """
        Extract raw Set-Cookie header strings from the scan context.
        Supports httpx.Response headers (with get_list) as well as dictionary headers.
        """
        results: list[str] = []

        if context.response is not None and hasattr(context.response, "headers"):
            headers_obj = context.response.headers
            if hasattr(headers_obj, "get_list"):
                results.extend(headers_obj.get_list("set-cookie"))
            elif "set-cookie" in headers_obj:
                results.append(headers_obj["set-cookie"])

        # Fallback to context.headers if response object was unavailable or empty
        if not results and context.headers:
            for k, v in context.headers.items():
                if k.lower() == "set-cookie" and v:
                    results.append(v)

        return results

    @classmethod
    def _parse_set_cookie(cls, header_str: str) -> ParsedCookie | None:
        """Parse a single Set-Cookie header string into a structured ParsedCookie."""
        parts = [p.strip() for p in header_str.split(";") if p.strip()]
        if not parts:
            return None

        # First part is name=value
        name_val = parts[0]
        if "=" in name_val:
            name, value = name_val.split("=", 1)
        else:
            name, value = name_val, ""

        name = name.strip()
        value = value.strip()
        if not name:
            return None

        cookie = ParsedCookie(
            name=name,
            value=value,
            raw_header=header_str,
            is_sensitive=bool(_SENSITIVE_COOKIE_NAME_REGEX.search(name)),
            is_csrf=bool(_CSRF_COOKIE_NAME_REGEX.search(name)),
            is_analytics=name.lower() in _ANALYTICS_COOKIE_NAMES or name.startswith(("_ga", "_gid", "__cf")),
        )

        for attr in parts[1:]:
            attr_lower = attr.lower()
            if attr_lower == "httponly":
                cookie.httponly = True
            elif attr_lower == "secure":
                cookie.secure = True
            elif attr_lower.startswith("samesite="):
                cookie.samesite = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("domain="):
                cookie.domain = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("path="):
                cookie.path = attr.split("=", 1)[1].strip()

        return cookie

    @staticmethod
    def _is_target_https(target_url: str) -> bool:
        """Determine if target URL scheme is HTTPS."""
        try:
            parsed = urlparse(target_url)
            return parsed.scheme.lower() == "https"
        except Exception:
            return target_url.lower().startswith("https://")
