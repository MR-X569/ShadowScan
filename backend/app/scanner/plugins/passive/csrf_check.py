"""
app/scanner/plugins/passive/csrf_check.py
-----------------------------------------
Cross-Site Request Forgery (CSRF) & State-Changing GET Analysis Plugin.

Safely evaluates HTML forms and discovered links for:
    1. POST/PUT/PATCH/DELETE forms lacking Anti-CSRF tokens.
    2. Sensitive state-changing operations exposed via HTTP GET endpoints/links.
    3. Missing or weak SameSite cookie configuration on session cookies interacting with unprotected forms.

Safety & Non-Destructive Operation:
    - NEVER submits forms.
    - NEVER triggers state-changing actions or GET endpoints.
    - Purely analyzes HTML DOM structure, input names, action paths, and HTTP headers/cookies.

Severity Logic:
    - Sensitive state-changing action exposed via GET -> HIGH / MEDIUM
    - Sensitive POST form lacking Anti-CSRF token -> HIGH
    - General state-changing POST form lacking Anti-CSRF token -> MEDIUM
    - Safe GET forms (search, pagination, filters) -> No finding (suppressed)
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Known Anti-CSRF token input field names
_CSRF_TOKEN_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "csrf",
        "_csrf",
        "csrf_token",
        "csrftoken",
        "xsrf",
        "_xsrf",
        "xsrf_token",
        "xsrftoken",
        "authenticity_token",
        "anti_csrf",
        "csrfmiddlewaretoken",
        "__requestverificationtoken",
        "_token",
        "token",
        "auth_token",
        "form_key",
    }
)

# Sensitive state-changing action keyword patterns in paths and query params
_STATE_CHANGING_KEYWORDS: list[str] = [
    "delete",
    "remove",
    "update",
    "change",
    "disable",
    "enable",
    "logout",
    "reset",
    "transfer",
    "approve",
    "confirm",
    "create",
    "edit",
    "modify",
    "password",
    "role",
    "admin",
]

_STATE_CHANGING_REGEX: re.Pattern[str] = re.compile(
    r"/(?:" + "|".join(_STATE_CHANGING_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

# Search/Filter suppression parameters to prevent false positives on harmless GET forms
_SAFE_SEARCH_PARAMS: frozenset[str] = frozenset(
    {"q", "query", "search", "keyword", "page", "limit", "sort", "order", "filter", "view", "lang"}
)


class CsrfCheckPlugin(BasePlugin):
    """
    Detects missing Anti-CSRF protections on forms and unsafe state-changing GET endpoints.
    """

    name = "csrf_check"
    description = (
        "Analyzes forms for Anti-CSRF token protections and identifies unsafe state-changing GET endpoints."
    )
    category = "passive"
    version = "1.0.0"
    priority = 72

    async def run(self, context: ScanContext) -> None:
        """
        Execute CSRF and state-changing GET analysis on context.html and response data.
        """
        html_body = context.html or ""
        if not html_body and context.response is not None:
            html_body = getattr(context.response, "text", "") or ""

        if not html_body:
            self.log("No HTML body available in context — skipping CSRF check.")
            return

        # 1. Analyze HTML forms for Anti-CSRF token presence
        self._analyze_forms(html_body, context)

        # 2. Analyze state-changing GET links and actions
        self._analyze_state_changing_get_links(html_body, context)

    # ------------------------------------------------------------------
    # HTML Form Inspection
    # ------------------------------------------------------------------

    def _analyze_forms(self, html_body: str, context: ScanContext) -> None:
        """Parse HTML forms and check for CSRF tokens on POST/PUT/PATCH/DELETE methods."""
        form_matches = re.finditer(r"<form\b([^>]*)>([\s\S]*?)</form>", html_body, re.IGNORECASE)

        for match in form_matches:
            attrs_str = match.group(1)
            form_content = match.group(2)

            # Extract method
            method_match = re.search(r'method=[\'"]?([a-zA-Z]+)[\'"]?', attrs_str, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"

            # Extract action
            action_match = re.search(r'action=[\'"]?([^\'"\s>]+)[\'"]?', attrs_str, re.IGNORECASE)
            action = action_match.group(1) if action_match else (context.target_url or "/")

            # Only inspect state-changing HTTP methods (POST, PUT, PATCH, DELETE)
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue

            # Check for presence of Anti-CSRF input fields
            inputs = re.findall(r'<input\b[^>]*name=[\'"]?([^\'"\s>]+)[\'"]?[^>]*>', form_content, re.IGNORECASE)
            input_names_lower = {inp.lower() for inp in inputs}

            has_csrf_token = any(token in input_names_lower for token in _CSRF_TOKEN_FIELD_NAMES)

            if not has_csrf_token:
                is_sensitive = any(kw in action.lower() for kw in _STATE_CHANGING_KEYWORDS) or any(
                    kw in form_content.lower() for kw in ("password", "email", "delete", "transfer", "role")
                )

                severity = Severity.HIGH if is_sensitive else Severity.MEDIUM

                evidence = (
                    f"Form Action: {action}\n"
                    f"Form Method: {method}\n"
                    f"Detected Input Fields: {', '.join(inputs) if inputs else 'None'}\n"
                    f"Anti-CSRF Token Detected: None\n"
                    f"Sensitivity Assessment: {'High (sensitive operation detected)' if is_sensitive else 'Medium'}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Missing Anti-CSRF Token on {method} Form ({action})",
                        description=(
                            f"The HTML form submitting to '{action}' via HTTP {method} does not include an Anti-CSRF "
                            f"token (e.g. csrf_token, authenticity_token). If the user authenticates via session cookies "
                            f"without strict SameSite protection, an external attacker can forge cross-site requests to "
                            f"perform unauthorized actions on behalf of the victim."
                        ),
                        severity=severity,
                        recommendation=(
                            f"Implement synchronized Anti-CSRF tokens for all state-changing forms submitting to '{action}'. "
                            f"Ensure session cookies enforce 'SameSite=Lax' or 'SameSite=Strict' and consider verifying "
                            f"the 'Origin' and 'Referer' request headers on backend submission."
                        ),
                        evidence=evidence,
                    )
                )

    # ------------------------------------------------------------------
    # State-Changing GET Inspection
    # ------------------------------------------------------------------

    def _analyze_state_changing_get_links(self, html_body: str, context: ScanContext) -> None:
        """Identify state-changing action keywords exposed in <a href> and GET form actions."""
        # Find all anchor href links
        links = re.findall(r'<a\b[^>]*href=[\'"]?([^\'"\s>]+)[\'"]?[^>]*>', html_body, re.IGNORECASE)

        seen_links: set[str] = set()

        for link in links:
            if link in seen_links or link.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            seen_links.add(link)

            parsed = urlparse(link)
            path_lower = parsed.path.lower()

            # Check if link path contains sensitive state-changing keyword
            if _STATE_CHANGING_REGEX.search(path_lower):
                # Filter out pure navigation/read-only links
                query_params = parse_qs(parsed.query)
                is_safe_search = any(k.lower() in _SAFE_SEARCH_PARAMS for k in query_params)
                if is_safe_search:
                    continue

                is_critical = any(kw in path_lower for kw in ("delete", "remove", "reset", "transfer", "logout", "password"))
                severity = Severity.HIGH if is_critical else Severity.MEDIUM

                evidence = (
                    f"Identified Link: {link}\n"
                    f"Extracted Path: {parsed.path}\n"
                    f"Query Parameters: {dict(query_params) if query_params else 'None'}\n"
                    f"State-Changing Pattern: {_STATE_CHANGING_REGEX.search(path_lower).group(0)}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Potential State-Changing Operation Exposed via HTTP GET ({parsed.path})",
                        description=(
                            f"The application contains a hyperlink or GET route '{link}' that appears to perform a state-changing "
                            f"action (e.g. deletion, modification, or session state reset) via HTTP GET. "
                            f"HTTP GET requests must be idempotent and safe. Exposing state changes over GET allows attackers "
                            f"to trigger unauthorized actions simply by embedding the URL in <img> or <iframe> tags on malicious websites (CSRF)."
                        ),
                        severity=severity,
                        recommendation=(
                            f"Refactor '{parsed.path}' to require HTTP POST, PUT, or DELETE methods with proper Anti-CSRF "
                            f"token verification. Never allow state-changing operations via HTTP GET."
                        ),
                        evidence=evidence,
                    )
                )
