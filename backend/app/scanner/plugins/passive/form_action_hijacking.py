"""
app/scanner/plugins/passive/form_action_hijacking.py
---------------------------------------------------
Form Action Hijacking & Insecure Transport Submission Analysis Plugin.

Safely evaluates HTML <form> elements and Content-Security-Policy 'form-action'
directives to identify insecure transport downgrades (HTTPS to HTTP submissions),
external cross-origin credential harvesting, dangerous URI schemes, and missing
form-action defense-in-depth policies.

Safety & Guardrails:
    - Purely passive HTML and header analysis.
    - NEVER submits forms, credentials, or payments.
    - NEVER attempts authentication or state-changing operations.
    - Resolves relative form actions safely against target URL origin.
    - Redacts all query parameters and sensitive values in findings.

Severity Logic:
    - HIGH: Sensitive form (passwords, tokens, payment, auth) submits data to unencrypted HTTP,
            a dangerous URI scheme (e.g. javascript:), or an external cross-origin domain.
    - MEDIUM: General form submits cross-origin without protection, or CSP form-action is wildcard (*).
    - LOW: Sensitive application page is completely missing a CSP form-action restriction.
    - NONE: Secure same-origin HTTPS forms with valid restrictive policies.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Dangerous non-web URI schemes in form action
_DANGEROUS_FORM_SCHEMES: tuple[str, ...] = (
    "javascript:",
    "data:",
    "file:",
    "vbscript:",
)

# Regex to match HTML <form ...> ... </form> blocks
_FORM_BLOCK_PATTERN: re.Pattern[str] = re.compile(
    r"""<form\b([^>]*)>(.*?)</form>""",
    re.IGNORECASE | re.DOTALL,
)

# Regex to extract form attributes
_ACTION_ATTR_PATTERN: re.Pattern[str] = re.compile(
    r"""\baction\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)
_METHOD_ATTR_PATTERN: re.Pattern[str] = re.compile(
    r"""\bmethod\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)

# Regex to detect sensitive input fields inside a form
_SENSITIVE_INPUT_PATTERN: re.Pattern[str] = re.compile(
    r"""(?i)(?:type=["'](?:password)["']|name=["'](?:password|passwd|pwd|token|auth|"""
    r"""otp|card|cvv|account|pin|payment|ssn|secret|creditcard|login)["']|"""
    r"""id=["'](?:password|passwd|pwd|token|auth|otp|card|cvv|account|pin)["'])"""
)


class FormActionHijackingPlugin(BasePlugin):
    """
    Evaluates form action destinations and CSP form-action directives for security weaknesses.
    """

    name = "form_action_hijacking"
    description = (
        "Analyzes HTML form action targets for unencrypted HTTP submissions, cross-origin data leakage, "
        "dangerous URI schemes, and missing Content-Security-Policy form-action restrictions."
    )
    category = "passive"
    version = "1.0.0"
    priority = 71

    async def run(self, context: ScanContext) -> None:
        """
        Scan context.html and context.headers for insecure form actions and missing CSP policies.
        """
        if not context.html or not context.target_url:
            self.log("No HTML content or target URL available — skipping form action hijacking analysis.")
            return

        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}".lower()
        target_hostname = (parsed_target.hostname or "").lower()
        target_is_https = parsed_target.scheme.lower() == "https"

        html_body = context.html
        headers = {k.lower(): v for k, v in context.headers.items()}

        # 1. Parse CSP form-action directive
        csp_headers = self._extract_csp_headers(headers)
        form_action_sources, has_form_action_directive = self._parse_csp_form_action(csp_headers)

        # 2. Extract and analyze all HTML forms
        forms = _FORM_BLOCK_PATTERN.findall(html_body)
        if not forms:
            self.log("No HTML form elements found in target page.")
            return

        has_sensitive_form_on_page = False
        seen_actions: set[str] = set()

        for form_attrs, form_content in forms:
            action_match = _ACTION_ATTR_PATTERN.search(form_attrs)
            raw_action = action_match.group(1).strip() if action_match else ""
            method_match = _METHOD_ATTR_PATTERN.search(form_attrs)
            method = method_match.group(1).upper() if method_match else "GET"

            is_sensitive_form = bool(_SENSITIVE_INPUT_PATTERN.search(form_content) or _SENSITIVE_INPUT_PATTERN.search(form_attrs))
            if is_sensitive_form:
                has_sensitive_form_on_page = True

            action_key = f"{raw_action}|{method}|{is_sensitive_form}"
            if action_key in seen_actions:
                continue
            seen_actions.add(action_key)

            # Check 1: Dangerous URI Scheme in form action (javascript:, data:, file:)
            action_lower = raw_action.lower()
            for d_scheme in _DANGEROUS_FORM_SCHEMES:
                if action_lower.startswith(d_scheme):
                    evidence = (
                        f"Page URL: {self._redact_url(target_url)}\n"
                        f"Form Action: {raw_action}\n"
                        f"Form Method: {method}\n"
                        f"Form Classification: {'Sensitive Form' if is_sensitive_form else 'Standard Form'}\n"
                        f"Issue: Form submission executes client-side script or unsafe URI scheme ({d_scheme.rstrip(':')})."
                    )
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Dangerous Form Action URI Scheme ({d_scheme.rstrip(':')})",
                            description=(
                                f"The form on '{self._redact_url(target_url)}' specifies a dangerous URI scheme in its action "
                                f"attribute ('{raw_action}'). When submitted by the user, the browser may execute inline JavaScript "
                                f"or access local resources, leading to Client-Side Form Action Hijacking or Cross-Site Scripting (XSS)."
                            ),
                            severity=Severity.HIGH,
                            recommendation="Ensure form actions specify valid HTTP/HTTPS URLs and never use 'javascript:' or 'data:' schemes.",
                            evidence=evidence,
                        )
                    )
                    return

            # Resolve relative action against target URL
            resolved_action = urljoin(target_url, raw_action) if raw_action else target_url
            parsed_action = urlparse(resolved_action)
            action_scheme = parsed_action.scheme.lower()
            action_hostname = (parsed_action.hostname or "").lower()

            # Check 2: Insecure Transport Submission (HTTPS page submitting to unencrypted HTTP)
            if target_is_https and action_scheme == "http":
                severity = Severity.HIGH if is_sensitive_form else Severity.MEDIUM
                evidence = (
                    f"Page URL (HTTPS): {self._redact_url(target_url)}\n"
                    f"Insecure Form Action: {self._redact_url(resolved_action)}\n"
                    f"Form Method: {method}\n"
                    f"Sensitive Inputs Detected: {'Yes (Password / Credentials)' if is_sensitive_form else 'No'}\n"
                    f"Issue: Form data submitted over unencrypted HTTP."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Insecure Form Submission over Unencrypted HTTP ({'Credentials Exposed' if is_sensitive_form else 'Transport Downgrade'})",
                        description=(
                            f"The HTTPS page at '{self._redact_url(target_url)}' contains a form that submits data to an "
                            f"unencrypted HTTP destination ('{self._redact_url(resolved_action)}'). "
                            f"Network eavesdroppers and Man-in-the-Middle (MitM) attackers can intercept credentials or user inputs in transit."
                        ),
                        severity=severity,
                        recommendation="Update form actions to use HTTPS destinations exclusively and enforce HSTS.",
                        evidence=evidence,
                    )
                )
                return

            # Check 3: Cross-Origin Submission to External Origin
            if action_hostname and action_hostname != target_hostname:
                if is_sensitive_form:
                    evidence = (
                        f"Page Origin: {target_origin}\n"
                        f"External Form Action: {self._redact_url(resolved_action)}\n"
                        f"Form Method: {method}\n"
                        f"Sensitive Inputs: Password / Credential / Token fields present.\n"
                        f"CSP form-action: {' '.join(form_action_sources) if has_form_action_directive else 'Not Set'}"
                    )
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title="Sensitive Form Submitting to External Origin (Cross-Origin Action)",
                            description=(
                                f"The sensitive form on '{self._redact_url(target_url)}' submits user credentials or authentication "
                                f"data to a third-party external origin ('{action_hostname}'). "
                                f"If this destination is unintended or malicious, user credentials will be harvested by the external server."
                            ),
                            severity=Severity.HIGH,
                            recommendation="Ensure sensitive forms submit only to trusted same-origin endpoints or verified SSO providers.",
                            evidence=evidence,
                        )
                    )
                    return

        # 3. Analyze CSP form-action Directive
        if has_form_action_directive:
            # Check for Wildcard in form-action
            if "*" in form_action_sources:
                evidence = (
                    f"Page URL: {self._redact_url(target_url)}\n"
                    f"Content-Security-Policy: form-action {' '.join(form_action_sources)}\n"
                    f"Issue: Wildcard '*' in form-action permits form submissions to any external domain."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Permissive CSP form-action Directive (Wildcard Allowed)",
                        description=(
                            "The Content-Security-Policy specifies 'form-action *', allowing forms to submit data to any arbitrary "
                            "third-party destination. Attackers exploiting DOM injection or XSS can retarget forms to attacker-controlled origins."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation="Restrict CSP 'form-action' to 'self' and explicit trusted authentication origins.",
                        evidence=evidence,
                    )
                )
        else:
            # Missing form-action on sensitive application page
            if has_sensitive_form_on_page:
                evidence = (
                    f"Page URL: {self._redact_url(target_url)}\n"
                    f"Content-Security-Policy form-action: Not configured\n"
                    f"Sensitive Forms Identified: Yes (Login / Credential fields detected)\n"
                    f"Defense-in-Depth Assessment: Absence of form-action restriction leaves forms vulnerable to injection retargeting."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Missing Content-Security-Policy form-action Restriction on Sensitive Page",
                        description=(
                            f"The page at '{self._redact_url(target_url)}' contains sensitive interactive forms (login/credentials) "
                            f"but does not enforce a Content-Security-Policy 'form-action' directive. "
                            f"Without 'form-action', HTML injection attacks can alter form targets to hijack user credentials upon submission."
                        ),
                        severity=Severity.LOW,
                        recommendation="Add 'Content-Security-Policy: form-action 'self'' to restrict form submission targets.",
                        evidence=evidence,
                    )
                )

    # ------------------------------------------------------------------
    # Parsing Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_csp_headers(headers: dict[str, str]) -> list[str]:
        """Extract all CSP response headers."""
        results = []
        for k, v in headers.items():
            if k in ("content-security-policy", "content-security-policy-report-only"):
                results.append(v)
        return results

    @staticmethod
    def _parse_csp_form_action(csp_headers: list[str]) -> tuple[list[str], bool]:
        """Parse CSP headers for form-action directives."""
        sources: list[str] = []
        has_directive = False

        for header in csp_headers:
            for piece in header.split(";"):
                piece = piece.strip()
                if piece.lower().startswith("form-action"):
                    has_directive = True
                    args = piece[len("form-action"):].strip().split()
                    sources.extend(args)

        return sources, has_directive

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
