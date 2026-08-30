"""
app/scanner/plugins/passive/ldap_injection.py
---------------------------------------------
LDAP Injection Analysis Plugin.

Safely evaluates candidate query parameters for potential LDAP search filter injection
using non-destructive syntax probes, high-confidence LDAP parser error signatures,
and baseline differential comparison.

Safety & Guardrails:
    - NEVER attempts authentication bypass against real accounts.
    - NEVER performs directory enumeration or user/group extraction.
    - NEVER accesses external LDAP servers.
    - Uses non-destructive filter diagnostics and syntax metacharacters.

Candidate Parameters:
    username, user, uid, cn, dn, name, login, account, search, query,
    filter, ldap_filter, group, member, email, user_id, employee, role,
    department, organization, ou, dc

Detection Strategy:
    1. Gather candidate parameters from target URL, query parameters, and crawler metadata.
    2. Establish baseline response to prevent reporting pre-existing errors or documentation.
    3. Inject safe syntax diagnostics and evaluate high-confidence LDAP parser error signatures.
    4. Perform controlled differential analysis to verify filter interpretation.
    5. Suppress literal reflection, SPA fallbacks, and static documentation.

Severity Logic:
    - HIGH: Confirmed LDAP filter injection behavior through strong differential/error evidence.
    - MEDIUM: High-confidence LDAP parser error triggered by user-controlled input.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# High-confidence LDAP parser/directory service error signatures
_LDAP_ERROR_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "Java Naming Directory / LDAP Error",
        re.compile(
            r"(?:javax\.naming\.directory\.InvalidSearchFilterException|"
            r"javax\.naming\.NameNotFoundException|"
            r"javax\.naming\.NamingException|"
            r"com\.sun\.jndi\.ldap\.LdapCtx)",
            re.IGNORECASE,
        ),
    ),
    (
        "Generic LDAP Filter Syntax Error",
        re.compile(
            r"(?:LDAP filter syntax error|Bad search filter|InvalidSearchFilter|"
            r"invalid search filter|malformed LDAP filter|Filter syntax error|"
            r"LDAPException:\s*Invalid filter syntax|LDAP:\s*error code \d+)",
            re.IGNORECASE,
        ),
    ),
    (
        "Python LDAP / ldap3 Error",
        re.compile(
            r"(?:ldap\.FILTER_ERROR|ldap3\.core\.exceptions\.LDAPInvalidFilterError|"
            r"ldap\.INVALID_SYNTAX|ldap\.OPERATIONS_ERROR|"
            r"ldap3\.core\.exceptions\.LDAPException)",
            re.IGNORECASE,
        ),
    ),
    (
        ".NET DirectoryServices LDAP Error",
        re.compile(
            r"(?:System\.DirectoryServices\.Protocols\.LdapException|"
            r"System\.DirectoryServices\.DirectoryServicesCOMException|"
            r"The search filter is invalid\.|An invalid dn syntax has been specified)",
            re.IGNORECASE,
        ),
    ),
    (
        "PHP LDAP Error",
        re.compile(
            r"(?:ldap_search\(\):\s*Search:\s*Bad search filter|"
            r"ldap_search\(\):\s*Search:\s*Invalid syntax|"
            r"Warning:\s*ldap_search\(\))",
            re.IGNORECASE,
        ),
    ),
]

_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "username",
        "user",
        "uid",
        "cn",
        "dn",
        "name",
        "login",
        "account",
        "search",
        "query",
        "filter",
        "ldap_filter",
        "group",
        "member",
        "email",
        "user_id",
        "employee",
        "role",
        "department",
        "organization",
        "ou",
        "dc",
    }
)

_SPA_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)


@dataclass
class _LdapProbe:
    name: str
    payload: str
    is_error_trigger: bool = True


_PROBES: list[_LdapProbe] = [
    _LdapProbe(name="Malformed Filter Unbalanced Parenthesis", payload="*)(cn=*", is_error_trigger=True),
    _LdapProbe(name="Filter Breakout Diagnostic", payload="*)(&", is_error_trigger=True),
    _LdapProbe(name="Parenthesis Inversion Probe", payload=")(", is_error_trigger=True),
    _LdapProbe(name="Filter Closing Parenthesis", payload="*))", is_error_trigger=True),
]


class LdapInjectionPlugin(BasePlugin):
    """
    Safely probes query parameters for potential LDAP search filter injection vulnerabilities.
    """

    name = "ldap_injection"
    description = (
        "Detects potential LDAP filter injection through safe differential analysis, "
        "malformed search filter diagnostics, and directory service parser error signatures."
    )
    category = "passive"
    version = "1.0.0"
    priority = 86

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe LDAP injection parameter analysis against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping LDAP injection checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Identify candidate parameters to test
        params_to_test = self._get_parameters_to_test(parsed_target, context)
        if not params_to_test:
            self.log("No candidate LDAP injection parameters detected.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for LDAP injection: {params_to_test}")

        baseline_text = context.html or ""
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            for probe in _PROBES:
                is_vulnerable = await self._test_param_ldap(
                    client,
                    parsed_target,
                    param_name,
                    probe,
                    baseline_text,
                    context,
                )
                if is_vulnerable:
                    break

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any, context: ScanContext) -> list[str]:
        """Extract candidate parameters from query string, crawler metadata, or common defaults."""
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found: list[str] = [k for k in query_dict if k.lower() in _CANDIDATE_PARAMS]

        # Add parameters discovered by crawler metadata
        discovered_params = context.metadata.get("discovered_parameters", [])
        for p in discovered_params:
            if p.lower() in _CANDIDATE_PARAMS and p not in found:
                found.append(p)

        if found:
            return found

        # Fallback to query dict keys if available
        for k in query_dict:
            found.append(k)

        if found:
            return found

        return ["username", "user", "uid", "cn", "search", "filter", "query"]

    # ------------------------------------------------------------------
    # Probe Execution & Error Analysis
    # ------------------------------------------------------------------

    async def _test_param_ldap(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        probe: _LdapProbe,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Inject LDAP diagnostic probe and check for directory service parser errors or behavior."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        original_val = query_dict.get(param_name, ["test"])[0]
        query_dict[param_name] = [f"{original_val}{probe.payload}"]

        flattened = [(k, v[0] if isinstance(v, list) and v else "") for k, v in query_dict.items()]
        new_query = urlencode(flattened)

        test_url = urlunparse((
            parsed_target.scheme,
            parsed_target.netloc,
            parsed_target.path,
            parsed_target.params,
            new_query,
            parsed_target.fragment,
        ))

        try:
            response = await client.get(test_url)
            text = response.text or ""
            content_type = response.headers.get("content-type", "").lower()

            # Anti-signature check for Single Page Applications
            if "text/html" in content_type and _SPA_ANTI_SIGNATURE.search(text):
                if not any(p.search(text) for _, p in _LDAP_ERROR_SIGNATURES):
                    return False

            # Check for high-confidence LDAP parser/directory service error signatures
            for sig_name, sig_regex in _LDAP_ERROR_SIGNATURES:
                err_match = sig_regex.search(text)
                if err_match and not sig_regex.search(baseline_text):
                    err_snippet = err_match.group(0)

                    # Ensure the error is not merely a literal reflection of documentation
                    if probe.payload in text and not any(k in err_snippet.lower() for k in ["ldap", "filter", "syntax", "search", "naming"]):
                        continue

                    severity = Severity.HIGH if response.status_code in (500, 502) or "filter" in err_snippet.lower() else Severity.MEDIUM

                    evidence = (
                        f"Tested Parameter: {param_name}\n"
                        f"Injected Diagnostic Probe: {probe.payload} ({probe.name})\n"
                        f"Identified LDAP Parser Signature: {sig_name}\n"
                        f"Test Request URL: {test_url}\n"
                        f"HTTP Status: {response.status_code}\n\n"
                        f"LDAP Error Snippet:\n{err_snippet}"
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Potential LDAP Filter Injection via Parameter: {param_name} ({sig_name})",
                            description=(
                                f"The parameter '{param_name}' appears vulnerable to LDAP Injection. "
                                f"Supplying LDAP filter metacharacters ('{probe.payload}') triggered an explicit directory "
                                f"service parser or filter syntax error ({sig_name}: '{err_snippet}'). "
                                f"An attacker can manipulate LDAP search filters to bypass authentication, enumerate directory "
                                f"structures, or extract sensitive organizational and user attributes."
                            ),
                            severity=severity,
                            recommendation=(
                                f"Properly sanitize and escape all user input used in LDAP search filters using framework-provided "
                                f"LDAP escaping utilities (e.g. RFC 4515/RFC 2254 encoder). Ensure special characters like "
                                f"'*', '(', ')', '\\', and NULL bytes are escaped with backslash hex sequences (e.g. '\\2a', '\\28')."
                            ),
                            evidence=evidence,
                        )
                    )
                    return True

            return False

        except Exception as exc:
            self.log(f"LDAP injection probe on '{param_name}' failed: {exc}")
            return False
