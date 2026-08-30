"""
app/scanner/plugins/passive/open_redirect.py
--------------------------------------------
Open Redirect Analysis Plugin — detects unvalidated external URL redirection
vulnerabilities in target query parameters.

Checks performed:
    - Identifies candidate redirection parameters (redirect, url, next, return_to, etc.)
    - Safe non-destructive injection of controlled test destination (https://example.com/)
    - Protocol-relative destination probe (//example.com/)
    - Inspects HTTP 301, 302, 303, 307, 308 response status codes and Location header
    - Suppresses safe same-origin / internal application redirects to prevent false positives

Severity Logic:
    - Arbitrary external redirect confirmed -> HIGH
    - Protocol-relative / partially filtered external redirect -> MEDIUM
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Standard safe test destination (RFC 2606 reserved example domain)
_TEST_DESTINATION_ABSOLUTE: str = "https://example.com/"
_TEST_DESTINATION_PROTOCOL_RELATIVE: str = "//example.com/"

# Candidate redirection query parameter names
_REDIRECT_PARAM_CANDIDATES: frozenset[str] = frozenset(
    {
        "redirect",
        "redirect_uri",
        "redirect_url",
        "url",
        "next",
        "next_url",
        "return",
        "return_url",
        "return_to",
        "continue",
        "destination",
        "dest",
        "target",
        "goto",
        "out",
        "view",
        "link",
        "r",
        "u",
    }
)

# HTTP redirect status codes
_REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})


class OpenRedirectPlugin(BasePlugin):
    """
    Safely tests URL parameters for unvalidated external destination redirection.
    """

    name = "open_redirect"
    description = (
        "Detects unvalidated open redirection vulnerabilities in target URL query parameters."
    )
    category = "passive"
    version = "1.0.0"
    priority = 60

    async def run(self, context: ScanContext) -> None:
        """
        Execute open redirect analysis against context.target_url using context.session.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping open redirect checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_hostname = parsed_target.hostname or ""

        # 1. Collect parameters to test
        params_to_test = self._get_parameters_to_test(parsed_target)
        if not params_to_test:
            self.log("No redirect parameters detected on target URL.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for open redirect: {params_to_test}")

        tested_params: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested_params:
                continue
            tested_params.add(param_name)

            # Test probe 1: Absolute HTTPS URL
            is_vuln, status_code, location, evidence = await self._test_param_redirect(
                client,
                parsed_target,
                param_name,
                _TEST_DESTINATION_ABSOLUTE,
                target_hostname,
            )

            if is_vuln:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Open Redirect Vulnerability via Parameter: {param_name}",
                        description=(
                            f"The target application accepts an unvalidated external URL in the '{param_name}' "
                            f"query parameter and redirects the client via HTTP {status_code} to an arbitrary domain. "
                            f"Attackers frequently exploit open redirects in phishing campaigns to lend credibility "
                            f"to malicious links, bypassing email spam filters and OAuth authorization workflows."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            f"Implement strict server-side validation for the '{param_name}' parameter. "
                            f"Restrict redirection to a whitelist of relative internal paths (e.g., verifying "
                            f"the path starts with '/' and not '//') or trusted explicit domains."
                        ),
                        evidence=evidence,
                    )
                )
                continue  # Avoid duplicate finding on same param

            # Test probe 2: Protocol-relative URL (//example.com/)
            is_vuln_rel, status_code_rel, location_rel, evidence_rel = await self._test_param_redirect(
                client,
                parsed_target,
                param_name,
                _TEST_DESTINATION_PROTOCOL_RELATIVE,
                target_hostname,
            )

            if is_vuln_rel:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Open Redirect via Protocol-Relative URL: {param_name}",
                        description=(
                            f"The parameter '{param_name}' allows protocol-relative external redirects "
                            f"('{_TEST_DESTINATION_PROTOCOL_RELATIVE}'). While absolute URLs might be restricted, "
                            f"the application fails to filter protocol-relative syntax, allowing attackers to "
                            f"redirect users to malicious external sites."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            f"Ensure validation rejects protocol-relative URLs starting with '//' or '\\\\' "
                            f"when validating redirection paths."
                        ),
                        evidence=evidence_rel,
                    )
                )

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any) -> list[str]:
        """
        Identify candidate redirection parameters from URL query string or common defaults.
        """
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found_in_url = [k for k in query_dict if k.lower() in _REDIRECT_PARAM_CANDIDATES]

        if found_in_url:
            return found_in_url

        # If query string has any parameters, check all of them against candidate patterns
        for k in query_dict:
            k_lower = k.lower()
            if any(cand in k_lower for cand in ("redirect", "url", "next", "return", "dest", "target")):
                found_in_url.append(k)

        if found_in_url:
            return found_in_url

        # If target has a path that suggests auth/login/redirect or has no query, test top candidates
        top_candidates = ["redirect", "url", "next", "return_to", "destination", "continue"]
        return top_candidates

    # ------------------------------------------------------------------
    # Probe Execution & Location Header Verification
    # ------------------------------------------------------------------

    @classmethod
    async def _test_param_redirect(
        cls,
        client: Any,
        parsed_target: Any,
        param_name: str,
        test_payload: str,
        target_hostname: str,
    ) -> tuple[bool, int, str, str]:
        """
        Inject payload into param, send request with follow_redirects=False, and inspect Location header.
        Returns: (is_vulnerable, status_code, location_header, evidence_string)
        """
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        query_dict[param_name] = [test_payload]

        # Flatten list values to query string
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
            response = await client.get(test_url, follow_redirects=False)

            if response.status_code in _REDIRECT_STATUS_CODES:
                location = response.headers.get("location", "").strip()

                if not location:
                    return False, response.status_code, "", ""

                is_external = cls._is_external_redirect(location, target_hostname)

                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Injected Payload: {test_payload}\n"
                    f"Test Request URL: {test_url}\n"
                    f"Response Status: HTTP {response.status_code}\n"
                    f"Response Location Header: {location}\n"
                    f"Redirect Evaluation: External destination confirmed ('example.com')"
                )

                if is_external:
                    return True, response.status_code, location, evidence

            return False, response.status_code, "", ""

        except Exception:
            return False, 0, "", ""

    @staticmethod
    def _is_external_redirect(location: str, target_hostname: str) -> bool:
        """
        Verifies if Location header points to an external destination rather than an internal/same-origin path.
        """
        location_lower = location.lower().strip()

        # Check if Location points to our test destination
        if "example.com" not in location_lower:
            return False

        parsed_loc = urlparse(location)

        # 1. Absolute URL check: e.g. https://example.com/
        if parsed_loc.netloc:
            loc_host = parsed_loc.hostname or ""
            if loc_host == "example.com" or loc_host.endswith(".example.com"):
                # Ensure it's not actually the target host
                if loc_host.lower() != target_hostname.lower():
                    return True

        # 2. Protocol-relative check: //example.com/
        if location_lower.startswith("//example.com") or location_lower.startswith("/\\example.com"):
            return True

        return False
