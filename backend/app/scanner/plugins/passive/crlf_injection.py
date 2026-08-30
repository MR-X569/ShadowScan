"""
app/scanner/plugins/passive/crlf_injection.py
---------------------------------------------
CRLF Injection / HTTP Response Splitting Analysis Plugin.

Safely evaluates candidate query parameters for potential HTTP header injection
and response splitting caused by unsanitized carriage return and line feed characters
reflected in HTTP response headers.

Safety & Guardrails:
    - GET requests only.
    - NEVER injects Set-Cookie or session-modifying headers.
    - NEVER attempts HTTP response-body HTML injection or XSS.
    - NEVER attempts HTTP cache poisoning or cache-header tampering.
    - Uses harmless, unique diagnostic header markers (ShadowScan-CRLF-Probe: 1).

Candidate Parameters:
    redirect, next, url, return, return_url, redirect_url, location, path,
    file, filename, download, name, value, callback, target, destination,
    continue, ref

Detection Strategy:
    1. Extract candidate query parameters from target URL and crawler metadata.
    2. Establish baseline response headers to prevent reporting pre-existing headers.
    3. Inject safe encoded CRLF probes (%0d%0a / %0D%0A) with unique benign marker headers.
    4. Inspect response headers (Location, Set-Cookie, Content-Type, custom headers).
    5. Verify if the injected marker appears as a distinct response header key rather than
       merely an encoded URL substring inside the Location header value.

Severity Logic:
    - HIGH: Confirmed CRLF-induced response header injection / response splitting.
    - MEDIUM: Strong evidence of unsanitized CRLF processing in response headers.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Harmless diagnostic header marker and value
_CRLF_HEADER_NAME: str = "ShadowScan-CRLF-Probe"
_CRLF_HEADER_NAME_LOWER: str = _CRLF_HEADER_NAME.lower()
_CRLF_HEADER_VAL: str = "1"

# CRLF probe payloads
_CRLF_PAYLOADS: list[tuple[str, str]] = [
    (f"%0d%0a{_CRLF_HEADER_NAME}: {_CRLF_HEADER_VAL}", "Standard CRLF Injection"),
    (f"%0D%0A{_CRLF_HEADER_NAME}: {_CRLF_HEADER_VAL}", "Uppercase CRLF Injection"),
    (f"/%0d%0a{_CRLF_HEADER_NAME}: {_CRLF_HEADER_VAL}", "Path-Prepended CRLF Injection"),
    (f"?test=%0d%0a{_CRLF_HEADER_NAME}: {_CRLF_HEADER_VAL}", "Query-Prepended CRLF Injection"),
]

# Candidate parameter names frequently reflected into HTTP response headers
_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "redirect",
        "next",
        "url",
        "return",
        "return_url",
        "redirect_url",
        "location",
        "path",
        "file",
        "filename",
        "download",
        "name",
        "value",
        "callback",
        "target",
        "destination",
        "continue",
        "ref",
    }
)


class CrlfInjectionPlugin(BasePlugin):
    """
    Safely probes parameters for HTTP response splitting and CRLF header injection.
    """

    name = "crlf_injection"
    description = (
        "Detects HTTP Response Splitting and CRLF Injection by safely probing query parameters "
        "and evaluating whether injected header markers appear as distinct HTTP response headers."
    )
    category = "passive"
    version = "1.0.0"
    priority = 62

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe CRLF injection parameter analysis against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping CRLF injection checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Identify candidate parameters to test
        params_to_test = self._get_parameters_to_test(parsed_target, context)
        if not params_to_test:
            self.log("No candidate CRLF injection parameters detected.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for CRLF injection: {params_to_test}")

        baseline_headers = {k.lower(): v for k, v in context.headers.items()}
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            for probe_payload, probe_desc in _CRLF_PAYLOADS:
                is_vulnerable = await self._test_param_crlf(
                    client,
                    parsed_target,
                    param_name,
                    probe_payload,
                    probe_desc,
                    baseline_headers,
                    context,
                )
                if is_vulnerable:
                    break

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any, context: ScanContext) -> list[str]:
        """Extract candidate parameters from query string, crawler metadata, or common candidates."""
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

        return ["redirect", "next", "url", "return_url", "location", "path", "callback", "target"]

    # ------------------------------------------------------------------
    # CRLF Probe Execution & Header Analysis
    # ------------------------------------------------------------------

    async def _test_param_crlf(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        probe_payload: str,
        probe_desc: str,
        baseline_headers: dict[str, str],
        context: ScanContext,
    ) -> bool:
        """Inject encoded CRLF probe and check if marker creates a distinct response header."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        query_dict[param_name] = [probe_payload]

        flattened = [(k, v[0] if isinstance(v, list) and v else "") for k, v in query_dict.items()]
        new_query = urlencode(flattened, safe=":% ")

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
            resp_headers = {k.lower(): v for k, v in response.headers.items()}

            # 1. Check if the injected header marker was parsed as an actual separate response header
            is_in_headers = _CRLF_HEADER_NAME_LOWER in resp_headers
            was_in_baseline = _CRLF_HEADER_NAME_LOWER in baseline_headers

            if is_in_headers and not was_in_baseline:
                injected_val = resp_headers.get(_CRLF_HEADER_NAME_LOWER, "")

                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Injected Probe: {probe_payload} ({probe_desc})\n"
                    f"Test Request URL: {test_url}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Injected Response Header: {_CRLF_HEADER_NAME}: {injected_val}\n"
                    f"Header Extraction: Successfully created distinct HTTP response header field."
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"CRLF Injection / HTTP Response Splitting via Parameter: {param_name}",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to CRLF Injection / HTTP Response Splitting. "
                            f"Supplying encoded carriage return and line feed sequences ('%0d%0a') resulted in the creation "
                            f"of a distinct HTTP response header ('{_CRLF_HEADER_NAME}: {injected_val}'). "
                            f"An attacker can exploit CRLF injection to inject malicious headers (e.g. Set-Cookie), "
                            f"perform HTTP response splitting, poison web caches, or conduct Cross-Site Scripting (XSS)."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            f"Sanitize all user-controlled input used in HTTP response headers (such as Location redirects). "
                            f"Strip or reject CR ('\\r', '%0d') and LF ('\\n', '%0a') characters before passing input to header APIs, "
                            f"or use modern framework redirect methods that enforce header value validation."
                        ),
                        evidence=evidence,
                    )
                )
                return True

            # 2. Check for Location header anomalies where CRLF was unencoded but not split
            location = resp_headers.get("location", "")
            if location and "\r" in location or "\n" in location:
                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Injected Probe: {probe_payload}\n"
                    f"Location Header Value with Raw CRLF: {location!r}\n"
                    f"HTTP Status: {response.status_code}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Unsanitized CRLF Characters in Response Header: {param_name}",
                        description=(
                            f"The parameter '{param_name}' reflects unencoded CRLF control characters into the HTTP Location "
                            f"response header. Although full response splitting did not occur, unvalidated CRLF sequences "
                            f"indicate a lack of header sanitization."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            "Strip carriage return ('\\r') and line feed ('\\n') characters from all data written to HTTP response headers."
                        ),
                        evidence=evidence,
                    )
                )
                return True

            return False

        except Exception as exc:
            self.log(f"CRLF injection probe on '{param_name}' failed: {exc}")
            return False
