"""
app/scanner/plugins/passive/ssrf.py
-----------------------------------
Server-Side Request Forgery (SSRF) Analysis Plugin — safely identifies
server-side URL fetching behaviors in candidate parameters.

Strict Safety Restrictions:
    - NEVER targets localhost, 127.0.0.0/8, ::1, or RFC1918 private networks.
    - NEVER targets cloud metadata endpoints (e.g. 169.254.169.254).
    - NEVER executes port scanning or internal network enumeration.
    - Strictly uses benign public test destinations (https://example.com/).

Detection Strategy:
    - Identifies candidate URL/fetching parameters (url, fetch, webhook, source, etc.).
    - Injects safe controlled test destination (https://example.com/).
    - Evaluates observable server response indicators:
        * Remote content embedding (e.g. 'Example Domain' title or IANA text) -> HIGH
        * Server-side HTTP client exceptions (cURL, urllib, HttpClient) -> MEDIUM
    - Compares against baseline target response.

Severity Logic:
    - Confirmed remote external URL fetching and embedding -> HIGH
    - Server-side HTTP client invocation / fetch error indicators -> MEDIUM
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

# Safe, benign external test destination (RFC 2606)
_SAFE_SSRF_TEST_URL: str = "https://example.com/"

# Candidate SSRF parameter names
_SSRF_PARAM_CANDIDATES: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "url_to_fetch",
        "fetch",
        "target",
        "destination",
        "callback",
        "webhook",
        "image_url",
        "img_url",
        "remote",
        "source",
        "src",
        "endpoint",
        "link",
        "feed",
        "proxy",
        "load",
        "site",
    }
)

# Remote signature in https://example.com/ response
_EXAMPLE_DOMAIN_SIGNATURE: re.Pattern[str] = re.compile(
    r"<title>\s*Example Domain\s*</title>|This domain is for use in illustrative examples",
    re.IGNORECASE,
)

# Common server-side HTTP client / socket error messages indicating outbound fetching
_SERVER_FETCH_ERROR_REGEX: re.Pattern[str] = re.compile(
    r"(?:cURL error \d+|getaddrinfo failed|urllib\.error|requests\.exceptions\."
    r"|HttpClientException|HttpWebRequest|ConnectionRefusedError|java\.net\.ConnectException"
    r"|failed to open stream: HTTP request failed|GuzzleHttp\\Exception)",
    re.IGNORECASE,
)


class SsrfPlugin(BasePlugin):
    """
    Safely probes candidate query parameters for server-side URL fetching behaviors.
    """

    name = "ssrf"
    description = (
        "Identifies potential Server-Side Request Forgery (SSRF) and external URL fetching parameters."
    )
    category = "passive"
    version = "1.0.0"
    priority = 85

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe SSRF parameter checks against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping SSRF checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Collect candidate parameters
        params_to_test = self._get_parameters_to_test(parsed_target)
        if not params_to_test:
            self.log("No candidate SSRF parameters detected.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for SSRF behavior: {params_to_test}")

        baseline_text = context.html or ""
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            await self._test_param_ssrf(client, parsed_target, param_name, baseline_text, context)

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any) -> list[str]:
        """Extract candidate SSRF parameters from query string or common candidates."""
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found = [k for k in query_dict if k.lower() in _SSRF_PARAM_CANDIDATES]

        if found:
            return found

        # If query has any parameters containing url/fetch/source/target
        for k in query_dict:
            k_lower = k.lower()
            if any(cand in k_lower for cand in ("url", "fetch", "source", "dest", "webhook", "proxy")):
                found.append(k)

        if found:
            return found

        return ["url", "fetch", "target", "source", "webhook", "image_url"]

    # ------------------------------------------------------------------
    # Safe SSRF Probing & Analysis
    # ------------------------------------------------------------------

    async def _test_param_ssrf(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        baseline_text: str,
        context: ScanContext,
    ) -> None:
        """Inject safe test URL into parameter and inspect server response behavior."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        query_dict[param_name] = [_SAFE_SSRF_TEST_URL]

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

            # Check if remote external content from example.com was fetched and embedded
            if _EXAMPLE_DOMAIN_SIGNATURE.search(text) and not _EXAMPLE_DOMAIN_SIGNATURE.search(baseline_text):
                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Injected Test URL: {_SAFE_SSRF_TEST_URL}\n"
                    f"Test Request URL: {test_url}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Observed Behavior: Response body contains content fetched from external test URL ('Example Domain').\n\n"
                    f"Response Excerpt:\n{text[:250].strip()}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Potential Server-Side Request Forgery (SSRF) via Parameter: {param_name}",
                        description=(
                            f"The parameter '{param_name}' appears to instruct the backend server to fetch content from the "
                            f"supplied URL ({_SAFE_SSRF_TEST_URL}) and embed it into the application response. "
                            f"If the application fails to enforce strict outbound URL whitelisting and network restrictions, "
                            f"attackers can abuse this functionality to probe internal cloud metadata services (e.g. AWS 169.254.169.254), "
                            f"access internal intranet microservices, or bypass firewalls."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            f"Implement strict server-side validation for the '{param_name}' parameter. "
                            f"Validate URLs against a restrictive allowlist of permitted domains. "
                            f"Block requests resolving to private IP ranges (RFC 1918, 127.0.0.0/8, link-local 169.254.0.0/16, IPv6 ::1) "
                            f"at the DNS resolution and network firewall layers."
                        ),
                        evidence=evidence,
                    )
                )
                return

            # Check if server-side fetcher exception / error message is exposed
            error_match = _SERVER_FETCH_ERROR_REGEX.search(text)
            if error_match and not _SERVER_FETCH_ERROR_REGEX.search(baseline_text):
                err_snippet = error_match.group(0)
                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Injected Test URL: {_SAFE_SSRF_TEST_URL}\n"
                    f"Test Request URL: {test_url}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Observed Server-Side Fetch Error: {err_snippet}\n\n"
                    f"Response Excerpt:\n{text[:250].strip()}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Potential SSRF / Server-Side URL Fetch Attempt via Parameter: {param_name}",
                        description=(
                            f"When supplied with an external URL, the parameter '{param_name}' triggered a server-side "
                            f"HTTP client error ({err_snippet}), indicating that the backend attempted to issue a network request. "
                            f"Ensure outbound requests are strictly isolated and validated."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation=(
                            f"Ensure outbound URL fetching on '{param_name}' is protected by domain allowlists and "
                            f"that private/internal IP ranges cannot be queried."
                        ),
                        evidence=evidence,
                    )
                )

        except Exception as exc:
            self.log(f"SSRF probe for '{param_name}' failed: {exc}")
