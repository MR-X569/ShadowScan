"""
app/scanner/plugins/passive/xss.py
----------------------------------
Reflected Cross-Site Scripting (XSS) Analysis Plugin — safely identifies
unescaped user input reflection in HTML bodies, attributes, and script contexts.

Detection strategy:
    - Identifies candidate query parameters (q, search, keyword, input, name, etc.)
      from the target URL or common reflection candidate lists.
    - Injects a unique, harmless, non-executable marker:
        "ShadowScanXssProbe7a8b<ssxss>1"
    - Determines if the marker is reflected in the HTTP response body.
    - Inspects the reflection context:
        * Safely HTML-entity encoded (e.g. &lt;ssxss&gt;) -> No vulnerability (suppressed)
        * Pure JSON content type (application/json) -> Informational / suppressed
        * Script context (<script> ... </script>) or JS string -> HIGH severity
        * HTML attribute context (e.g. value="...", href="...") -> HIGH severity
        * HTML text context with unescaped markup (<ssxss>) -> MEDIUM/HIGH severity

Severity Logic:
    - Unescaped marker inside executable HTML/Script/Attribute context -> HIGH
    - Unescaped marker reflection in HTML body where tags are preserved -> MEDIUM
    - Encoded or safely escaped reflection -> No finding
"""

from __future__ import annotations

import html
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Safe, unique, non-executable probe marker containing special characters (<, >, ")
_XSS_PROBE_MARKER: str = "ShadowScanXssProbe7a8b<ssxss>1"
_XSS_PROBE_TAG: str = "<ssxss>"
_XSS_PROBE_IDENTIFIER: str = "ShadowScanXssProbe7a8b"

# Candidate reflection parameter names
_CANDIDATE_XSS_PARAMS: frozenset[str] = frozenset(
    {
        "q",
        "query",
        "search",
        "search_query",
        "keyword",
        "term",
        "input",
        "text",
        "message",
        "msg",
        "name",
        "title",
        "content",
        "value",
        "id",
        "page",
        "redirect",
        "url",
        "email",
        "user",
        "username",
        "comment",
        "filter",
        "sort",
        "view",
    }
)


class XssPlugin(BasePlugin):
    """
    Safely tests URL query parameters for unescaped reflected input vulnerabilities.
    """

    name = "xss"
    description = (
        "Detects reflected Cross-Site Scripting (XSS) input reflection and escaping weaknesses."
    )
    category = "passive"
    version = "1.0.0"
    priority = 75

    async def run(self, context: ScanContext) -> None:
        """
        Execute reflected XSS parameter checks.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping XSS checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Identify parameters to probe
        params_to_test = self._get_parameters_to_test(parsed_target)
        if not params_to_test:
            self.log("No candidate reflection parameters found.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for reflected XSS: {params_to_test}")

        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            await self._test_parameter_reflection(client, parsed_target, param_name, context)

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any) -> list[str]:
        """Extract existing URL query parameters or test common candidate names."""
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found = list(query_dict.keys())

        if found:
            return found

        # If no query params in URL, test the most common candidates
        return ["q", "search", "keyword", "input", "name", "query", "term"]

    # ------------------------------------------------------------------
    # Probe & Context Evaluation
    # ------------------------------------------------------------------

    async def _test_parameter_reflection(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        context: ScanContext,
    ) -> None:
        """Inject harmless probe marker into parameter and analyze response context."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        query_dict[param_name] = [_XSS_PROBE_MARKER]

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
            content_type = response.headers.get("content-type", "").lower()
            text = response.text or ""

            # Check if probe identifier is present at all
            if _XSS_PROBE_IDENTIFIER not in text:
                return

            # If JSON response, input reflection in API data is not HTML XSS
            if "application/json" in content_type and not ("text/html" in content_type):
                self.log(f"Parameter '{param_name}' reflected inside JSON response — no HTML XSS risk.")
                return

            # Check if properly HTML-entity encoded (e.g. &lt;ssxss&gt;)
            encoded_marker = html.escape(_XSS_PROBE_MARKER)
            if encoded_marker in text and _XSS_PROBE_TAG not in text:
                self.log(f"Parameter '{param_name}' reflected but safely HTML-escaped.")
                return

            # Determine reflection context
            is_tag_reflected = _XSS_PROBE_TAG in text
            context_type, excerpt = self._analyze_reflection_context(text, _XSS_PROBE_MARKER)

            if is_tag_reflected or context_type in ("script_context", "attribute_context"):
                severity = Severity.HIGH if (context_type in ("script_context", "attribute_context") or is_tag_reflected) else Severity.MEDIUM

                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Probe Payload: {_XSS_PROBE_MARKER}\n"
                    f"Test URL: {test_url}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Content-Type: {content_type}\n"
                    f"Reflection Context: {context_type}\n"
                    f"Special Character Tag Preserved: {'Yes (<ssxss> unescaped)' if is_tag_reflected else 'No'}\n\n"
                    f"Response Excerpt:\n{excerpt}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Reflected Cross-Site Scripting (XSS) via Parameter: {param_name}",
                        description=(
                            f"The parameter '{param_name}' reflects user-supplied input into the HTTP response body "
                            f"without adequate HTML entity encoding (Context: {context_type}). "
                            f"An attacker can craft malicious URLs containing JavaScript payloads to execute arbitrary scripts "
                            f"in the victim's browser, enabling session hijacking, credential harvesting, or DOM manipulation."
                        ),
                        severity=severity,
                        recommendation=(
                            f"Contextually encode and sanitize all user input for parameter '{param_name}' before reflecting "
                            f"it in responses. Use contextual output encoding (e.g. HTML entity encoding, JavaScript string escaping) "
                            f"and implement a strict Content-Security-Policy (CSP)."
                        ),
                        evidence=evidence,
                    )
                )

        except Exception as exc:
            self.log(f"XSS probe for parameter '{param_name}' on '{test_url}' failed: {exc}")

    # ------------------------------------------------------------------
    # Context Analysis Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_reflection_context(html_body: str, marker: str) -> tuple[str, str]:
        """
        Locates the marker in the response HTML and determines the surrounding context.
        Returns: (context_name, sanitized_snippet)
        """
        idx = html_body.find(marker)
        if idx == -1:
            return "unknown", ""

        start = max(0, idx - 80)
        end = min(len(html_body), idx + len(marker) + 80)
        excerpt = html_body[start:end].strip()

        before = html_body[:idx].lower()

        # Check if inside <script> tag
        last_script_open = before.rfind("<script")
        last_script_close = before.rfind("</script")
        if last_script_open > last_script_close:
            return "script_context", excerpt

        # Check if inside an HTML tag attribute (e.g. value="...", href="...")
        last_tag_open = before.rfind("<")
        last_tag_close = before.rfind(">")
        if last_tag_open > last_tag_close:
            return "attribute_context", excerpt

        return "html_body_text", excerpt
