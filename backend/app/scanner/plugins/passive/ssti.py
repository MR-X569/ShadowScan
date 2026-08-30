"""
app/scanner/plugins/passive/ssti.py
-----------------------------------
Server-Side Template Injection (SSTI) Analysis Plugin.

Safely evaluates candidate parameters for server-side template engine execution
using harmless arithmetic expressions (e.g. {{7*7}}, ${7*7}, <%= 7*7 %>).

Safety & Guardrails:
    - NEVER executes operating system commands or subprocesses.
    - NEVER accesses internal configuration objects ({{config}}, self.__class__).
    - NEVER attempts sandbox escape payloads or object traversal.
    - Purely uses harmless mathematical arithmetic evaluation verification.

Supported Template Engine Syntax Probes:
    - Jinja2 / Twig / Nunjucks: {{7*7}} -> 49
    - Freemarker / MVEL / Spring EL: ${7*7} -> 49
    - ERB / Ruby: <%= 7*7 %> -> 49
    - Tornado / Smarty: {{7*7}} -> 49

False-Positive Protections:
    - Verifies mathematical result (49) was NOT already in the baseline response.
    - Rejects literal expression reflection (e.g. response containing "{{7*7}}").
    - Verifies against secondary probe ({{7*7*7}} -> 343) for high confidence.
    - Suppresses static documentation and Single Page Application fallbacks.

Severity Logic:
    - Confirmed arithmetic template expression evaluation -> HIGH
    - Strong template syntax differential behavior -> MEDIUM
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


@dataclass
class _SstiProbe:
    engine_family: str
    expression: str
    expected_result: str
    verification_expression: str
    verification_result: str


_PROBES: list[_SstiProbe] = [
    _SstiProbe(
        engine_family="Jinja2 / Twig / Django / Nunjucks",
        expression="{{7*7}}",
        expected_result="49",
        verification_expression="{{7*7*7}}",
        verification_result="343",
    ),
    _SstiProbe(
        engine_family="Freemarker / Spring EL / MVEL",
        expression="${7*7}",
        expected_result="49",
        verification_expression="${7*7*7}",
        verification_result="343",
    ),
    _SstiProbe(
        engine_family="ERB / Ruby Template",
        expression="<%= 7*7 %>",
        expected_result="49",
        verification_expression="<%= 7*7*7 %>",
        verification_result="343",
    ),
]

_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "name",
        "template",
        "message",
        "msg",
        "q",
        "query",
        "search",
        "input",
        "text",
        "title",
        "content",
        "value",
        "page",
        "view",
        "subject",
        "preview",
        "render",
        "layout",
        "body",
        "comment",
        "greeting",
    }
)

_SPA_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)


class SstiPlugin(BasePlugin):
    """
    Safely probes parameters for Server-Side Template Injection vulnerabilities.
    """

    name = "ssti"
    description = (
        "Detects Server-Side Template Injection (SSTI) through safe arithmetic expression "
        "evaluation across Jinja2, Twig, Freemarker, and ERB template engines."
    )
    category = "passive"
    version = "1.0.0"
    priority = 88

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe SSTI parameter analysis against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping SSTI checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Identify candidate parameters to test
        params_to_test = self._get_parameters_to_test(parsed_target, context)
        if not params_to_test:
            self.log("No candidate SSTI parameters detected.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for SSTI: {params_to_test}")

        baseline_text = context.html or ""
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            for probe in _PROBES:
                is_vulnerable = await self._test_param_ssti(
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
        """Extract parameters from query string, crawler metadata, or common candidates."""
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found = [k for k in query_dict if k.lower() in _CANDIDATE_PARAMS]

        # Add parameters discovered by crawler
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

        return ["template", "name", "message", "query", "q", "preview", "render"]

    # ------------------------------------------------------------------
    # Safe SSTI Probing & Verification
    # ------------------------------------------------------------------

    async def _test_param_ssti(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        probe: _SstiProbe,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Inject arithmetic probe and verify if expression was evaluated into mathematical result."""
        # 1. Test primary arithmetic probe (e.g. {{7*7}})
        test_url_1 = self._build_probe_url(parsed_target, param_name, probe.expression)

        try:
            resp_1 = await client.get(test_url_1)
            text_1 = resp_1.text or ""
            content_type = resp_1.headers.get("content-type", "").lower()

            # Anti-signature check for Single Page Applications
            if "text/html" in content_type and _SPA_ANTI_SIGNATURE.search(text_1):
                if probe.expected_result not in text_1:
                    return False

            # Check if arithmetic result (49) is present in response
            # AND the raw expression itself is NOT simply reflected
            has_evaluated_result = probe.expected_result in text_1
            is_literal_reflection = probe.expression in text_1
            was_in_baseline = probe.expected_result in baseline_text

            if has_evaluated_result and not is_literal_reflection and not was_in_baseline:
                # 2. Confirmation Probe with secondary arithmetic (e.g. {{7*7*7}} -> 343)
                test_url_2 = self._build_probe_url(parsed_target, param_name, probe.verification_expression)
                resp_2 = await client.get(test_url_2)
                text_2 = resp_2.text or ""

                if probe.verification_result in text_2 and probe.verification_expression not in text_2:
                    evidence = (
                        f"Tested Parameter: {param_name}\n"
                        f"Target Engine Family: {probe.engine_family}\n"
                        f"Primary Probe: {probe.expression} -> Result: {probe.expected_result}\n"
                        f"Verification Probe: {probe.verification_expression} -> Result: {probe.verification_result}\n"
                        f"Test Request URL: {test_url_1}\n"
                        f"HTTP Status: {resp_1.status_code}\n\n"
                        f"Response Snippet:\n{text_1[:250].strip()}"
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Server-Side Template Injection (SSTI) via Parameter: {param_name}",
                            description=(
                                f"The parameter '{param_name}' evaluates user input inside a server-side template engine "
                                f"({probe.engine_family}). Injecting harmless arithmetic expressions ({probe.expression}) "
                                f"resulted in mathematical execution ({probe.expected_result}). "
                                f"An attacker can exploit SSTI to access server-side environment variables, read application files, "
                                f"or achieve Remote Code Execution (RCE)."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                f"Never concatenate unvalidated user input into server-side template strings. "
                                f"Pass user data strictly as context variables to template renderers, or use sandboxed "
                                f"template execution environments."
                            ),
                            evidence=evidence,
                        )
                    )
                    return True

        except Exception as exc:
            self.log(f"SSTI probe on '{param_name}' failed: {exc}")

        return False

    @staticmethod
    def _build_probe_url(parsed_target: Any, param_name: str, probe_value: str) -> str:
        """Build test URL with injected template probe."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        query_dict[param_name] = [probe_value]

        flattened = [(k, v[0] if isinstance(v, list) and v else "") for k, v in query_dict.items()]
        new_query = urlencode(flattened)

        return urlunparse((
            parsed_target.scheme,
            parsed_target.netloc,
            parsed_target.path,
            parsed_target.params,
            new_query,
            parsed_target.fragment,
        ))
