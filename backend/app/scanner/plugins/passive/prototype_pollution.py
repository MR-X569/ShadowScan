"""
app/scanner/plugins/passive/prototype_pollution.py
--------------------------------------------------
Prototype Pollution Analysis Plugin.

Safely evaluates candidate query parameters and client-side scripts for potential
server-side and client-side JavaScript prototype pollution patterns.

Safety & Guardrails:
    - NEVER executes JavaScript code.
    - NEVER attempts process-level pollution, privilege escalation, or RCE.
    - NEVER executes state-changing or persistent modification requests.
    - Uses harmless diagnostic markers and static code analysis.

Candidate Parameters:
    __proto__, constructor, prototype, merge, extend, assign, defaults,
    config, options, settings, object, data, params, query, input

Detection Strategy:
    1. Probing with safe, unique marker properties (__proto__[marker]=val, constructor[prototype][marker]=val).
    2. Server-side object processing & reflection analysis (e.g. property assigned into JSON object structure).
    3. Parser/library error signature detection (e.g. prototype pollution warnings, Lodash merge errors).
    4. Client-side static analysis for unsafe recursive merge/extend routines lacking key filtration.
    5. Suppress literal reflection, markdown/documentation pages, and SPA fallbacks.

Severity Logic:
    - HIGH: Confirmed server-side prototype property interpretation / object mutation.
    - MEDIUM: Suspicious prototype-property processing with supporting error or differential evidence.
    - LOW: Potentially vulnerable client-side merge/extend pattern detected statically.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Harmless diagnostic marker property and value
_PROTO_MARKER_PROP: str = "shadow_proto_prop"
_PROTO_MARKER_VAL: str = "shadow_proto_val"

# High-confidence prototype pollution server error / warning patterns
_PROTO_ERROR_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "Prototype Property Assignment Error",
        re.compile(
            r"(?:TypeError:\s*Cannot assign to read only property ['\"]" + _PROTO_MARKER_PROP + r"['\"]|"
            r"Object\.prototype\." + _PROTO_MARKER_PROP + r"|"
            r"PrototypePollutionError|Prototype pollution detected|"
            r"Prevented prototype pollution assignment)",
            re.IGNORECASE,
        ),
    ),
    (
        "Lodash / Merge Library Exception",
        re.compile(
            r"(?:lodash\.merge:\s*prototype pollution|"
            r"TypeError:\s*Cannot set property '.*?' of #<Object>|"
            r"Uncaught TypeError:\s*Cannot convert undefined or null to object)",
            re.IGNORECASE,
        ),
    ),
]

# Static regex patterns for vulnerable client-side merge/extend implementations
# Matching recursive property assignments that lack __proto__/constructor checks
_CLIENT_VULN_MERGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "Unsafe Recursive Object Merge",
        re.compile(
            r"function\s+\w+\s*\([^)]*\)\s*\{[^}]*for\s*\(\s*(?:var|let|const)?\s*(\w+)\s+in\s+\w+\)[^}]*\[\1\]\s*=\s*(?:merge|extend|clone|\w+)\(",
            re.IGNORECASE,
        ),
    ),
    (
        "Unsafe Object.assign / Deep Merge without Key Validation",
        re.compile(
            r"(?:target\[key\]\s*=\s*source\[key\]|dst\[p\]\s*=\s*src\[p\]|obj\[prop\]\s*=\s*val)",
            re.IGNORECASE,
        ),
    ),
]

_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "__proto__",
        "constructor",
        "prototype",
        "merge",
        "extend",
        "assign",
        "defaults",
        "config",
        "options",
        "settings",
        "object",
        "data",
        "params",
        "query",
        "input",
    }
)

_SPA_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)


class PrototypePollutionPlugin(BasePlugin):
    """
    Safely evaluates endpoints and scripts for prototype pollution vulnerabilities.
    """

    name = "prototype_pollution"
    description = (
        "Detects potential server-side and client-side JavaScript prototype pollution vulnerabilities "
        "through non-destructive parameter probes and static source pattern analysis."
    )
    category = "passive"
    version = "1.0.0"
    priority = 74

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe prototype pollution analysis against context.target_url and page assets.
        """
        if not context.target_url:
            self.log("No target URL available — skipping prototype pollution checks.")
            return

        # 1. Client-Side Static Analysis of HTML / Scripts
        self._analyze_client_side_scripts(context)

        if context.session is None:
            self.log("No HTTP session available — skipping active parameter probing.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 2. Identify candidate parameters for server-side probing
        params_to_test = self._get_parameters_to_test(parsed_target, context)
        if not params_to_test:
            self.log("No candidate prototype pollution parameters found.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for prototype pollution: {params_to_test}")

        baseline_text = context.html or ""
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            await self._test_param_prototype_pollution(
                client,
                parsed_target,
                param_name,
                baseline_text,
                context,
            )

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

        return ["config", "options", "settings", "data", "params", "__proto__", "query"]

    # ------------------------------------------------------------------
    # Server-Side Probing & Object Reflection Analysis
    # ------------------------------------------------------------------

    async def _test_param_prototype_pollution(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Inject safe prototype pollution probes and analyze server response."""
        probes = [
            (f"__proto__[{_PROTO_MARKER_PROP}]", _PROTO_MARKER_VAL, "Bracket Prototype Notation"),
            (f"constructor[prototype][{_PROTO_MARKER_PROP}]", _PROTO_MARKER_VAL, "Constructor Prototype Notation"),
            (f"__proto__.{_PROTO_MARKER_PROP}", _PROTO_MARKER_VAL, "Dot Prototype Notation"),
        ]

        for probe_key, probe_val, probe_desc in probes:
            query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
            # If testing a generic parameter, test as nested property; otherwise test directly
            if param_name in ("__proto__", "constructor", "prototype"):
                query_dict.pop(param_name, None)
                query_dict[probe_key] = [probe_val]
            else:
                query_dict[f"{param_name}[__proto__][{_PROTO_MARKER_PROP}]"] = [probe_val]

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
                    if _PROTO_MARKER_PROP not in text and not any(p.search(text) for _, p in _PROTO_ERROR_SIGNATURES):
                        continue

                # 1. Check for Prototype Pollution error / exception reflections
                for err_name, err_regex in _PROTO_ERROR_SIGNATURES:
                    err_match = err_regex.search(text)
                    if err_match and not err_regex.search(baseline_text):
                        err_snippet = err_match.group(0)
                        evidence = (
                            f"Tested Parameter: {param_name}\n"
                            f"Injected Probe: {probe_key}={probe_val} ({probe_desc})\n"
                            f"Identified Error Signature: {err_name}\n"
                            f"Test Request URL: {test_url}\n"
                            f"HTTP Status: {response.status_code}\n\n"
                            f"Error Snippet:\n{err_snippet}"
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Prototype Pollution Error Indicator via Parameter: {param_name}",
                                description=(
                                    f"Submitting prototype property assignments in parameter '{param_name}' triggered "
                                    f"an explicit prototype mutation or object parser error ({err_name}: '{err_snippet}'). "
                                    f"This indicates the application attempts to merge or assign user-controlled keys into JavaScript Object prototypes."
                                ),
                                severity=Severity.MEDIUM,
                                recommendation=(
                                    "Validate all object keys against an allowlist, freeze Object.prototype using Object.freeze(), "
                                    "or use Object.create(null) for dictionary objects."
                                ),
                                evidence=evidence,
                            )
                        )
                        return True

                # 2. Check for Server-Side Object Interpretation / Mutation in JSON Responses
                if "application/json" in content_type or (text.strip().startswith("{") and text.strip().endswith("}")):
                    try:
                        data = json.loads(text)
                        # Check if the marker property was assigned into the top-level object or parsed data
                        if isinstance(data, dict):
                            is_assigned_top_level = _PROTO_MARKER_PROP in data and data[_PROTO_MARKER_PROP] == _PROTO_MARKER_VAL
                            is_in_proto_obj = "__proto__" in data and isinstance(data["__proto__"], dict) and _PROTO_MARKER_PROP in data["__proto__"]

                            # Exclude cases where the raw query string was simply echoed in a reflection field
                            is_literal_reflection = probe_key in text and not (is_assigned_top_level or is_in_proto_obj)

                            if (is_assigned_top_level or is_in_proto_obj) and not is_literal_reflection:
                                evidence = (
                                    f"Tested Parameter: {param_name}\n"
                                    f"Injected Probe: {probe_key}={probe_val}\n"
                                    f"Probe Style: {probe_desc}\n"
                                    f"Test Request URL: {test_url}\n"
                                    f"HTTP Status: {response.status_code}\n\n"
                                    f"Response Excerpt:\n{text[:300].strip()}"
                                )

                                context.add_finding(
                                    Finding(
                                        plugin=self.name,
                                        title=f"Server-Side Prototype Pollution via Parameter: {param_name}",
                                        description=(
                                            f"The parameter '{param_name}' allows modifying object prototypes on the server. "
                                            f"Supplying prototype mutation keys resulted in the property '{_PROTO_MARKER_PROP}' "
                                            f"being parsed and attached to server-side object instances. "
                                            f"An attacker can exploit server-side prototype pollution to achieve Remote Code Execution (RCE), "
                                            f"bypass authorization checks, or cause Denial of Service (DoS)."
                                        ),
                                        severity=Severity.HIGH,
                                        recommendation=(
                                            "Ensure recursive object merge/extend functions filter out dangerous keys like "
                                            "'__proto__', 'constructor', and 'prototype'. Use Map objects or Object.create(null) "
                                            "to store arbitrary key-value pairs."
                                        ),
                                        evidence=evidence,
                                    )
                                )
                                return True
                    except json.JSONDecodeError:
                        pass

            except Exception as exc:
                self.log(f"Prototype pollution probe on '{param_name}' failed: {exc}")

        return False

    # ------------------------------------------------------------------
    # Client-Side Static JavaScript Analysis
    # ------------------------------------------------------------------

    def _analyze_client_side_scripts(self, context: ScanContext) -> None:
        """Statically inspect HTML and discovered scripts for unsafe merge/extend implementations."""
        html = context.html or ""
        if not html:
            return

        # Suppress static documentation/markdown articles mentioning prototype pollution
        if any(doc_k in html.lower() for doc_k in ("# prototype pollution", "prototype pollution vulnerability guide", "cve-20")):
            return

        # Extract inline <script> contents
        script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
        for script_content in script_blocks:
            # Check length to respect resource limits
            if len(script_content) > 100_000:
                script_content = script_content[:100_000]

            # Check if script contains prototype references
            if "__proto__" not in script_content and "prototype" not in script_content:
                continue

            # Check if script has unsafe merge routines without key filtering
            for pattern_name, pattern_regex in _CLIENT_VULN_MERGE_PATTERNS:
                match = pattern_regex.search(script_content)
                if match:
                    # Verify the script does NOT contain key sanitization (e.g. key !== '__proto__')
                    has_sanitization = bool(re.search(r"(?:__proto__|constructor|prototype)\s*!==|===|includes|indexOf", script_content))
                    if not has_sanitization:
                        snippet = match.group(0)
                        evidence = (
                            f"Detected Pattern: {pattern_name}\n"
                            f"Vulnerable Code Snippet:\n{snippet}\n\n"
                            f"Context: Unsanitized recursive object merge/assignment in client-side script."
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Potentially Vulnerable Client-Side Object Merge ({pattern_name})",
                                description=(
                                    f"Static analysis identified a client-side JavaScript object merge or clone routine "
                                    f"that does not appear to sanitize dangerous object properties such as '__proto__' or 'constructor'. "
                                    f"If user input from URL fragments, query parameters, or postMessage events reaches this merge routine, "
                                    f"an attacker may pollute the client-side Object.prototype leading to DOM XSS or client-side logic bypass."
                                ),
                                severity=Severity.LOW,
                                recommendation=(
                                    "Ensure all client-side object merge/extend functions filter out '__proto__' and 'constructor' "
                                    "properties, or use secure object cloning libraries with prototype pollution protections."
                                ),
                                evidence=evidence,
                            )
                        )
                        return
