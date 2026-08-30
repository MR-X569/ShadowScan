"""
app/scanner/plugins/passive/nosql_injection.py
----------------------------------------------
NoSQL Injection Analysis Plugin.

Safely evaluates candidate query parameters for potential NoSQL (e.g. MongoDB, DocumentDB,
CouchDB) injection vulnerabilities using operator object syntax, database parser error
diagnostics, and non-destructive boolean differential analysis.

Safety & Guardrails:
    - NEVER attempts database exfiltration or credential extraction.
    - NEVER performs collection enumeration or administrative commands.
    - NEVER executes $where JavaScript or server-side scripts.
    - NEVER executes destructive operations (delete, update, drop).
    - Uses non-destructive boolean differential probes and harmless operator diagnostics.

Candidate Parameters:
    id, user, username, password, email, search, query, filter, where,
    sort, order, category, product, item, name, key, value, lookup,
    document, collection

Detection Strategy:
    1. Gather candidate parameters from target URL, query parameters, and crawler metadata.
    2. Establish baseline response to avoid false positives on pre-existing errors or static content.
    3. Inject safe operator probes (e.g. [$ne], [$regex]=(, [$unknown_op]) to evaluate NoSQL parser errors.
    4. Perform controlled boolean differential probing ($ne true condition vs $eq false condition).
    5. Filter out generic JSON syntax errors unless paired with specific NoSQL engine signatures or differential behavior.

Severity Logic:
    - HIGH: Strong evidence of server-side NoSQL query manipulation (confirmed boolean differential or database exception).
    - MEDIUM: High-confidence NoSQL parser/operator error triggered by user-controlled input.
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

# High-confidence NoSQL engine / ODM / parser error signatures
_NOSQL_ERROR_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "MongoDB Server / MongoError",
        re.compile(
            r"(?:MongoServerError:\s*|MongoError:\s*|Can't canonicalize query:\s*BadValue|"
            r"unknown top level operator:\s*\$|unknown operator:\s*\$|"
            r"bad query:\s*\$|MongoDB\\Driver\\Exception|com\.mongodb\.MongoException)",
            re.IGNORECASE,
        ),
    ),
    (
        "Mongoose / BSON CastError",
        re.compile(
            r"(?:Cast to (?:ObjectId|string|number|date|Array) failed for value|"
            r"MongooseError:\s*|BSONError:\s*|BSONException:\s*|"
            r"org\.bson\.BsonInvalidOperationException)",
            re.IGNORECASE,
        ),
    ),
    (
        "CouchDB / Couchbase Error",
        re.compile(
            r"(?:Couchbase(?:Exception|Error)|no_db_file|database_does_not_exist|"
            r"org\.couchbase\.mock|CouchDB Exception)",
            re.IGNORECASE,
        ),
    ),
]

_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "id",
        "user",
        "username",
        "password",
        "email",
        "search",
        "query",
        "filter",
        "where",
        "sort",
        "order",
        "category",
        "product",
        "item",
        "name",
        "key",
        "value",
        "lookup",
        "document",
        "collection",
    }
)

_SPA_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)

# Harmless marker for boolean differential testing
_NONEXISTENT_VAL_MARKER: str = "ShadowScanNoSqlDiff9x7"


class NosqlInjectionPlugin(BasePlugin):
    """
    Safely probes query parameters for potential NoSQL injection vulnerabilities.
    """

    name = "nosql_injection"
    description = (
        "Detects NoSQL Injection vulnerabilities through database parser error diagnostics, "
        "operator injection analysis, and safe boolean differential testing."
    )
    category = "passive"
    version = "1.0.0"
    priority = 94

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe NoSQL injection parameter analysis against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping NoSQL injection checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Identify candidate parameters to test
        params_to_test = self._get_parameters_to_test(parsed_target, context)
        if not params_to_test:
            self.log("No candidate NoSQL injection parameters detected.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for NoSQL injection: {params_to_test}")

        baseline_text = context.html or ""
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            # 1. Test error-based / operator injection
            is_vuln_err = await self._test_error_nosql(
                client,
                parsed_target,
                param_name,
                baseline_text,
                context,
            )
            if is_vuln_err:
                continue

            # 2. Test boolean differential operator injection ($ne vs $eq)
            await self._test_boolean_differential_nosql(
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

        return ["id", "user", "username", "search", "query", "filter", "category"]

    # ------------------------------------------------------------------
    # Error-Based & Operator Diagnostics
    # ------------------------------------------------------------------

    async def _test_error_nosql(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Inject safe NoSQL operator diagnostic probes and analyze error responses."""
        error_probes: list[tuple[str, str, str]] = [
            (f"{param_name}[$regex]", "(", "Unclosed Regex Pattern"),
            (f"{param_name}[$unknown_op_probe]", "1", "Unknown Operator Probe"),
        ]

        for probe_key, probe_val, probe_desc in error_probes:
            query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
            # Remove original flat parameter and inject structured operator parameter
            query_dict.pop(param_name, None)
            query_dict[probe_key] = [probe_val]

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
                    if not any(p.search(text) for _, p in _NOSQL_ERROR_SIGNATURES):
                        continue

                # Match against high-confidence NoSQL error signatures
                for db_name, db_regex in _NOSQL_ERROR_SIGNATURES:
                    err_match = db_regex.search(text)
                    if err_match and not db_regex.search(baseline_text):
                        err_snippet = err_match.group(0)

                        evidence = (
                            f"Tested Parameter: {param_name}\n"
                            f"Injected Operator Probe: {probe_key}={probe_val} ({probe_desc})\n"
                            f"Identified Database Signature: {db_name}\n"
                            f"Test Request URL: {test_url}\n"
                            f"HTTP Status: {response.status_code}\n\n"
                            f"Database Error Snippet:\n{err_snippet}"
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Potential NoSQL Injection via Parameter: {param_name} ({db_name})",
                                description=(
                                    f"The parameter '{param_name}' appears vulnerable to NoSQL Injection. "
                                    f"Submitting query operator syntax ('{probe_key}={probe_val}') triggered an explicit "
                                    f"database or ODM parser error ({db_name}: '{err_snippet}'). "
                                    f"An attacker can supply MongoDB/NoSQL query operators to bypass authentication, "
                                    f"extract sensitive database documents, or alter database query logic."
                                ),
                                severity=Severity.HIGH,
                                recommendation=(
                                    f"Ensure parameters passed to database queries are strictly cast to expected primitive types "
                                    f"(e.g. String(), parseInt()) or validate inputs using strict schema validators (e.g. Joi, Zod). "
                                    f"Disable nested object/array query parsing (e.g. configure express 'extended: false' or sanitize with mongo-sanitize)."
                                ),
                                evidence=evidence,
                            )
                        )
                        return True

            except Exception as exc:
                self.log(f"NoSQL error probe on '{param_name}' failed: {exc}")

        return False

    # ------------------------------------------------------------------
    # Boolean Differential Probing ($ne vs $eq)
    # ------------------------------------------------------------------

    async def _test_boolean_differential_nosql(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Evaluate parameter using safe boolean differential probes ($ne vs $eq)."""
        if not baseline_text:
            return False

        try:
            # Probe 1: TRUE condition ($ne non-existent value -> matches all documents / baseline)
            url_true = self._build_operator_url(parsed_target, param_name, "$ne", _NONEXISTENT_VAL_MARKER)
            resp_true = await client.get(url_true)

            # Probe 2: FALSE condition ($eq non-existent value -> matches no documents / empty)
            url_false = self._build_operator_url(parsed_target, param_name, "$eq", _NONEXISTENT_VAL_MARKER)
            resp_false = await client.get(url_false)

            # If True and False responses are identical, no differential behavior
            if resp_true.status_code == resp_false.status_code and abs(len(resp_true.text) - len(resp_false.text)) < 10:
                return False

            len_true = len(resp_true.text)
            len_false = len(resp_false.text)
            len_base = len(baseline_text)

            # Check if TRUE condition returns normal baseline-like content while FALSE condition suppresses content or 404s
            if resp_true.status_code == 200 and resp_false.status_code in (200, 404):
                if abs(len_true - len_base) < 200 and (len_base - len_false > 200 or len_false == 0):
                    evidence = (
                        f"Tested Parameter: {param_name}\n"
                        f"True Condition Probe: {param_name}[$ne]={_NONEXISTENT_VAL_MARKER} (HTTP {resp_true.status_code}, Length: {len_true})\n"
                        f"False Condition Probe: {param_name}[$eq]={_NONEXISTENT_VAL_MARKER} (HTTP {resp_false.status_code}, Length: {len_false})\n"
                        f"Baseline Content Length: {len_base}\n"
                        f"Behavior: Injected $ne operator preserved records whereas $eq operator suppressed results."
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Boolean-Based NoSQL Injection via Parameter: {param_name}",
                            description=(
                                f"The parameter '{param_name}' demonstrates boolean differential NoSQL operator evaluation. "
                                f"Supplying a negated condition ('[$ne]') preserved baseline record output, whereas "
                                f"an equality check for an invalid value ('[$eq]') resulted in record suppression. "
                                f"This indicates user-supplied query operators are interpreted directly by the database layer."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                f"Sanitize all query parameters before passing them to database find/filter methods. "
                                f"Use mongo-sanitize or cast input explicitly to primitives (e.g. String(param)) to prevent operator injection."
                            ),
                            evidence=evidence,
                        )
                    )
                    return True

        except Exception as exc:
            self.log(f"NoSQL boolean differential probe on '{param_name}' failed: {exc}")

        return False

    @staticmethod
    def _build_operator_url(parsed_target: Any, param_name: str, op: str, val: str) -> str:
        """Build test URL with injected operator parameter (e.g. param[$ne]=val)."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        query_dict.pop(param_name, None)
        query_dict[f"{param_name}[{op}]"] = [val]

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
