"""
app/scanner/plugins/passive/sqli.py
-----------------------------------
SQL Injection (SQLi) Analysis Plugin — safely identifies SQL syntax error reflections
and boolean-based differential behavior in query parameters.

Safety & Non-Destructive Operation:
    - NEVER executes destructive SQL statements (DROP, DELETE, UPDATE, INSERT, ALTER, CREATE).
    - NEVER executes database administration procedures or xp_cmdshell.
    - NEVER attempts database exfiltration or data extraction.
    - Uses non-destructive quote probes and standard boolean equivalence tests.

Detection Strategy:
    - Analyzes candidate parameters (id, user, search, query, product, item, category, sort, etc.).
    - Injects safe quote probes: "'", '"', "'"
    - Evaluates high-confidence database error signatures for MySQL, PostgreSQL, MSSQL, SQLite, and Oracle.
    - Evaluates safe boolean differential conditions (True condition vs False condition).
    - Strict baseline comparison to prevent false positives from pre-existing errors or SPA fallbacks.

Severity Logic:
    - Verified database driver exception / syntax error reflection -> HIGH / CRITICAL
    - Confirmed boolean differential SQL response divergence -> HIGH
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

# High-confidence database engine error signatures
_DB_ERROR_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "MySQL Error",
        re.compile(
            r"(?:You have an error in your SQL syntax; check the manual that corresponds to your (?:MySQL|MariaDB) server version|"
            r"MySqlException|mysql_fetch_array\(\)|mysqli_query\(\)|supplied argument is not a valid MySQL|"
            r"com\.mysql\.jdbc\.exceptions|check the manual that corresponds to your MariaDB server version)",
            re.IGNORECASE,
        ),
    ),
    (
        "PostgreSQL Error",
        re.compile(
            r"(?:PSQLException|syntax error at or near \".*?\"|pg_query\(\): Query failed|"
            r"PG::SyntaxError|unterminated quoted string at or near|PostgreSQL query failed|"
            r"org\.postgresql\.util\.PSQLException)",
            re.IGNORECASE,
        ),
    ),
    (
        "Microsoft SQL Server Error",
        re.compile(
            r"(?:Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|"
            r"\[Microsoft\]\[ODBC SQL Server Driver\]|System\.Data\.SqlClient\.SqlException|"
            r"Incorrect syntax near|com\.microsoft\.sqlserver\.jdbc\.SQLServerException)",
            re.IGNORECASE,
        ),
    ),
    (
        "SQLite Error",
        re.compile(
            r"(?:SQLite3::SQLException|sqlite3\.OperationalError: near \".*?\": syntax error|"
            r"unrecognized token: \".*?\"|SQLite error: near|no such table:|SQL logic error)",
            re.IGNORECASE,
        ),
    ),
    (
        "Oracle Database Error",
        re.compile(
            r"(?:ORA-00933: SQL command not properly ended|ORA-00936: missing expression|"
            r"ORA-01756: quoted string not properly terminated|oracle\.jdbc\.driver\.OracleDriver|"
            r"OracleException)",
            re.IGNORECASE,
        ),
    ),
]

_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "id",
        "user",
        "username",
        "search",
        "query",
        "q",
        "product",
        "item",
        "category",
        "cat",
        "sort",
        "order",
        "by",
        "filter",
        "page",
        "limit",
        "offset",
        "view",
        "select",
        "type",
        "ref",
    }
)

_SPA_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)


class SqliPlugin(BasePlugin):
    """
    Safely evaluates parameters for error-based and boolean-based SQL injection vulnerabilities.
    """

    name = "sqli"
    description = (
        "Detects SQL Injection (SQLi) vulnerabilities through high-confidence database syntax "
        "error analysis and non-destructive boolean differential testing."
    )
    category = "passive"
    version = "1.0.0"
    priority = 95

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe SQL injection parameter analysis against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping SQLi checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        params_to_test = self._get_parameters_to_test(parsed_target)
        if not params_to_test:
            self.log("No candidate SQL injection parameters found.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for SQL injection: {params_to_test}")

        baseline_text = context.html or ""
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            # 1. Error-based probing with single and double quotes
            is_vuln_err = await self._test_error_sqli(client, parsed_target, param_name, baseline_text, context)
            if is_vuln_err:
                continue

            # 2. Non-destructive boolean differential probing
            await self._test_boolean_sqli(client, parsed_target, param_name, baseline_text, context)

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any) -> list[str]:
        """Extract candidate parameters from query string or common defaults."""
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found = [k for k in query_dict if k.lower() in _CANDIDATE_PARAMS]

        if found:
            return found

        for k in query_dict:
            found.append(k)

        if found:
            return found

        return ["id", "user", "q", "search", "category", "item", "page"]

    # ------------------------------------------------------------------
    # Error-Based SQLi Probing
    # ------------------------------------------------------------------

    async def _test_error_sqli(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Inject non-destructive quote probes and check for database driver syntax errors."""
        quote_probes = ["'", "''", '"']

        for probe in quote_probes:
            query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
            original_val = query_dict.get(param_name, [""])[0]
            query_dict[param_name] = [f"{original_val}{probe}"]

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

                # Anti-signature check for generic SPA fallbacks
                if "text/html" in content_type and _SPA_ANTI_SIGNATURE.search(text):
                    if not any(p.search(text) for _, p in _DB_ERROR_SIGNATURES):
                        continue

                # Match against high-confidence database error signatures
                for db_name, db_regex in _DB_ERROR_SIGNATURES:
                    err_match = db_regex.search(text)
                    if err_match and not db_regex.search(baseline_text):
                        err_snippet = err_match.group(0)
                        evidence = (
                            f"Tested Parameter: {param_name}\n"
                            f"Injected Probe: {probe}\n"
                            f"Identified Database Engine: {db_name}\n"
                            f"Test Request URL: {test_url}\n"
                            f"HTTP Status: {response.status_code}\n\n"
                            f"Database Error Snippet:\n{err_snippet}"
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Error-Based SQL Injection via Parameter: {param_name} ({db_name})",
                                description=(
                                    f"The parameter '{param_name}' is vulnerable to SQL Injection. "
                                    f"Injecting quotation characters triggered an explicit database syntax error or driver "
                                    f"exception ({db_name}: '{err_snippet}'). "
                                    f"An attacker can manipulate database queries to bypass authentication, extract confidential "
                                    f"database tables and user credentials, or alter database contents."
                                ),
                                severity=Severity.HIGH,
                                recommendation=(
                                    f"Use parameterized queries (prepared statements) or an Object-Relational Mapper (ORM) "
                                    f"for all database access involving '{param_name}'. Never concatenate raw user input into SQL strings."
                                ),
                                evidence=evidence,
                            )
                        )
                        return True

            except Exception as exc:
                self.log(f"Error-based SQLi probe on '{param_name}' failed: {exc}")

        return False

    # ------------------------------------------------------------------
    # Boolean Differential SQLi Probing
    # ------------------------------------------------------------------

    async def _test_boolean_sqli(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Evaluate parameter using safe boolean differential probes (' OR '1'='1 vs ' AND '1'='2)."""
        if not baseline_text:
            return False

        try:
            # Probe 1: TRUE condition (should reflect baseline-like results)
            url_true = self._build_probe_url(parsed_target, param_name, "' OR '1'='1")
            resp_true = await client.get(url_true)

            # Probe 2: FALSE condition (should suppress results / differ from True)
            url_false = self._build_probe_url(parsed_target, param_name, "' AND '1'='2")
            resp_false = await client.get(url_false)

            # If True and False responses are identical, no boolean injection
            if resp_true.status_code == resp_false.status_code and abs(len(resp_true.text) - len(resp_false.text)) < 5:
                return False

            # If TRUE condition succeeds (HTTP 200) with substantial body, while FALSE condition returns empty / different content
            if resp_true.status_code == 200 and resp_false.status_code in (200, 404):
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)
                len_base = len(baseline_text)

                # Strong boolean differential indicator: TRUE is consistent with baseline, FALSE diverges significantly
                if abs(len_true - len_base) < 150 and (len_base - len_false > 200 or len_false == 0):
                    evidence = (
                        f"Tested Parameter: {param_name}\n"
                        f"True Condition Payload: ' OR '1'='1 (HTTP {resp_true.status_code}, Length: {len_true})\n"
                        f"False Condition Payload: ' AND '1'='2 (HTTP {resp_false.status_code}, Length: {len_false})\n"
                        f"Baseline Length: {len_base}\n"
                        f"Divergence: True condition preserved baseline content, False condition suppressed records."
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Boolean-Based Blind SQL Injection via Parameter: {param_name}",
                            description=(
                                f"The parameter '{param_name}' demonstrates boolean differential behavior. "
                                f"Supplying a TRUE boolean condition (' OR '1'='1) returned normal baseline content, "
                                f"whereas a FALSE boolean condition (' AND '1'='2) resulted in consistent content suppression."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                f"Implement parameterized queries / prepared statements for parameter '{param_name}'."
                            ),
                            evidence=evidence,
                        )
                    )
                    return True

        except Exception as exc:
            self.log(f"Boolean SQLi probe on '{param_name}' failed: {exc}")

        return False

    @staticmethod
    def _build_probe_url(parsed_target: Any, param_name: str, probe_value: str) -> str:
        """Build test URL with injected probe value."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        original_val = query_dict.get(param_name, ["1"])[0]
        query_dict[param_name] = [f"{original_val}{probe_value}"]

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
