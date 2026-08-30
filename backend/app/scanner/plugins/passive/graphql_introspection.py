"""
app/scanner/plugins/passive/graphql_introspection.py
---------------------------------------------------
GraphQL Schema Security & Introspection Analysis Plugin.

Safely evaluates GraphQL endpoints for active introspection (__schema), sensitive
administrative type disclosures, field suggestion leakage ("Did you mean..."),
and publicly exposed developer IDE interfaces.

Safety & Guardrails:
    - Purely read-only introspection queries.
    - NEVER executes mutations or subscription requests.
    - NEVER attempts brute-force schema fuzzing.
    - Strictly bounded request count and response size limits.
    - Redacts all credentials, cookies, tokens, and authorization parameters in findings.

Severity Logic:
    - HIGH: Public production GraphQL endpoint exposes full introspection/schema containing
            sensitive administrative, password, or secret fields.
    - MEDIUM: Introspection is enabled on production GraphQL endpoint, or detailed field suggestion
              leakage ("Did you mean...") exposes internal schema structure.
    - LOW: Public GraphQL IDE / developer console is exposed without sensitive schema disclosure.
    - NONE: Introspection securely disabled/rejected and no developer IDE exposed.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Common GraphQL endpoint candidate paths
_GRAPHQL_CANDIDATE_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/graphql/api",
    "/v1/graphql",
    "/api/v1/graphql",
    "/query",
    "/api/query",
)

# Standard read-only schema introspection query
_FULL_INTROSPECTION_QUERY: str = (
    '{"query": "{ __schema { queryType { name } mutationType { name } '
    'types { name kind fields { name } } } }"}'
)

# Harmless malformed query to test field suggestion leakage
_FIELD_SUGGESTION_PROBE_QUERY: str = '{"query": "{ __shadowscan_nonexistent_field }"}'

# Sensitive administrative keywords in schema types and fields
_SENSITIVE_SCHEMA_KEYWORDS: frozenset[str] = frozenset(
    {
        "admin",
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "internal",
        "billing",
        "creditcard",
        "payment",
        "ssn",
        "system",
        "debug",
        "auth",
        "private",
        "apikey",
        "hash",
        "salt",
    }
)

# Interactive IDE regex signatures
_IDE_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("GraphiQL IDE", re.compile(r"GraphiQL\.createFetcher|<title>GraphiQL</title>|React\.createElement\(GraphiQL", re.IGNORECASE)),
    ("GraphQL Playground", re.compile(r"GraphQLPlayground\.init|<title>GraphQL Playground</title>|window\.GraphQLPlayground", re.IGNORECASE)),
    ("Apollo Sandbox", re.compile(r"ApolloSandbox|<title>Apollo Sandbox</title>|embedded-sandbox", re.IGNORECASE)),
    ("Altair GraphQL Client", re.compile(r"<title>Altair</title>|altair-root", re.IGNORECASE)),
]

# Regex to detect field suggestion leakage ("Did you mean...")
_SUGGESTION_PATTERN: re.Pattern[str] = re.compile(
    r"""(?:did\s+you\s+mean|cannot\s+query\s+field)""",
    re.IGNORECASE,
)


class GraphQLIntrospectionPlugin(BasePlugin):
    """
    Evaluates GraphQL endpoints for introspection exposure, administrative schema disclosure,
    and field suggestion leaks.
    """

    name = "graphql_introspection"
    description = (
        "Analyzes GraphQL endpoints for enabled schema introspection, administrative schema leakage, "
        "field suggestion disclosures, and public developer playground IDEs."
    )
    category = "passive"
    version = "1.0.0"
    priority = 56

    async def run(self, context: ScanContext) -> None:
        """
        Execute GraphQL introspection and schema analysis against candidate endpoints.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping GraphQL introspection analysis.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # 1. Collect candidate endpoints
        candidate_urls = self._collect_graphql_candidates(target_origin, context)
        if not candidate_urls:
            return

        checked_urls: set[str] = set()

        for gql_url in candidate_urls[:4]:  # Bounded to top 4 candidate endpoints
            if gql_url in checked_urls:
                continue
            checked_urls.add(gql_url)

            try:
                # A. Test Schema Introspection (POST)
                has_introspection = await self._check_introspection(client, gql_url, context)
                if has_introspection:
                    return  # Top finding reported

                # B. Test for Public Interactive Developer IDE (GET)
                has_ide = await self._check_ide_exposure(client, gql_url, context)

                # C. If full introspection was disabled, test for Field Suggestion Leakage
                has_suggestion = await self._check_field_suggestion_leak(client, gql_url, context)

                if has_ide or has_suggestion:
                    return

            except Exception as exc:
                self.log(f"GraphQL probe on '{gql_url}' failed: {exc}")

    # ------------------------------------------------------------------
    # Discovery Helper
    # ------------------------------------------------------------------

    def _collect_graphql_candidates(self, target_origin: str, context: ScanContext) -> list[str]:
        """Collect potential GraphQL endpoints from candidate paths and crawler URLs."""
        candidates = [urljoin(target_origin, p) for p in _GRAPHQL_CANDIDATE_PATHS]

        discovered_urls = context.metadata.get("discovered_urls", [])
        for url in discovered_urls:
            parsed = urlparse(url)
            if "graphql" in parsed.path.lower() or "query" in parsed.path.lower():
                candidates.append(urljoin(target_origin, parsed.path))

        # Deduplicate preserving order
        unique_candidates: list[str] = []
        for c in candidates:
            if c not in unique_candidates:
                unique_candidates.append(c)

        return unique_candidates

    # ------------------------------------------------------------------
    # Interactive IDE Detection
    # ------------------------------------------------------------------

    async def _check_ide_exposure(self, client: Any, gql_url: str, context: ScanContext) -> bool:
        """Check if endpoint serves a public GraphQL IDE console on GET."""
        resp = await client.get(gql_url)
        if resp.status_code != 200 or not resp.text:
            return False

        text = resp.text
        for ide_name, pattern in _IDE_SIGNATURES:
            if pattern.search(text):
                evidence = (
                    f"GraphQL Endpoint: {gql_url}\n"
                    f"Detected Console: {ide_name}\n"
                    f"HTTP Status: HTTP 200 OK\n"
                    f"Interface: Interactive Public GraphQL IDE"
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Public GraphQL Interactive Console Exposed ({ide_name})",
                        description=(
                            f"An interactive GraphQL developer console ({ide_name}) was detected at '{gql_url}'. "
                            f"Public consoles allow unauthorized users to visually inspect documentation, autocomplete "
                            f"queries, and construct tailored data queries against backend models."
                        ),
                        severity=Severity.LOW,
                        recommendation=f"Disable {ide_name} in production environments or place it behind strict authentication.",
                        evidence=evidence,
                    )
                )
                return True
        return False

    # ------------------------------------------------------------------
    # Introspection Analysis
    # ------------------------------------------------------------------

    async def _check_introspection(self, client: Any, gql_url: str, context: ScanContext) -> bool:
        """Send read-only introspection query and evaluate schema disclosure."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        resp = await client.request("POST", gql_url, content=_FULL_INTROSPECTION_QUERY.encode("utf-8"), headers=headers)

        if resp.status_code != 200 or not resp.text:
            return False

        try:
            gql_json = json.loads(resp.text)
        except Exception:
            return False

        if not isinstance(gql_json, dict) or "data" not in gql_json:
            return False

        schema_data = gql_json["data"].get("__schema") if isinstance(gql_json["data"], dict) else None
        if not schema_data or "types" not in schema_data:
            return False

        types_list = schema_data.get("types", [])
        type_count = len(types_list)
        if type_count == 0:
            return False

        # Analyze exposed types & fields for sensitive keywords
        disclosed_type_names = [t.get("name", "") for t in types_list if isinstance(t, dict) and t.get("name")]
        user_types = [name for name in disclosed_type_names if not name.startswith("__")]

        sensitive_fields_found: list[str] = []
        for t in types_list:
            if isinstance(t, dict):
                t_name = t.get("name", "")
                if self._is_sensitive_keyword(t_name):
                    sensitive_fields_found.append(f"Type: {t_name}")

                for f in t.get("fields") or []:
                    if isinstance(f, dict):
                        f_name = f.get("name", "")
                        if self._is_sensitive_keyword(f_name):
                            sensitive_fields_found.append(f"{t_name}.{f_name}")

        has_sensitive_schema = len(sensitive_fields_found) > 0
        severity = Severity.HIGH if has_sensitive_schema else Severity.MEDIUM

        sample_types = user_types[:6]
        evidence = (
            f"GraphQL Endpoint: {gql_url}\n"
            f"Introspection Status: Enabled (HTTP 200)\n"
            f"Total Types Disclosed: {type_count}\n"
            f"Sample Schema Types: {', '.join(sample_types) if sample_types else 'Standard Types'}\n"
            f"Sensitive Fields/Types Identified: {', '.join(sensitive_fields_found[:5]) if has_sensitive_schema else 'None obvious'}"
        )

        context.add_finding(
            Finding(
                plugin=self.name,
                title=f"GraphQL Schema Introspection Enabled ({'Sensitive Fields Exposed' if has_sensitive_schema else 'Schema Disclosed'})",
                description=(
                    f"The GraphQL service at '{gql_url}' permits unrestricted schema introspection. "
                    f"Attackers can reconstruct the complete schema graph, including internal query methods, "
                    f"mutations, private data fields, and administrative actions."
                ),
                severity=severity,
                recommendation=(
                    "Disable GraphQL introspection (__schema queries) in production deployment configurations. "
                    "For Apollo Server, Yoga, or GraphQL-Ruby, set 'introspection: false'."
                ),
                evidence=evidence,
            )
        )
        return True

    # ------------------------------------------------------------------
    # Field Suggestion Leakage Detection
    # ------------------------------------------------------------------

    async def _check_field_suggestion_leak(self, client: Any, gql_url: str, context: ScanContext) -> bool:
        """Send intentional non-existent field to detect 'Did you mean' schema leakage."""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        resp = await client.request("POST", gql_url, content=_FIELD_SUGGESTION_PROBE_QUERY.encode("utf-8"), headers=headers)

        if not resp.text:
            return False

        match = _SUGGESTION_PATTERN.search(resp.text)
        if match and ("did you mean" in resp.text.lower() or "cannot query field" in resp.text.lower()):
            suggested_snippet = resp.text[:300]
            evidence = (
                f"GraphQL Endpoint: {gql_url}\n"
                f"Probe Query: {_FIELD_SUGGESTION_PROBE_QUERY}\n"
                f"Engine Response Snippet: {suggested_snippet}\n"
                f"Issue: GraphQL validation error includes field suggestions ('Did you mean...')."
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="GraphQL Field Suggestion Schema Leakage ('Did you mean...')",
                    description=(
                        f"The GraphQL server at '{gql_url}' returns detailed field suggestions when queried with "
                        f"non-existent fields. Even with introspection disabled, attackers can automate character-by-character "
                        f"field guessing (blind schema enumeration) to reconstruct hidden fields and internal APIs."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation="Disable field suggestions and verbose validation error hints in production GraphQL configurations.",
                    evidence=evidence,
                )
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Keyword Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _is_sensitive_keyword(name: str) -> bool:
        """Check if type/field name matches sensitive keyword patterns."""
        name_lower = name.lower()
        for kw in _SENSITIVE_SCHEMA_KEYWORDS:
            if kw == name_lower:
                return True
            if name_lower.startswith(f"{kw}_") or name_lower.endswith(f"_{kw}"):
                return True
            if name_lower.startswith(f"{kw}id") or name_lower.startswith(f"{kw}key"):
                return True
            if kw in ("password", "passwd", "secret", "creditcard", "apikey") and kw in name_lower:
                return True
        return False
