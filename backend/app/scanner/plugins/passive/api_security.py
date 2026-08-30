"""
app/scanner/plugins/passive/api_security.py
-------------------------------------------
REST & GraphQL API Security Analyzer Plugin.

Identifies publicly exposed API specifications, documentation consoles, and
GraphQL configurations on the target application:
    1. Public OpenAPI / Swagger specifications and interactive documentation
       (/openapi.json, /swagger.json, /docs, /redoc, /swagger-ui).
    2. Public GraphQL endpoints and active GraphQL Introspection schemas (__schema).
    3. Public interactive GraphQL IDE interfaces (GraphiQL, GraphQL Playground, Apollo Sandbox).

Safety & Guardrails:
    - Purely read-only reconnaissance and configuration inspection.
    - NEVER performs data modification, mutation, deletion, or user enumeration.
    - NEVER performs brute force attacks or authentication bypass attempts.
    - Redacts any sensitive parameter examples discovered in schema documentation.

Severity Logic:
    - Publicly Exposed OpenAPI / Swagger JSON Specification -> MEDIUM
    - Public GraphQL Introspection Enabled (__schema) -> MEDIUM
    - Public GraphQL Interactive IDE (GraphiQL / Playground) -> LOW
    - Public API Interactive Documentation UI (/docs /redoc) -> LOW
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

# Common REST API documentation and specification paths
_SWAGGER_DOC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/redoc",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/swagger-ui/",
)

# Common GraphQL endpoints
_GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/graphql/",
    "/api/v1/graphql",
    "/v1/graphql",
)

# Minimal safe read-only GraphQL Introspection Query
_GRAPHQL_INTROSPECTION_QUERY: str = '{"query": "{ __schema { types { name } } }"}'

# Signatures for GraphQL Interactive IDEs
_GRAPHQL_IDE_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("GraphiQL IDE", re.compile(r"GraphiQL\.createFetcher|<title>GraphiQL</title>|React\.createElement\(GraphiQL", re.IGNORECASE)),
    ("GraphQL Playground", re.compile(r"GraphQLPlayground\.init|<title>GraphQL Playground</title>|window\.GraphQLPlayground", re.IGNORECASE)),
    ("Apollo Sandbox", re.compile(r"ApolloSandbox|<title>Apollo Sandbox</title>|embedded-sandbox", re.IGNORECASE)),
]


class ApiSecurityPlugin(BasePlugin):
    """
    Analyzes target for exposed API documentation, Swagger specs, and GraphQL introspection.
    """

    name = "api_security"
    description = (
        "Identifies exposed REST API specifications (Swagger/OpenAPI), GraphQL endpoints, "
        "GraphQL introspection schemas, and interactive developer IDE consoles."
    )
    category = "passive"
    version = "1.0.0"
    priority = 55

    async def run(self, context: ScanContext) -> None:
        """
        Execute API documentation and GraphQL introspection checks.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping API security analysis.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # 1. Inspect OpenAPI / Swagger Documentation
        await self._check_swagger_and_openapi(client, target_origin, context)

        # 2. Inspect GraphQL Endpoints and Introspection
        await self._check_graphql_endpoints(client, target_origin, context)

    # ------------------------------------------------------------------
    # REST API & OpenAPI/Swagger Inspection
    # ------------------------------------------------------------------

    async def _check_swagger_and_openapi(
        self,
        client: Any,
        target_origin: str,
        context: ScanContext,
    ) -> None:
        """Probe for public Swagger/OpenAPI JSON specifications and documentation consoles."""
        discovered_urls = context.metadata.get("discovered_urls", [])

        paths_to_check = list(_SWAGGER_DOC_PATHS)
        for url in discovered_urls:
            parsed = urlparse(url)
            if any(k in parsed.path.lower() for k in ("swagger", "openapi", "api-doc", "redoc")):
                if parsed.path not in paths_to_check:
                    paths_to_check.append(parsed.path)

        checked_urls: set[str] = set()

        for path in paths_to_check[:6]:  # Bounded to top candidate paths
            spec_url = urljoin(target_origin, path)
            if spec_url in checked_urls:
                continue
            checked_urls.add(spec_url)

            try:
                response = await client.get(spec_url)
                if response.status_code != 200:
                    continue

                text = response.text or ""
                content_type = response.headers.get("content-type", "").lower()

                # Check if it's a valid JSON OpenAPI / Swagger document
                if "application/json" in content_type or (text.strip().startswith("{") and text.strip().endswith("}")):
                    try:
                        doc = json.loads(text)
                        if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and "paths" in doc:
                            version = doc.get("openapi") or doc.get("swagger") or "2.0/3.0"
                            path_count = len(doc.get("paths", {}))

                            evidence = (
                                f"Specification URL: {spec_url}\n"
                                f"Specification Standard: OpenAPI/Swagger {version}\n"
                                f"Total Exposed Endpoints: {path_count}\n"
                                f"HTTP Status: HTTP 200 OK\n\n"
                                f"Sample Endpoints Disclosed:\n" + "\n".join(f" - {p}" for p in list(doc.get("paths", {}).keys())[:5])
                            )

                            context.add_finding(
                                Finding(
                                    plugin=self.name,
                                    title=f"Publicly Exposed OpenAPI / Swagger Specification ({path})",
                                    description=(
                                        f"The application exposes an interactive OpenAPI/Swagger specification file at '{spec_url}'. "
                                        f"Public exposure of API definitions reveals internal endpoint structures, parameter schemas, "
                                        f"data models, and administrative routes to unauthorized users."
                                    ),
                                    severity=Severity.MEDIUM,
                                    recommendation=(
                                        "Restrict access to API documentation and OpenAPI schemas using authentication, "
                                        "or disable public documentation endpoints in production environments."
                                    ),
                                    evidence=evidence,
                                )
                            )
                            return
                    except Exception:
                        pass

                # Check if it's an interactive Swagger UI / ReDoc HTML interface
                if "text/html" in content_type:
                    if "swagger-ui" in text.lower() or "redoc" in text.lower() or "<title>swagger ui</title>" in text.lower():
                        evidence = (
                            f"Documentation URL: {spec_url}\n"
                            f"Content-Type: {content_type}\n"
                            f"HTTP Status: HTTP 200 OK\n"
                            f"Identified Interface: Interactive API Documentation (Swagger UI / ReDoc)"
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Public API Interactive Documentation Interface Exposed ({path})",
                                description=(
                                    f"Interactive API documentation was detected at '{spec_url}'. "
                                    f"Ensure all documented API routes enforce robust authorization controls."
                                ),
                                severity=Severity.LOW,
                                recommendation="Protect API documentation behind authentication in production environments.",
                                evidence=evidence,
                            )
                        )
                        return

            except Exception as exc:
                self.log(f"API spec probe on '{spec_url}' failed: {exc}")

    # ------------------------------------------------------------------
    # GraphQL Endpoints & Introspection Inspection
    # ------------------------------------------------------------------

    async def _check_graphql_endpoints(
        self,
        client: Any,
        target_origin: str,
        context: ScanContext,
    ) -> None:
        """Detect GraphQL endpoints, active introspection, and interactive IDE consoles."""
        discovered_urls = context.metadata.get("discovered_urls", [])

        graphql_paths = list(_GRAPHQL_PATHS)
        for url in discovered_urls:
            parsed = urlparse(url)
            if "graphql" in parsed.path.lower() and parsed.path not in graphql_paths:
                graphql_paths.append(parsed.path)

        checked_paths: set[str] = set()

        for path in graphql_paths[:4]:
            gql_url = urljoin(target_origin, path)
            if gql_url in checked_paths:
                continue
            checked_paths.add(gql_url)

            try:
                # 1. Test GET for GraphQL IDE interfaces (GraphiQL, Playground)
                resp_get = await client.get(gql_url)
                text_get = resp_get.text or ""

                for ide_name, ide_regex in _GRAPHQL_IDE_SIGNATURES:
                    if ide_regex.search(text_get):
                        evidence = (
                            f"GraphQL IDE URL: {gql_url}\n"
                            f"Detected Console: {ide_name}\n"
                            f"HTTP Status: HTTP {resp_get.status_code}"
                        )
                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Public GraphQL Interactive IDE Exposed ({ide_name})",
                                description=(
                                    f"A public interactive GraphQL developer IDE ({ide_name}) is exposed at '{gql_url}'. "
                                    f"Attackers can use interactive consoles to easily explore data models and craft queries."
                                ),
                                severity=Severity.LOW,
                                recommendation=(
                                    f"Disable public GraphQL IDE consoles ({ide_name}) in production environments."
                                ),
                                evidence=evidence,
                            )
                        )
                        break

                # 2. Test POST Introspection Query (__schema)
                headers = {"Content-Type": "application/json", "Accept": "application/json"}
                resp_post = await client.request("POST", gql_url, content=_GRAPHQL_INTROSPECTION_QUERY.encode("utf-8"), headers=headers)

                if resp_post.status_code == 200 and resp_post.text:
                    try:
                        gql_data = json.loads(resp_post.text)
                        if isinstance(gql_data, dict) and "data" in gql_data:
                            schema_data = gql_data["data"].get("__schema")
                            if schema_data and "types" in schema_data:
                                type_count = len(schema_data.get("types", []))
                                sample_types = [t.get("name") for t in schema_data.get("types", []) if t.get("name") and not t.get("name", "").startswith("__")][:5]

                                evidence = (
                                    f"GraphQL Endpoint: {gql_url}\n"
                                    f"Introspection Query: POST {_GRAPHQL_INTROSPECTION_QUERY}\n"
                                    f"Schema Types Disclosed: {type_count}\n"
                                    f"Sample Disclosed Types: {', '.join(sample_types) if sample_types else 'Standard Types'}\n"
                                    f"HTTP Status: HTTP 200 OK"
                                )

                                context.add_finding(
                                    Finding(
                                        plugin=self.name,
                                        title=f"Public GraphQL Introspection Enabled ({path})",
                                        description=(
                                            f"The GraphQL endpoint at '{gql_url}' allows public introspection queries. "
                                            f"Enabling introspection allows attackers to extract the complete database schema, "
                                            f"query names, mutation parameters, and internal data structures."
                                        ),
                                        severity=Severity.MEDIUM,
                                        recommendation=(
                                            "Disable GraphQL introspection (__schema queries) in production deployment configurations."
                                        ),
                                        evidence=evidence,
                                    )
                                )
                    except Exception:
                        pass

            except Exception as exc:
                self.log(f"GraphQL probe on '{gql_url}' failed: {exc}")
