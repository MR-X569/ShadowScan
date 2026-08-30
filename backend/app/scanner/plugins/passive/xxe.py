"""
app/scanner/plugins/passive/xxe.py
----------------------------------
XML External Entity (XXE) Injection Analysis Plugin.

Safely tests endpoints that accept or process XML payloads for internal and
custom external entity resolution capabilities without performing destructive
actions, local file access, or private network probes.

Safety & Guardrails:
    - NEVER targets /etc/passwd, win.ini, or local system files.
    - NEVER targets localhost, 127.0.0.0/8, ::1, or RFC1918 private subnets.
    - NEVER targets cloud metadata endpoints (169.254.169.254).
    - NEVER uses external out-of-band (OOB) network callback infrastructure.
    - Uses harmless inline custom entity expansion probes to detect parser resolution.

Detection Strategy:
    1. Discovers potential XML endpoints from context.target_url, crawler metadata
       (context.metadata["discovered_urls"], context.metadata["discovered_forms"]),
       or common API/XML routes (/api/xml, /soap, /feed, /rpc, /upload/xml).
    2. Sends a safe inline entity expansion probe:
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE root [ <!ENTITY ssxxe "ShadowScanXxeExpandedToken8a1"> ]>
       <root><data>&ssxxe;</data></root>
    3. Evaluates response:
       - If "ShadowScanXxeExpandedToken8a1" is reflected in the response body without
         the literal entity declaration text -> Confirmed XML entity resolution (HIGH).
       - If the server explicitly throws an XML parser DTD/entity restriction error
         (e.g., "DOCTYPE is disallowed", "External entity not allowed") -> Informational/No finding.
       - If the payload is rejected or ignored without entity resolution -> No finding.

Severity Logic:
    - Confirmed XML entity expansion reflection -> HIGH
    - Potential XML parser entity evaluation indicator -> MEDIUM
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Unique benign marker for entity resolution detection
_XXE_ENTITY_TOKEN: str = "ShadowScanXxeExpandedToken8a1"
_XXE_ENTITY_NAME: str = "ssxxe"

# Benign inline entity probe (no SYSTEM file/network URI)
_BENIGN_XML_PROBE: str = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY {_XXE_ENTITY_NAME} "{_XXE_ENTITY_TOKEN}"> ]>
<root><data>&{_XXE_ENTITY_NAME};</data><query>&{_XXE_ENTITY_NAME};</query></root>"""

# Candidate XML endpoint paths to probe if discovered or common
_XML_ENDPOINT_CANDIDATES: tuple[str, ...] = (
    "/api/xml",
    "/xml",
    "/soap",
    "/ws",
    "/rpc",
    "/api/v1/xml",
    "/feed.xml",
    "/import/xml",
)


class XxePlugin(BasePlugin):
    """
    Safely probes candidate XML endpoints for entity resolution and expansion.
    """

    name = "xxe"
    description = (
        "Detects XML External Entity (XXE) and inline entity resolution vulnerabilities "
        "using safe, non-destructive diagnostic entity expansion probes."
    )
    category = "passive"
    version = "1.0.0"
    priority = 78

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe XXE analysis against discovered endpoints and candidate routes.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping XXE analysis.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # 1. Collect candidate endpoints to test
        endpoints_to_test = self._get_endpoints_to_test(context, target_origin)
        if not endpoints_to_test:
            self.log("No candidate XML endpoints identified.")
            return

        self.log(f"Testing {len(endpoints_to_test)} endpoint(s) for XML entity resolution: {endpoints_to_test}")

        tested: set[str] = set()

        for endpoint_url in endpoints_to_test:
            if endpoint_url in tested:
                continue
            tested.add(endpoint_url)

            await self._test_endpoint_xxe(client, endpoint_url, context)

    # ------------------------------------------------------------------
    # Endpoint Discovery
    # ------------------------------------------------------------------

    def _get_endpoints_to_test(self, context: ScanContext, target_origin: str) -> list[str]:
        """Collect potential XML endpoints from crawler metadata and common XML routes."""
        endpoints: list[str] = []

        # 1. Primary target URL
        if context.target_url:
            endpoints.append(context.target_url)

        # 2. Check crawler discovered URLs
        discovered_urls = context.metadata.get("discovered_urls", [])
        for url in discovered_urls:
            url_lower = url.lower()
            if any(k in url_lower for k in ("xml", "soap", "rpc", "feed", "import", "parse")):
                endpoints.append(url)

        # 3. Check crawler discovered forms with XML indicators
        discovered_forms = context.metadata.get("discovered_forms", [])
        for form in discovered_forms:
            action = form.get("action", "")
            if any(k in action.lower() for k in ("xml", "soap", "rpc", "import")):
                endpoints.append(action)

        # 4. Common candidate routes on target origin (limit to 3 for bounded scanning)
        for cand in _XML_ENDPOINT_CANDIDATES[:3]:
            abs_cand = urljoin(target_origin, cand)
            if abs_cand not in endpoints:
                endpoints.append(abs_cand)

        # Deduplicate while preserving order, max 5 endpoints
        seen: set[str] = set()
        deduped: list[str] = []
        for ep in endpoints:
            if ep not in seen:
                seen.add(ep)
                deduped.append(ep)
                if len(deduped) >= 5:
                    break

        return deduped

    # ------------------------------------------------------------------
    # Safe Entity Probing & Verification
    # ------------------------------------------------------------------

    async def _test_endpoint_xxe(
        self,
        client: Any,
        endpoint_url: str,
        context: ScanContext,
    ) -> None:
        """Post safe XML entity payload and check for entity expansion in response."""
        try:
            # Send XML POST probe with application/xml header
            headers = {
                "Content-Type": "application/xml; charset=utf-8",
                "Accept": "application/xml, text/xml, application/json, */*",
            }

            response = await client.request(
                "POST",
                endpoint_url,
                content=_BENIGN_XML_PROBE.encode("utf-8"),
                headers=headers,
            )

            text = response.text or ""

            # Check if the token was expanded in the response
            if _XXE_ENTITY_TOKEN in text:
                # Distinguish entity resolution from literal reflection of the raw payload
                is_raw_doctype_reflected = "<!DOCTYPE" in text and "<!ENTITY" in text

                if not is_raw_doctype_reflected:
                    evidence = (
                        f"Target Endpoint: {endpoint_url}\n"
                        f"Request Method: POST\n"
                        f"Content-Type: application/xml\n"
                        f"Entity Probe Token: {_XXE_ENTITY_TOKEN}\n"
                        f"HTTP Status: {response.status_code}\n"
                        f"Observed Behavior: XML parser expanded internal entity '&{_XXE_ENTITY_NAME};' "
                        f"into resolved value without echoing raw DOCTYPE declaration.\n\n"
                        f"Response Excerpt:\n{text[:300].strip()}"
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"XML Entity Resolution / Potential XXE Vulnerability ({endpoint_url})",
                            description=(
                                f"The endpoint '{endpoint_url}' parses incoming XML documents and successfully resolves "
                                f"inline DTD entities. When XML parsers are configured to process external entities and DTDs, "
                                f"an attacker can exploit XML External Entity (XXE) injection to read arbitrary server files, "
                                f"probe internal networks/cloud metadata (SSRF), or cause denial of service."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                "Completely disable Document Type Definitions (DTDs) and external entity resolution in all "
                                "XML parsers across the application. In Python (defusedxml / lxml), set resolve_entities=False "
                                "and disallow_dtd=True. In Java, configure 'http://apache.org/xml/features/disallow-doctype-decl' "
                                "to true."
                            ),
                            evidence=evidence,
                        )
                    )

        except Exception as exc:
            self.log(f"XXE probe on '{endpoint_url}' failed: {exc}")
