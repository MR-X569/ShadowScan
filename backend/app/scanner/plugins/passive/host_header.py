"""
app/scanner/plugins/passive/host_header.py
-----------------------------------------
Host Header & Host Header Injection Analysis Plugin.

Safely tests if the application trusts attacker-controlled Host-related headers
and reflects them into security-sensitive locations (redirects, canonical links,
or password-reset URL constructions) using a benign, controlled probe domain.

Headers Evaluated:
    - Host
    - X-Forwarded-Host
    - X-Host
    - X-Forwarded-Server
    - Forwarded (host=...)

Controlled Probe Domain:
    - shadowscan-host-probe.example (RFC 2606 reserved .example domain)

Safety & Guardrails:
    - Purely GET requests; NEVER submits password-reset forms or alters account state.
    - NEVER sends emails, triggers actual password resets, or poisons shared caches.
    - Compares responses against baseline to ensure markers were not pre-existing.
    - Scoped strictly to the target endpoint.

Severity Logic:
    - Redirect Location Poisoning (Location header contains probe host) -> HIGH
    - Password-Reset / Recovery Link Poisoning Indicator -> HIGH
    - Canonical URL / Absolute Resource Link Poisoning -> MEDIUM
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# RFC 2606 safe reserved test host
_PROBE_HOST: str = "shadowscan-host-probe.example"

# Header test cases to evaluate independently
_HOST_HEADER_PROBES: list[tuple[str, dict[str, str]]] = [
    ("X-Forwarded-Host Header", {"X-Forwarded-Host": _PROBE_HOST}),
    ("Forwarded Header", {"Forwarded": f"host={_PROBE_HOST};proto=https"}),
    ("X-Host Header", {"X-Host": _PROBE_HOST}),
    ("X-Forwarded-Server Header", {"X-Forwarded-Server": _PROBE_HOST}),
    ("Host Header Override", {"Host": _PROBE_HOST}),
]

# Sensitive URL context indicators (e.g. password reset / account recovery)
_RESET_LINK_REGEX: re.Pattern[str] = re.compile(
    r"(?:reset[-_]?password|forgot[-_]?password|password[-_]?recovery|auth/reset|account/reset)",
    re.IGNORECASE,
)


class HostHeaderPlugin(BasePlugin):
    """
    Safely evaluates application trust and reflection of Host-related request headers.
    """

    name = "host_header"
    description = (
        "Detects Host Header Injection vulnerabilities where untrusted Host or "
        "X-Forwarded-Host headers are reflected into redirects, canonical URLs, or links."
    )
    category = "passive"
    version = "1.0.0"
    priority = 68

    async def run(self, context: ScanContext) -> None:
        """
        Execute Host header injection probes against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping Host Header analysis.")
            return

        client = context.session
        target_url = context.target_url
        baseline_text = context.html or ""
        baseline_headers = {k.lower(): v for k, v in (context.headers or {}).items()}

        # If baseline already contained the probe marker, skip to avoid false positives
        if _PROBE_HOST in baseline_text or _PROBE_HOST in str(baseline_headers):
            self.log("Probe host already present in baseline — skipping.")
            return

        self.log(f"Testing Host Header reflection on '{target_url}' with probe host '{_PROBE_HOST}'.")

        for probe_name, custom_headers in _HOST_HEADER_PROBES:
            await self._test_host_probe(
                client,
                target_url,
                probe_name,
                custom_headers,
                baseline_text,
                baseline_headers,
                context,
            )

    # ------------------------------------------------------------------
    # Probe Execution & Differential Analysis
    # ------------------------------------------------------------------

    async def _test_host_probe(
        self,
        client: Any,
        target_url: str,
        probe_name: str,
        custom_headers: dict[str, str],
        baseline_text: str,
        baseline_headers: dict[str, str],
        context: ScanContext,
    ) -> None:
        """Send GET request with custom Host header and analyze response reflections."""
        try:
            # We pass custom headers without following redirects automatically to inspect Location headers
            response = await client.get(target_url, headers=custom_headers)
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            resp_text = response.text or ""

            # Check 1: Redirect Location Header Poisoning (HIGH)
            location_header = resp_headers.get("location", "")
            if _PROBE_HOST in location_header and _PROBE_HOST not in baseline_headers.get("location", ""):
                evidence = (
                    f"Injected Header: {custom_headers}\n"
                    f"Probe Technique: {probe_name}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Reflected Location Header: {location_header}\n"
                    f"Evaluation: Server constructed redirect Location using untrusted Host-related header."
                )
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Host Header Injection: Open Redirect via {probe_name}",
                        description=(
                            f"The target application accepts untrusted '{probe_name}' values and constructs HTTP redirect "
                            f"Location headers pointing to the attacker-supplied host ('{location_header}'). "
                            f"An attacker can exploit this behavior to perform open redirection, OAuth token interception, "
                            f"or web cache poisoning."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            "Validate the Host and X-Forwarded-Host headers against a strict whitelist of approved server domains. "
                            "Do not dynamically construct redirect URLs using untrusted Host header values."
                        ),
                        evidence=evidence,
                    )
                )
                return

            # Check 2: Password-Reset / Recovery Link Poisoning Indicator in Body (HIGH)
            if _PROBE_HOST in resp_text and _PROBE_HOST not in baseline_text:
                if _RESET_LINK_REGEX.search(resp_text):
                    evidence = (
                        f"Injected Header: {custom_headers}\n"
                        f"Probe Technique: {probe_name}\n"
                        f"HTTP Status: {response.status_code}\n"
                        f"Observed Host Reflection: Marker '{_PROBE_HOST}' appears near password reset / auth link.\n\n"
                        f"Response Excerpt:\n{self._extract_snippet(resp_text, _PROBE_HOST)}"
                    )
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Host Header Injection: Password Reset / Link Poisoning Risk via {probe_name}",
                            description=(
                                f"The application reflects untrusted '{probe_name}' values into authentication or password reset "
                                f"related links. In password recovery workflows, this allows attackers to poison password reset "
                                f"emails, causing reset links to send user recovery tokens to attacker-controlled servers."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                "Configure web servers (e.g. Nginx/Apache) to drop unknown Host/Forwarded headers, "
                                "and use static server domain configurations in application URL generators."
                            ),
                            evidence=evidence,
                        )
                    )
                    return

                # Check 3: Canonical URL / Link Poisoning in HTML (MEDIUM)
                # Look for <link rel="canonical" href="..."> or <meta property="og:url" content="...">
                is_canonical_or_script = (
                    f'rel="canonical" href="http' in resp_text and _PROBE_HOST in resp_text
                ) or (
                    f'property="og:url" content="http' in resp_text and _PROBE_HOST in resp_text
                ) or (
                    f'<script src="http' in resp_text and _PROBE_HOST in resp_text
                )

                if is_canonical_or_script:
                    evidence = (
                        f"Injected Header: {custom_headers}\n"
                        f"Probe Technique: {probe_name}\n"
                        f"HTTP Status: {response.status_code}\n"
                        f"Observed Host Reflection: Injected host '{_PROBE_HOST}' used to generate canonical/script URLs.\n\n"
                        f"Response Excerpt:\n{self._extract_snippet(resp_text, _PROBE_HOST)}"
                    )
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Host Header Injection: Web Resource / Canonical URL Poisoning via {probe_name}",
                            description=(
                                f"The application reflects the untrusted '{probe_name}' into canonical links, metadata, "
                                f"or absolute script URLs. If a caching proxy or CDN caches this response, all visitors "
                                f"will receive poisoned links, leading to web cache poisoning or cross-site scripting."
                            ),
                            severity=Severity.MEDIUM,
                            recommendation=(
                                "Hardcode canonical base domain configurations and configure front-end reverse proxies "
                                "to override or strip untrusted X-Forwarded-Host / Forwarded headers."
                            ),
                            evidence=evidence,
                        )
                    )
                    return

        except Exception as exc:
            self.log(f"Host header probe '{probe_name}' failed: {exc}")

    @staticmethod
    def _extract_snippet(text: str, marker: str) -> str:
        """Extract a short snippet around the reflected marker."""
        idx = text.find(marker)
        if idx == -1:
            return text[:200].strip()
        start = max(0, idx - 60)
        end = min(len(text), idx + len(marker) + 60)
        return text[start:end].strip()
