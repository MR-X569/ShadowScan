"""
app/scanner/plugins/passive/websocket_security.py
-------------------------------------------------
WebSocket Security & Cross-Site WebSocket Hijacking (CSWSH) Analysis Plugin.

Safely discovers WebSocket endpoints and evaluates them for insecure transport
(cleartext ws://) and weak/missing Origin validation during the WebSocket upgrade handshake.

Safety & Guardrails:
    - Handshake testing ONLY.
    - NEVER sends application messages, data frames, or commands after upgrade.
    - NEVER attempts credential attacks or session replay.
    - NEVER performs connection flooding or load testing.
    - Uses strict per-endpoint limits (max 5 candidate paths) and request timeouts.

Checks Performed:
    1. Endpoint Discovery from target URL, HTML scripts, and common paths (/ws, /socket.io, /websocket, etc.).
    2. Transport Security: Insecure cleartext ws:// references on HTTPS applications.
    3. Cross-Site WebSocket Hijacking (CSWSH): Evaluates whether WebSocket upgrade handshakes
       accept arbitrary untrusted cross-origin requests (e.g. Origin: https://evil-attacker.example.com).

Severity Logic:
    - HIGH: WebSocket upgrade handshake accepts untrusted cross-origin in an authenticated/session context (CSWSH).
    - MEDIUM: WebSocket endpoint accepts untrusted Origin without strict origin validation.
    - MEDIUM: Insecure cleartext ws:// transport used in an HTTPS application.
    - LOW: Publicly exposed WebSocket endpoint with permissive static configuration.
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

# Standard candidate WebSocket paths
_CANDIDATE_WS_PATHS: tuple[str, ...] = (
    "/ws",
    "/websocket",
    "/socket.io/",
    "/sockjs/",
    "/graphql-ws",
    "/cable",
)

# Standard WebSocket handshake headers for HTTP 101 testing
_WS_HANDSHAKE_HEADERS: dict[str, str] = {
    "upgrade": "websocket",
    "connection": "Upgrade",
    "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
    "sec-websocket-version": "13",
}

# Untrusted test origin for CSWSH verification
_UNTRUSTED_TEST_ORIGIN: str = "https://evil-attacker.example.com"

# Regex patterns to discover WebSocket references in HTML/JS
_WS_URL_PATTERN: re.Pattern[str] = re.compile(
    r"""(?i)(?:["'])(ws[s]?://[^"'\s<>]+|/(?:ws|websocket|socket\.io|sockjs|cable|graphql-ws)[^"'\s<>]*)(?:["'])"""
)
_INSECURE_WS_REFERENCE: re.Pattern[str] = re.compile(r"""["'](ws://[^"'\s<>]+)["']""", re.IGNORECASE)


class WebSocketSecurityPlugin(BasePlugin):
    """
    Safely inspects WebSocket endpoints for transport security and Cross-Site WebSocket Hijacking.
    """

    name = "websocket_security"
    description = (
        "Detects WebSocket security misconfigurations, insecure cleartext ws:// transport, "
        "and Cross-Site WebSocket Hijacking (CSWSH) caused by weak Origin validation during handshakes."
    )
    category = "passive"
    version = "1.0.0"
    priority = 76

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe WebSocket security analysis against context.target_url and HTML content.
        """
        if not context.target_url:
            self.log("No target URL available — skipping WebSocket security checks.")
            return

        parsed_target = urlparse(context.target_url)
        target_scheme = parsed_target.scheme.lower()
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # 1. Inspect HTML / JavaScript for insecure cleartext ws:// URLs on HTTPS context
        self._check_cleartext_ws_references(context, target_scheme)

        if context.session is None:
            self.log("No HTTP session available — skipping WebSocket handshake checks.")
            return

        client = context.session

        # 2. Discover potential WebSocket endpoints
        endpoints_to_test = self._discover_websocket_endpoints(parsed_target, context)
        if not endpoints_to_test:
            self.log("No candidate WebSocket endpoints detected.")
            return

        self.log(f"Testing {len(endpoints_to_test)} WebSocket candidate endpoint(s): {endpoints_to_test}")

        tested_endpoints: set[str] = set()

        for ep_url in endpoints_to_test[:5]:  # Bounded to max 5 endpoints
            if ep_url in tested_endpoints:
                continue
            tested_endpoints.add(ep_url)

            await self._test_websocket_handshake(
                client,
                ep_url,
                target_origin,
                context,
            )

    # ------------------------------------------------------------------
    # Cleartext Transport Analysis
    # ------------------------------------------------------------------

    def _check_cleartext_ws_references(self, context: ScanContext, target_scheme: str) -> None:
        """Flag insecure ws:// references when the target application runs over HTTPS."""
        html_content = context.html or ""
        if not html_content or target_scheme != "https":
            return

        matches = _INSECURE_WS_REFERENCE.findall(html_content)
        if matches:
            ws_url = matches[0]
            evidence = (
                f"Application Scheme: HTTPS\n"
                f"Discovered Cleartext WebSocket: {ws_url}\n"
                f"Risk: Unencrypted WebSocket connection susceptible to network eavesdropping and MITM tampering."
            )

            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Insecure Cleartext WebSocket (ws://) on HTTPS Application",
                    description=(
                        f"The application runs over HTTPS but references an unencrypted WebSocket URL ('{ws_url}'). "
                        f"Unencrypted WebSocket traffic ('ws://') is transmitted in cleartext and is vulnerable to "
                        f"eavesdropping, credential interception, and Man-In-The-Middle (MITM) session manipulation."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Upgrade all WebSocket connections to use encrypted WebSockets over TLS ('wss://'). "
                        "Ensure the server enforces TLS for all WebSocket endpoints."
                    ),
                    evidence=evidence,
                )
            )

    # ------------------------------------------------------------------
    # Endpoint Discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _discover_websocket_endpoints(parsed_target: Any, context: ScanContext) -> list[str]:
        """Discover candidate WebSocket endpoints from URL, HTML/JS, or standard paths."""
        found: list[str] = []
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # If target URL itself looks like a WebSocket endpoint
        if any(p in parsed_target.path.lower() for p in ("/ws", "/websocket", "/socket.io", "/graphql-ws")):
            found.append(context.target_url)

        # Inspect HTML for WebSocket URLs
        html = context.html or ""
        if html:
            for match in _WS_URL_PATTERN.findall(html):
                clean_url = match.strip("'\"")
                if clean_url.startswith(("ws://", "wss://")):
                    http_url = clean_url.replace("ws://", "http://").replace("wss://", "https://")
                    if http_url not in found:
                        found.append(http_url)
                elif clean_url.startswith("/"):
                    full_url = urljoin(base_url, clean_url)
                    if full_url not in found:
                        found.append(full_url)

        # Append top standard candidate paths if none discovered
        if not found:
            for path in _CANDIDATE_WS_PATHS:
                found.append(urljoin(base_url, path))

        return found

    # ------------------------------------------------------------------
    # Handshake & CSWSH Probing
    # ------------------------------------------------------------------

    async def _test_websocket_handshake(
        self,
        client: Any,
        endpoint_url: str,
        same_origin: str,
        context: ScanContext,
    ) -> None:
        """Perform safe handshake with untrusted cross-origin to verify Origin validation."""
        headers = dict(_WS_HANDSHAKE_HEADERS)
        headers["origin"] = _UNTRUSTED_TEST_ORIGIN

        try:
            response = await client.get(endpoint_url, headers=headers, follow_redirects=False)

            is_101_upgrade = response.status_code == 101
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            has_ws_accept = "sec-websocket-accept" in resp_headers
            is_upgrade_resp = resp_headers.get("upgrade", "").lower() == "websocket"

            # Check if server accepted the cross-origin handshake
            if is_101_upgrade and (has_ws_accept or is_upgrade_resp):
                # Verify if cookies / session are present in context
                has_session_context = bool(context.cookies) or "set-cookie" in resp_headers

                severity = Severity.HIGH if has_session_context else Severity.MEDIUM

                evidence = (
                    f"Tested WebSocket Endpoint: {endpoint_url}\n"
                    f"Supplied Untrusted Origin: {_UNTRUSTED_TEST_ORIGIN}\n"
                    f"Handshake Response Status: HTTP {response.status_code} Switching Protocols\n"
                    f"Sec-WebSocket-Accept Header: {resp_headers.get('sec-websocket-accept', 'Present')}\n"
                    f"Session Context Observed: {'Yes (Cookies present)' if has_session_context else 'No'}\n"
                    f"Evaluation: Server accepted cross-origin WebSocket connection without Origin validation."
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Cross-Site WebSocket Hijacking (CSWSH) / Weak Origin: {urlparse(endpoint_url).path or '/'}",
                        description=(
                            f"The WebSocket endpoint at '{endpoint_url}' accepts WebSocket upgrade handshakes "
                            f"from arbitrary untrusted origins ('{_UNTRUSTED_TEST_ORIGIN}'). "
                            f"If the application relies on ambient credentials (such as session cookies or HTTP auth), "
                            f"an attacker can establish a cross-origin WebSocket connection from a malicious site to hijack "
                            f"the user's real-time communication channel, execute unauthorized commands, or exfiltrate private messages."
                        ),
                        severity=severity,
                        recommendation=(
                            "Implement strict server-side validation of the 'Origin' header during the WebSocket upgrade handshake. "
                            "Reject any handshake requests originating from untrusted or missing Origin domains. "
                            "Additionally, require one-time anti-CSRF tokens or cryptographically signed session tokens during connection establishment."
                        ),
                        evidence=evidence,
                    )
                )

        except Exception as exc:
            self.log(f"WebSocket handshake test against '{endpoint_url}' failed: {exc}")
