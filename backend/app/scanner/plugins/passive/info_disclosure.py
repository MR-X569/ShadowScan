"""
app/scanner/plugins/passive/info_disclosure.py
----------------------------------------------
Information Disclosure & Banner Grabbing Plugin — identifies exposed server banners,
technology versions, debug traces, stack traces, database errors, and sensitive
configuration files.

Checks performed:
    - Server header detailed version disclosure
    - X-Powered-By and framework version headers
    - Internal diagnostic / infrastructure headers
    - Stack trace and debug error disclosure in response body
      (Python, Node.js, PHP, Java/Spring, ASP.NET, SQL errors)
    - Targeted sensitive file / configuration exposure probes
      (/.env, /.git/HEAD, /.git/config, /phpinfo.php, /actuator/env)

Severity Logic:
    - Exposed environment file (.env) with credentials -> CRITICAL
    - Application stack trace / debug console exposed -> HIGH
    - Exposed Git repository (.git/HEAD, .git/config) -> HIGH
    - Exposed phpinfo() diagnostic page -> HIGH
    - Exposed Spring Boot Actuator environment -> HIGH
    - Detailed server / framework version header -> LOW
    - Internal infrastructure / diagnostic headers -> LOW
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Header Inspection Regexes
# ---------------------------------------------------------------------------

# Matches detailed version strings (e.g., Apache/2.4.41, nginx/1.18.0, IIS/10.0, PHP/8.1.2)
_VERSION_REGEX: re.Pattern[str] = re.compile(
    r"[a-zA-Z_-]+/\d+\.[\d.]+[a-zA-Z0-9_.-]*"
)

# Headers that often disclose technology names and versions
_TECH_HEADERS: tuple[str, ...] = (
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-version",
)

# Diagnostic or infrastructure routing headers
_INFRA_HEADERS: tuple[str, ...] = (
    "x-backend-server",
    "x-served-by",
    "x-debug-token",
    "x-debug-token-link",
    "x-sourcemap",
    "x-varnish",
)


# ---------------------------------------------------------------------------
# Stack Trace & Debug Signature Regexes
# ---------------------------------------------------------------------------

_DEBUG_SIGNATURES: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "Python Stack Trace / Debug Mode",
        re.compile(
            r"Traceback \(most recent call last\):[\s\S]*?File \".*?\", line \d+"
            r"|Werkzeug Debugger|You're seeing this error because you have DEBUG = True in your Django settings",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Python traceback or interactive debug console detected in HTTP response body.",
    ),
    (
        "Node.js Stack Trace",
        re.compile(
            r"(?:TypeError|ReferenceError|SyntaxError|Error): .*?\n\s+at (?:[\w.<>]+ )?\(?(?:node:|\/|[A-Za-z]:\\|[a-zA-Z0-9_/-]+\.js:\d+:\d+)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Node.js runtime stack trace with source file paths and line numbers detected.",
    ),
    (
        "PHP Error / Stack Trace",
        re.compile(
            r"(?:Fatal error|Parse error|Warning): .*? in (?:/|[A-Za-z]:\\).*? on line \d+"
            r"|Stack trace:\s*#0\s+.*?",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "PHP fatal error, warning, or detailed call stack trace exposed in response body.",
    ),
    (
        "Java / Spring Stack Trace",
        re.compile(
            r"(?:java\.lang\.\w+Exception|org\.springframework\.\w+Exception): .*?\n\s+at (?:[a-zA-Z0-9_$.]+\.)+[a-zA-Z0-9_$]+\([a-zA-Z0-9_$]+\.java:\d+\)"
            r"|Whitelabel Error Page[\s\S]*?This application has no explicit mapping for /error",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Java exception stack trace or Spring Whitelabel debug error page exposed.",
    ),
    (
        "ASP.NET Detailed Error Page",
        re.compile(
            r"Server Error in '.*?' Application\.|System\.Web\.HttpUnhandledException|\[InvalidOperationException\]",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "ASP.NET detailed yellow-screen-of-death or exception dump exposed in response body.",
    ),
    (
        "Database Error / SQL Diagnostic Message",
        re.compile(
            r"(?:SQL syntax error|ODBC SQL Server Driver|PG::SyntaxError|ORA-\d{5}|mysql_fetch_array\(\)|SQLite3::SQLException|com\.mysql\.jdbc\.exceptions)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Database query syntax error or database driver error message disclosed in response.",
    ),
]


# ---------------------------------------------------------------------------
# Sensitive File Probe Definitions
# ---------------------------------------------------------------------------

@dataclass
class _FileProbe:
    path: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    signature_regex: re.Pattern[str]
    anti_signature_regex: re.Pattern[str] | None = None


_SENSITIVE_FILE_PROBES: list[_FileProbe] = [
    _FileProbe(
        path="/.env",
        title="Exposed Environment File (.env)",
        severity=Severity.CRITICAL,
        description=(
            "An environment configuration file (.env) is publicly accessible on the web server. "
            "This file typically contains highly sensitive credentials including database passwords, "
            "API tokens, encryption keys, and service secrets."
        ),
        recommendation=(
            "Immediately restrict web access to .env files in your web server configuration (e.g. Nginx, Apache), "
            "and rotate all secrets, passwords, and tokens contained within the exposed file."
        ),
        signature_regex=re.compile(
            r"(?:DB_PASSWORD|SECRET_KEY|APP_KEY|AWS_SECRET_ACCESS_KEY|DATABASE_URL|JWT_SECRET|REDIS_URL|API_KEY)\s*=",
            re.IGNORECASE,
        ),
        anti_signature_regex=re.compile(r"<!DOCTYPE html|<html", re.IGNORECASE),
    ),
    _FileProbe(
        path="/.git/HEAD",
        title="Exposed Git Repository Metadata (.git/HEAD)",
        severity=Severity.HIGH,
        description=(
            "The '.git/HEAD' repository metadata file is publicly accessible. Attackers can download "
            "the complete Git repository, recovering full source code, commit history, branch names, "
            "and previously committed credentials."
        ),
        recommendation=(
            "Block public web access to the '.git' directory across all web server and proxy configurations. "
            "Ensure deployment pipelines exclude version control directories."
        ),
        signature_regex=re.compile(r"^ref:\s*refs/|[0-9a-fA-F]{40}"),
        anti_signature_regex=re.compile(r"<!DOCTYPE html|<html", re.IGNORECASE),
    ),
    _FileProbe(
        path="/.git/config",
        title="Exposed Git Configuration (.git/config)",
        severity=Severity.HIGH,
        description=(
            "The '.git/config' file is publicly accessible, disclosing internal repository URLs, "
            "remote origin endpoints, and potentially embedded access tokens."
        ),
        recommendation=(
            "Deny HTTP access to all files and directories beginning with '.git'."
        ),
        signature_regex=re.compile(r"\[core\]|repositoryformatversion\s*="),
        anti_signature_regex=re.compile(r"<!DOCTYPE html|<html", re.IGNORECASE),
    ),
    _FileProbe(
        path="/phpinfo.php",
        title="Exposed phpinfo() Diagnostic Page",
        severity=Severity.HIGH,
        description=(
            "A public phpinfo() diagnostic script was detected. This page exposes detailed system "
            "architecture, loaded PHP extensions, file system paths, environment variables, "
            "and server configuration details."
        ),
        recommendation=(
            "Remove or restrict access to phpinfo.php scripts on production servers."
        ),
        signature_regex=re.compile(r"<title>phpinfo\(\)</title>|PHP Version \d+\.\d+", re.IGNORECASE),
    ),
    _FileProbe(
        path="/actuator/env",
        title="Exposed Spring Boot Actuator Environment",
        severity=Severity.HIGH,
        description=(
            "The Spring Boot Actuator '/actuator/env' endpoint is publicly accessible without authentication, "
            "exposing active profiles, configuration properties, and environment variables."
        ),
        recommendation=(
            "Secure Spring Boot Actuator endpoints using Spring Security or disable exposure of sensitive endpoints in application.properties."
        ),
        signature_regex=re.compile(r'"propertySources"|"activeProfiles"|"systemProperties"', re.IGNORECASE),
    ),
]


# ---------------------------------------------------------------------------
# Plugin Class
# ---------------------------------------------------------------------------

class InfoDisclosurePlugin(BasePlugin):
    """
    Scans for information disclosure via HTTP headers, response body stack traces,
    and targeted sensitive file exposure checks.
    """

    name = "info_disclosure"
    description = (
        "Detects exposed server banners, technology versions, debug stack traces, "
        "and accidentally exposed sensitive configuration files."
    )
    category = "passive"
    version = "1.0.0"
    priority = 35

    async def run(self, context: ScanContext) -> None:
        """
        Execute information disclosure detection against context headers, body,
        and targeted lightweight file probes.
        """
        # 1. Inspect HTTP Response Headers
        self._check_headers(context)

        # 2. Inspect Response Body / HTML for Stack Traces & Debug Info
        self._check_response_body(context)

        # 3. Perform Targeted Sensitive File Probes (if session available)
        if context.session is not None and context.target_url:
            await self._probe_sensitive_files(context)

    # ------------------------------------------------------------------
    # Header Analysis
    # ------------------------------------------------------------------

    def _check_headers(self, context: ScanContext) -> None:
        """Inspect HTTP response headers for version banners and diagnostic leaks."""
        if not context.headers:
            return

        headers_lower = {k.lower(): v for k, v in context.headers.items()}

        # 1. Server Header Check
        server_val = headers_lower.get("server", "").strip()
        if server_val and _VERSION_REGEX.search(server_val):
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Detailed Server Version Banner Disclosed",
                    description=(
                        f"The web server reveals its exact software and version in the 'Server' header: '{server_val}'. "
                        f"Disclosing specific version numbers allows attackers to quickly identify known CVEs "
                        f"and tailor targeted exploits against the infrastructure."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Configure your web server to suppress or minimize the 'Server' header banner. "
                        "For example, set 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx."
                    ),
                    evidence=f"Server: {server_val}",
                )
            )

        # 2. Technology & Framework Headers (X-Powered-By, etc.)
        for hdr in _TECH_HEADERS:
            val = headers_lower.get(hdr, "").strip()
            if val:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Technology Banner Disclosed via {hdr.title()} Header",
                        description=(
                            f"The HTTP response header '{hdr}' discloses application technology details: '{val}'. "
                            f"This assists attackers in fingerprinting backend frameworks and targeted attack vectors."
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            f"Remove or disable the '{hdr}' header in your web application / framework configuration."
                        ),
                        evidence=f"{hdr}: {val}",
                    )
                )

        # 3. Diagnostic / Infrastructure Headers
        for hdr in _INFRA_HEADERS:
            val = headers_lower.get(hdr, "").strip()
            if val:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Internal Diagnostic Header Disclosed: {hdr}",
                        description=(
                            f"The response contains internal infrastructure or diagnostic header '{hdr}': '{val}'. "
                            f"This may reveal internal hostnames, routing proxies, or debug tokens."
                        ),
                        severity=Severity.LOW,
                        recommendation=f"Strip the '{hdr}' header in production reverse proxies.",
                        evidence=f"{hdr}: {val}",
                    )
                )

    # ------------------------------------------------------------------
    # Body / Stack Trace Analysis
    # ------------------------------------------------------------------

    def _check_response_body(self, context: ScanContext) -> None:
        """Inspect HTML or text body of initial response for stack traces & debug output."""
        body = context.html
        if not body:
            return

        for title, regex, severity, description in _DEBUG_SIGNATURES:
            match = regex.search(body)
            if match:
                snippet = match.group(0)[:300]
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=title,
                        description=(
                            f"{description} Verbose error messages reveal internal file system paths, "
                            f"framework architecture, database queries, and code structures to potential attackers."
                        ),
                        severity=severity,
                        recommendation=(
                            "Disable debug mode (e.g. DEBUG = False, display_errors = Off, NODE_ENV = production) "
                            "and implement custom error pages (HTTP 500 handlers) that log details privately."
                        ),
                        evidence=f"Matched debug signature:\n{snippet}...",
                    )
                )

    # ------------------------------------------------------------------
    # Targeted Sensitive File Probes
    # ------------------------------------------------------------------

    async def _probe_sensitive_files(self, context: ScanContext) -> None:
        """
        Execute targeted lightweight probes for common sensitive files.
        Only tests high-signal files and validates content signatures strictly.
        """
        client = context.session
        base_url = self._get_base_url(context.target_url)

        for probe in _SENSITIVE_FILE_PROBES:
            target_file_url = urljoin(base_url, probe.path)

            try:
                response = await client.get(target_file_url)

                if response.status_code == 200:
                    text = response.text

                    # Validate content signature
                    if probe.signature_regex.search(text):
                        # Check anti-signature (e.g., ensure it's not a 200 OK custom HTML error page)
                        if probe.anti_signature_regex and probe.anti_signature_regex.search(text):
                            continue

                        evidence_snippet = text[:250].strip()

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=probe.title,
                                description=f"{probe.description} (Found at: {target_file_url})",
                                severity=probe.severity,
                                recommendation=probe.recommendation,
                                evidence=f"URL: {target_file_url}\nHTTP Status: 200 OK\n\nContent snippet:\n{evidence_snippet}",
                            )
                        )

            except Exception as exc:
                self.log(f"Sensitive file probe for '{target_file_url}' failed: {exc}")

    @staticmethod
    def _get_base_url(target_url: str) -> str:
        """Extract base URL (scheme + host[:port]) from target URL."""
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}"
