"""
app/scanner/plugins/passive/sensitive_data.py
---------------------------------------------
Sensitive Data & Secret Exposure Plugin — scans HTTP responses, JavaScript assets,
JSON payloads, and source code for accidentally exposed credentials and secrets.

Detected Secret Patterns:
    - AWS Access Key IDs (AKIA...)
    - Google Cloud / Maps API Keys (AIza...)
    - GitHub Personal Access Tokens (ghp_..., github_pat_...)
    - Slack Webhooks & Bot Tokens (hooks.slack.com, xoxb-...)
    - Private Cryptographic Keys (PEM RSA, EC, OpenSSH Private Keys)
    - Database Connection Strings with embedded credentials (Postgres, MySQL, Mongo, Redis)
    - Signed JSON Web Tokens (JWT)
    - Generic High-Entropy API Secrets & Private Token assignments

Strict Redaction & Safety:
    - Secrets are ALWAYS safely redacted before inclusion in finding evidence (e.g. AKIA****1234).
    - Full credentials or private keys are NEVER stored in plaintext.
    - Placeholder strings (example, test, dummy, changeme) are filtered to prevent false positives.

Severity Logic:
    - Private PEM keys / Database connection credentials / Cloud access keys -> CRITICAL
    - Valid GitHub tokens / Google API keys / JWT tokens / API secrets -> HIGH
    - Potential secret assignment -> MEDIUM
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

# Placeholder values to ignore during secret evaluation
_IGNORE_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "your_api_key",
        "your_secret_key",
        "your_token_here",
        "your-api-key",
        "example",
        "sample",
        "placeholder",
        "changeme",
        "dummy",
        "1234567890",
        "abcdef123456",
        "xxxxxxxxxx",
        "test_secret",
    }
)


@dataclass
class _SecretRule:
    name: str
    category: str
    severity: Severity
    regex: re.Pattern[str]
    description: str


_RULES: list[_SecretRule] = [
    _SecretRule(
        name="Private Cryptographic Key",
        category="Private Key",
        severity=Severity.CRITICAL,
        regex=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        description="An unencrypted private cryptographic key (PEM format) is publicly exposed in HTTP response source.",
    ),
    _SecretRule(
        name="Database Connection String with Credentials",
        category="Database Credential",
        severity=Severity.CRITICAL,
        regex=re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[a-zA-Z0-9_\-\.%]+:[a-zA-Z0-9_\-\.%!@#$^&*+=]+@[a-zA-Z0-9_\-\.]+(?::\d+)?\/[a-zA-Z0-9_\-\.]*"),
        description="A database connection URI with embedded username and password was found in response text.",
    ),
    _SecretRule(
        name="AWS Access Key ID",
        category="Cloud Credential",
        severity=Severity.CRITICAL,
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        description="An Amazon Web Services (AWS) Access Key ID was detected.",
    ),
    _SecretRule(
        name="Google Cloud API Key",
        category="Cloud Credential",
        severity=Severity.HIGH,
        regex=re.compile(r"\b(AIza[0-9A-Za-z_\-]{32,40})\b"),
        description="A Google Cloud Platform / Maps API Key was identified in client-side source code.",
    ),
    _SecretRule(
        name="GitHub Personal Access Token",
        category="API Token",
        severity=Severity.HIGH,
        regex=re.compile(r"\b(ghp_[0-9a-zA-Z]{36,40}|github_pat_[0-9a-zA-Z_]{80,90})\b"),
        description="A GitHub personal access token was found in public response data.",
    ),
    _SecretRule(
        name="Slack Webhook URL",
        category="Webhook Credential",
        severity=Severity.HIGH,
        regex=re.compile(r"https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+"),
        description="An incoming Slack Webhook URL was exposed, which allows unauthorized message posting to internal channels.",
    ),
    _SecretRule(
        name="JSON Web Token (JWT)",
        category="Authentication Token",
        severity=Severity.HIGH,
        regex=re.compile(r"\b(eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,})\b"),
        description="A signed JSON Web Token (JWT) containing authentication or authorization claims was detected.",
    ),
    _SecretRule(
        name="Hardcoded Secret / API Token Assignment",
        category="API Secret",
        severity=Severity.HIGH,
        regex=re.compile(r"(?:api_key|client_secret|db_password|auth_token|secret_key|jwt_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", re.IGNORECASE),
        description="A high-entropy secret assignment was detected in client-side code.",
    ),
]


class SensitiveDataPlugin(BasePlugin):
    """
    Scans HTTP responses and referenced same-origin JavaScript for exposed credentials.
    """

    name = "sensitive_data"
    description = (
        "Detects accidentally exposed API keys, private keys, database connection strings, "
        "and credentials in HTTP responses and JavaScript assets."
    )
    category = "passive"
    version = "1.0.0"
    priority = 100

    async def run(self, context: ScanContext) -> None:
        """
        Execute sensitive data inspection on context.html and response data.
        """
        body_text = context.html or ""
        if not body_text and context.response is not None:
            body_text = getattr(context.response, "text", "") or ""

        if not body_text:
            self.log("No response body available — skipping sensitive data scan.")
            return

        found_secrets: set[str] = set()

        # 1. Scan primary response body
        self._scan_content(body_text, context.target_url, context, found_secrets)

        # 2. Extract and inspect same-origin JavaScript script tags
        if context.session is not None and context.target_url:
            await self._scan_referenced_scripts(context, body_text, found_secrets)

    # ------------------------------------------------------------------
    # Content Scanning & Redaction Engine
    # ------------------------------------------------------------------

    def _scan_content(
        self,
        content: str,
        source_url: str,
        context: ScanContext,
        found_secrets: set[str],
    ) -> None:
        """Evaluate content against all secret rules."""
        for rule in _RULES:
            for match in rule.regex.finditer(content):
                secret_str = match.group(1) if match.groups() else match.group(0)

                # Skip short or known placeholder values
                if not secret_str or len(secret_str) < 8 or self._is_placeholder(secret_str):
                    continue

                # Deduplicate based on rule and secret prefix
                secret_id = f"{rule.name}:{secret_str[:8]}"
                if secret_id in found_secrets:
                    continue
                found_secrets.add(secret_id)

                redacted = self._redact_secret(secret_str)

                evidence = (
                    f"Secret Category: {rule.category}\n"
                    f"Detected Pattern: {rule.name}\n"
                    f"Source Asset: {source_url}\n"
                    f"Redacted Secret Evidence: {redacted}\n"
                    f"Length: {len(secret_str)} characters"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Exposed {rule.name} Detected",
                        description=(
                            f"{rule.description} Found in asset '{source_url}'. "
                            f"Public disclosure of credentials allows unauthorized access to backend services, "
                            f"cloud resources, databases, or API infrastructure."
                        ),
                        severity=rule.severity,
                        recommendation=(
                            f"Immediately revoke and rotate the exposed credential. Remove all sensitive tokens and keys "
                            f"from client-accessible source code, and use environment variables or secret management vaults."
                        ),
                        evidence=evidence,
                    )
                )

    # ------------------------------------------------------------------
    # Same-Origin Script Asset Inspection
    # ------------------------------------------------------------------

    async def _scan_referenced_scripts(
        self,
        context: ScanContext,
        html_body: str,
        found_secrets: set[str],
    ) -> None:
        """Find same-origin script src tags in HTML and inspect their contents."""
        script_srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html_body, re.IGNORECASE)
        base_url = context.target_url
        parsed_base = urlparse(base_url)
        client = context.session

        for src in script_srcs[:5]:  # Limit to first 5 scripts for performance
            abs_script_url = urljoin(base_url, src)
            parsed_script = urlparse(abs_script_url)

            # Strictly same-origin only
            if parsed_script.netloc != parsed_base.netloc:
                continue

            try:
                resp = await client.get(abs_script_url)
                if resp.status_code == 200 and resp.text:
                    # Scan script file (bounded to first 100KB)
                    script_text = resp.text[:102400]
                    self._scan_content(script_text, abs_script_url, context, found_secrets)
            except Exception as exc:
                self.log(f"Failed to inspect script asset '{abs_script_url}': {exc}")

    # ------------------------------------------------------------------
    # Helpers: Redaction & Placeholder Filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _redact_secret(val: str) -> str:
        """
        Safely redact secrets to protect sensitive values while providing clear evidence.
        Example: AKIA1234567890ABCD -> AKIA****ABCD
        """
        if "PRIVATE KEY" in val:
            return "-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY DATA]\n-----END PRIVATE KEY-----"

        if "://" in val and "@" in val:
            # Redact password in connection string: postgres://user:pass@host:5432/db -> postgres://user:****@host:5432/db
            return re.sub(r":([^@\/\s:]+)@", r":****@", val)

        if len(val) <= 8:
            return f"{val[:2]}****{val[-2:]}"

        return f"{val[:4]}****{val[-4:]}"

    @staticmethod
    def _is_placeholder(val: str) -> bool:
        """Check if string matches common documentation/test placeholders."""
        val_lower = val.lower().strip()
        if val_lower in _IGNORE_PLACEHOLDERS:
            return True
        if val_lower.startswith(("your_", "my_", "test_", "placeholder_", "dummy_", "example_")):
            return True
        # Check if repetitive string (e.g. aaaaaaa, 0000000)
        if len(set(val)) <= 2:
            return True
        return False
