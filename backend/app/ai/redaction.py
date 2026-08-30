"""
app/ai/redaction.py
-------------------
Sanitization and Redaction Engine for AI Input Payloads.

Ensures that authentication tokens, credentials, private keys, passwords,
API keys, session cookies, and sensitive headers are redacted before findings
or scan context are passed to the Ollama model.
"""

from __future__ import annotations

import re
from typing import Any

# Regular expression patterns for sensitive data redaction
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Private cryptographic keys (PEM)
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # AWS Access Key IDs
    (
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "[REDACTED_AWS_KEY]",
    ),
    # Google API Keys
    (
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{32,40})\b"),
        "[REDACTED_GOOGLE_KEY]",
    ),
    # GitHub Tokens
    (
        re.compile(r"\b(ghp_[0-9a-zA-Z]{36,40}|github_pat_[0-9a-zA-Z_]{80,90})\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    # JSON Web Tokens (JWT)
    (
        re.compile(r"\b(eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,})\b"),
        "[REDACTED_JWT_TOKEN]",
    ),
    # Authorization & Cookie headers
    (
        re.compile(r"(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)([^\s\r\n,;]+)"),
        r"\1[REDACTED_AUTH_HEADER]",
    ),
    (
        re.compile(r"(?i)(Set-Cookie\s*:\s*[^=\s;]+)=([^;\r\n]+)"),
        r"\1=[REDACTED_COOKIE_VALUE]",
    ),
    (
        re.compile(r"(?i)(Cookie\s*:\s*[^=\s;]+)=([^;\r\n]+)"),
        r"\1=[REDACTED_COOKIE_VALUE]",
    ),
    # Database connection strings with credentials
    (
        re.compile(r"((?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[a-zA-Z0-9_\-\.%]+:)([^@\/\s:]+)(@[a-zA-Z0-9_\-\.]+)"),
        r"\1[REDACTED_DB_PASSWORD]\3",
    ),
    # Query parameters with sensitive names (token, secret, key, password, auth)
    (
        re.compile(r"(?i)([?&](?:token|access_token|refresh_token|api_key|secret|password|passwd|auth)=)([^&\s]+)"),
        r"\1[REDACTED_PARAM]",
    ),
    # Generic high-entropy secret assignments
    (
        re.compile(r"(?i)(?:api_key|client_secret|db_password|auth_token|secret_key|jwt_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"),
        "[REDACTED_SECRET_ASSIGNMENT]",
    ),
]


def redact_sensitive_text(text: str | None, max_length: int = 1200) -> str:
    """
    Sanitize text by replacing sensitive patterns with redaction placeholders
    and bounding the maximum length to prevent prompt exhaustion.
    """
    if not text:
        return ""

    sanitized = text
    for pattern, replacement in _REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    # Bounded length to prevent oversized prompts
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + " ... [TRUNCATED_FOR_AI_ANALYSIS]"

    return sanitized


def sanitize_finding_for_ai(finding: Any) -> dict[str, Any]:
    """
    Convert a Finding ORM model or object into a sanitized dictionary safe for AI processing.
    """
    finding_id = getattr(finding, "id", None) or 0
    vuln_name = getattr(finding, "vulnerability_name", None) or getattr(finding, "title", "Finding")
    plugin = getattr(finding, "plugin", "") or ""
    severity = getattr(finding, "severity", "LOW")
    if hasattr(severity, "value"):
        severity = severity.value
    severity_str = str(severity).upper()

    description = redact_sensitive_text(getattr(finding, "description", ""), max_length=800)
    recommendation = redact_sensitive_text(getattr(finding, "recommendation", ""), max_length=600)
    evidence = redact_sensitive_text(getattr(finding, "evidence", ""), max_length=1000)

    return {
        "finding_id": finding_id,
        "title": vuln_name,
        "plugin": plugin,
        "severity": severity_str,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence,
    }
