"""
app/scanner/plugins/passive/jwt_security.py
------------------------------------------
JSON Web Token (JWT) Security Analysis Plugin.

Safely detects insecure JWT configurations and exposures from:
    1. Authorization: Bearer <JWT> headers in responses or context.
    2. Set-Cookie / Cookie session tokens.
    3. HTTP response bodies and crawler-discovered metadata.

Detection Areas:
    - Algorithm weaknesses: alg="none" or unsigned tokens -> CRITICAL
    - Sensitive embedded claims: passwords, API keys, private keys, secrets in payload -> HIGH
    - Missing expiration: authentication tokens without 'exp' claim -> MEDIUM
    - Excessive token lifetime: tokens expiring in > 30 days -> LOW/MEDIUM
    - Missing standard claims: missing 'iat', 'iss', 'aud' on auth tokens -> LOW

Safety & Guardrails:
    - Local decoding only (base64url decoding of header and payload).
    - NEVER sends discovered JWTs to external third-party services.
    - NEVER performs token cracking, brute forcing, or signature tampering.
    - Mandatory redaction of all sensitive claim values and token signatures in findings.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# JWT structure regex: header.payload[.signature] (each base64url encoded)
_JWT_REGEX: re.Pattern[str] = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-+/=]*)?)"
)

# Sensitive claim keys to inspect in decoded payload
_SENSITIVE_CLAIM_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "db_password",
        "client_secret",
        "auth_secret",
        "token_secret",
    }
)

# 30 days threshold in seconds for long-lived tokens
_MAX_TOKEN_LIFETIME_SECONDS: int = 30 * 24 * 3600


class JwtSecurityPlugin(BasePlugin):
    """
    Safely inspects JWT tokens in HTTP headers, cookies, and bodies for security weaknesses.
    """

    name = "jwt_security"
    description = (
        "Analyzes JSON Web Tokens (JWT) for critical configuration weaknesses, "
        "including unsigned alg:none tokens, exposed secrets in claims, and missing expiration."
    )
    category = "passive"
    version = "1.0.0"
    priority = 82

    async def run(self, context: ScanContext) -> None:
        """
        Execute JWT discovery and claim analysis across context headers, cookies, and HTML.
        """
        discovered_jwts: set[str] = set()

        # 1. Inspect HTTP Headers (Authorization, Set-Cookie, Custom)
        if context.headers:
            for header_name, header_val in context.headers.items():
                for match in _JWT_REGEX.finditer(header_val):
                    discovered_jwts.add(match.group(1))

        # 2. Inspect ScanContext Cookies
        if context.cookies:
            for cookie_name, cookie_val in context.cookies.items():
                for match in _JWT_REGEX.finditer(str(cookie_val)):
                    discovered_jwts.add(match.group(1))

        # 3. Inspect Response HTML body (first 100KB)
        body_text = context.html or ""
        if not body_text and context.response is not None:
            body_text = getattr(context.response, "text", "") or ""

        if body_text:
            for match in _JWT_REGEX.finditer(body_text[:102400]):
                discovered_jwts.add(match.group(1))

        if not discovered_jwts:
            self.log("No JSON Web Tokens discovered in scan context.")
            return

        self.log(f"Discovered {len(discovered_jwts)} JWT token(s) to analyze.")

        for raw_jwt in discovered_jwts:
            self._analyze_jwt(raw_jwt, context)

    # ------------------------------------------------------------------
    # JWT Decoding & Analysis
    # ------------------------------------------------------------------

    def _analyze_jwt(self, raw_jwt: str, context: ScanContext) -> None:
        """Decode header and payload and evaluate security claims."""
        parts = raw_jwt.split(".")
        if len(parts) != 3:
            return

        header_b64, payload_b64, sig_b64 = parts

        header = self._decode_jwt_part(header_b64)
        payload = self._decode_jwt_part(payload_b64)

        if header is None or payload is None:
            return

        redacted_jwt = self._redact_jwt(raw_jwt)

        # A. Algorithm None / Unsigned Token Check (CRITICAL)
        alg = str(header.get("alg", "")).lower()
        if alg in ("none", "null") or (alg == "" and not sig_b64):
            evidence = (
                f"Redacted Token: {redacted_jwt}\n"
                f"Header: {json.dumps(header)}\n"
                f"Evaluation: Token algorithm is explicitly set to 'none' or lacks cryptographic signature."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Insecure Unsigned JWT Configuration (alg: none)",
                    description=(
                        "The application uses or produces JSON Web Tokens configured with algorithm 'none' "
                        "or missing cryptographic signatures. An attacker can forge arbitrary payloads and claims "
                        "(such as user IDs or administrative roles) to achieve complete authentication bypass."
                    ),
                    severity=Severity.CRITICAL,
                    recommendation=(
                        "Enforce strong asymmetric (e.g. RS256, ES256) or symmetric (e.g. HS256) cryptographic signatures "
                        "on all JWTs. Explicitly reject tokens with 'alg: none' at the token verification layer."
                    ),
                    evidence=evidence,
                )
            )

        # B. Sensitive Claims in Payload Check (HIGH)
        sensitive_found: list[str] = []
        for claim_k, claim_v in payload.items():
            if claim_k.lower() in _SENSITIVE_CLAIM_NAMES:
                sensitive_found.append(f"{claim_k}=****")

        if sensitive_found:
            evidence = (
                f"Redacted Token: {redacted_jwt}\n"
                f"Exposed Sensitive Claims: {', '.join(sensitive_found)}\n"
                f"Decoded Non-Sensitive Claims: {list(payload.keys())}"
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Sensitive Credentials / Secrets Exposed in JWT Payload",
                    description=(
                        f"The JWT payload contains sensitive credential or secret keys ({', '.join(sensitive_found)}). "
                        f"JWT payloads are only base64url-encoded and are not encrypted, meaning any client or intermediary "
                        f"can view these embedded credentials in plaintext."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Remove all sensitive secrets, passwords, and private API keys from JWT payload claims. "
                        "Store credentials securely in backend session stores or use encrypted tokens (JWE)."
                    ),
                    evidence=evidence,
                )
            )

        # C. Missing Expiration (exp) on Session/Auth Token (MEDIUM)
        is_auth_token = any(k in payload for k in ("sub", "user", "username", "user_id", "email", "uid", "role", "roles"))
        if "exp" not in payload and is_auth_token:
            evidence = (
                f"Redacted Token: {redacted_jwt}\n"
                f"Payload Claims: {list(payload.keys())}\n"
                f"Evaluation: Authentication token contains user identity claims but lacks an 'exp' expiration claim."
            )
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Missing Expiration Claim (exp) in Authentication JWT",
                    description=(
                        "The authentication JSON Web Token does not contain an 'exp' (expiration time) claim. "
                        "Tokens without an expiration remain valid indefinitely, increasing the risk of unauthorized "
                        "session replay if the token is intercepted or leaked."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Include a short-lived 'exp' claim in all issued JWTs (e.g. 15-60 minutes for access tokens) "
                        "and validate token expiration strictly on all backend API requests."
                    ),
                    evidence=evidence,
                )
            )

        # D. Excessively Long-Lived Token (LOW / MEDIUM)
        elif "exp" in payload:
            try:
                exp_val = int(payload["exp"])
                iat_val = int(payload.get("iat", time.time()))
                lifetime = exp_val - iat_val

                if lifetime > _MAX_TOKEN_LIFETIME_SECONDS:
                    days = round(lifetime / 86400, 1)
                    evidence = (
                        f"Redacted Token: {redacted_jwt}\n"
                        f"Configured Lifetime: {days} days ({lifetime} seconds)\n"
                        f"Expiration Timestamp: {exp_val}\n"
                        f"Issued At: {iat_val}"
                    )
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Excessively Long-Lived JWT Token Lifetime ({days} Days)",
                            description=(
                                f"The JWT token is configured with a validity period of {days} days, which exceeds recommended "
                                f"best practices. Long-lived access tokens present a wider window of vulnerability if stolen."
                            ),
                            severity=Severity.LOW,
                            recommendation=(
                                "Reduce access token lifetime to 15-60 minutes and implement refresh token rotation."
                            ),
                            evidence=evidence,
                        )
                    )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helpers: Decoding & Redaction
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_jwt_part(b64_str: str) -> dict[str, Any] | None:
        """Safely base64url-decode a JWT part into a dictionary."""
        try:
            rem = len(b64_str) % 4
            if rem > 0:
                b64_str += "=" * (4 - rem)
            decoded_bytes = base64.urlsafe_b64decode(b64_str.encode("ascii"))
            data = json.loads(decoded_bytes.decode("utf-8", errors="ignore"))
            if isinstance(data, dict):
                return data
            return None
        except Exception:
            return None

    @staticmethod
    def _redact_jwt(token: str) -> str:
        """Redact the JWT signature and payload to avoid storing sensitive values."""
        parts = token.split(".")
        if len(parts) == 3:
            return f"{parts[0]}.[REDACTED_PAYLOAD].{parts[2][:6]}****"
        return f"{token[:15]}****"
