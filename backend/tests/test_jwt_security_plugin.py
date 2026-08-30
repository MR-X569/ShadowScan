"""
Tests for JwtSecurityPlugin.
"""

import asyncio
import base64
import json
import time
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.jwt_security import JwtSecurityPlugin


def _make_jwt(header: dict, payload: dict, signature: str = "dGVzdF9zaWduYXR1cmVfZGF0YQ") -> str:
    """Helper to generate base64url-encoded test JWTs."""
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{signature}"


@pytest.fixture
def plugin() -> JwtSecurityPlugin:
    return JwtSecurityPlugin()


def test_jwt_alg_none_critical(plugin: JwtSecurityPlugin):
    async def _run():
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin", "role": "superuser"}, signature="")
        context = ScanContext(scan_id=1, target_url="https://example.com/api", user_id=1)
        context.headers = {"Authorization": f"Bearer {token}"}

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Insecure Unsigned JWT" in finding.title
        assert finding.severity == Severity.CRITICAL

    asyncio.run(_run())


def test_jwt_sensitive_claims_exposed_high(plugin: JwtSecurityPlugin):
    async def _run():
        token = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "user_123", "api_key": "AKIA1234567890SECRETKEY", "db_password": "SuperSecretPassword123"},
        )
        context = ScanContext(scan_id=1, target_url="https://example.com/dashboard", user_id=1)
        context.cookies = {"session_token": token}

        await plugin.run(context)

        assert len(context.findings) >= 1
        finding = context.findings[0]
        assert "Sensitive Credentials / Secrets Exposed" in finding.title
        assert finding.severity == Severity.HIGH
        assert "api_key=****" in finding.evidence
        assert "SuperSecretPassword123" not in finding.evidence

    asyncio.run(_run())


def test_jwt_missing_exp_on_auth_token_medium(plugin: JwtSecurityPlugin):
    async def _run():
        token = _make_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "alice", "user_id": 42, "role": "member"},  # No exp claim
        )
        context = ScanContext(scan_id=1, target_url="https://example.com/profile", user_id=1)
        context.headers = {"Authorization": f"Bearer {token}"}

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Missing Expiration Claim" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_jwt_excessive_lifetime_low(plugin: JwtSecurityPlugin):
    async def _run():
        now = int(time.time())
        token = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "bob", "iat": now, "exp": now + (90 * 86400)},  # 90 days validity
        )
        context = ScanContext(scan_id=1, target_url="https://example.com/app", user_id=1)
        context.html = f"<html><body><script>const userToken = '{token}';</script></body></html>"

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Long-Lived JWT Token Lifetime" in finding.title
        assert finding.severity == Severity.LOW

    asyncio.run(_run())


def test_secure_jwt_clean_no_findings(plugin: JwtSecurityPlugin):
    async def _run():
        now = int(time.time())
        # Secure, short-lived token (15 mins) with valid signature and standard claims
        token = _make_jwt(
            {"alg": "ES256", "typ": "JWT"},
            {"sub": "user_99", "iat": now, "exp": now + 900, "iss": "https://auth.example.com"},
        )
        context = ScanContext(scan_id=1, target_url="https://example.com/api", user_id=1)
        context.headers = {"Authorization": f"Bearer {token}"}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_malformed_jwt_handled(plugin: JwtSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"Authorization": "Bearer eyJhbGciOi.invalidpayload.invalidsig"}

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_no_jwt_handled(plugin: JwtSecurityPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)
        context.headers = {"Server": "nginx"}
        context.html = "<html><body>Welcome</body></html>"

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
