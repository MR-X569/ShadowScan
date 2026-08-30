"""
Tests for TlsCiphersPlugin.
"""

import asyncio
from unittest.mock import patch
import pytest

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.tls_ciphers import (
    TlsCiphersPlugin,
    _TlsEvaluationResult,
)


@pytest.fixture
def plugin() -> TlsCiphersPlugin:
    return TlsCiphersPlugin()


def test_http_target_skipped(plugin: TlsCiphersPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="http://example.com", user_id=1)
        await plugin.run(context)
        # HTTP is handled by ssl_tls plugin; tls_ciphers returns gracefully
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_null_ciphers_accepted_critical(plugin: TlsCiphersPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_result = _TlsEvaluationResult(
            hostname="example.com",
            port=443,
            is_tls_available=True,
            default_protocol="TLSv1.2",
            default_cipher_name="ECDHE-RSA-AES128-GCM-SHA256",
            default_cipher_bits=128,
            supports_null_ciphers=True,
        )

        with patch.object(TlsCiphersPlugin, "_evaluate_tls_posture", return_value=mock_result):
            await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("Null Encryption" in t for t in titles)
        finding = next(f for f in context.findings if "Null Encryption" in f.title)
        assert finding.severity == Severity.CRITICAL

    asyncio.run(_run())


def test_deprecated_tls_protocols(plugin: TlsCiphersPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_result = _TlsEvaluationResult(
            hostname="example.com",
            port=443,
            is_tls_available=True,
            default_protocol="TLSv1.2",
            default_cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
            default_cipher_bits=256,
            supports_sslv3=True,
            supports_tls1_0=True,
            supports_tls1_1=True,
            supports_tls1_2=True,
        )

        with patch.object(TlsCiphersPlugin, "_evaluate_tls_posture", return_value=mock_result):
            await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("SSL 3.0" in t for t in titles)
        assert any("TLS 1.0" in t for t in titles)
        assert any("TLS 1.1" in t for t in titles)

        sslv3_finding = next(f for f in context.findings if "SSL 3.0" in f.title)
        assert sslv3_finding.severity == Severity.CRITICAL

        tls10_finding = next(f for f in context.findings if "TLS 1.0" in f.title)
        assert tls10_finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_weak_rc4_cipher(plugin: TlsCiphersPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_result = _TlsEvaluationResult(
            hostname="example.com",
            port=443,
            is_tls_available=True,
            default_protocol="TLSv1.2",
            default_cipher_name="RC4-SHA",
            default_cipher_bits=128,
        )

        with patch.object(TlsCiphersPlugin, "_evaluate_tls_posture", return_value=mock_result):
            await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("RC4" in t for t in titles)
        rc4_finding = next(f for f in context.findings if "RC4" in f.title)
        assert rc4_finding.severity == Severity.HIGH

    asyncio.run(_run())


def test_3des_sweet32_cipher(plugin: TlsCiphersPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_result = _TlsEvaluationResult(
            hostname="example.com",
            port=443,
            is_tls_available=True,
            default_protocol="TLSv1.2",
            default_cipher_name="DES-CBC3-SHA",
            default_cipher_bits=112,
        )

        with patch.object(TlsCiphersPlugin, "_evaluate_tls_posture", return_value=mock_result):
            await plugin.run(context)

        titles = [f.title for f in context.findings]
        assert any("3DES" in t or "SWEET32" in t for t in titles)

    asyncio.run(_run())


def test_modern_secure_tls13_configuration(plugin: TlsCiphersPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://example.com", user_id=1)

        mock_result = _TlsEvaluationResult(
            hostname="example.com",
            port=443,
            is_tls_available=True,
            default_protocol="TLSv1.3",
            default_cipher_name="TLS_AES_256_GCM_SHA384",
            default_cipher_bits=256,
            supports_tls1_2=True,
            supports_tls1_3=True,
        )

        with patch.object(TlsCiphersPlugin, "_evaluate_tls_posture", return_value=mock_result):
            await plugin.run(context)

        # Fully secure modern config -> 0 findings
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_tls_connection_failure_handled(plugin: TlsCiphersPlugin):
    async def _run():
        context = ScanContext(scan_id=1, target_url="https://unreachable.test", user_id=1)

        mock_result = _TlsEvaluationResult(
            hostname="unreachable.test",
            port=443,
            is_tls_available=False,
            error="Connection timed out",
        )

        with patch.object(TlsCiphersPlugin, "_evaluate_tls_posture", return_value=mock_result):
            await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
