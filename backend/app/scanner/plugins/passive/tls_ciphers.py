"""
app/scanner/plugins/passive/tls_ciphers.py
------------------------------------------
TLS / Cipher Suite Health Plugin — evaluates supported TLS protocol versions,
negotiated cipher suite strength, key lengths, forward secrecy, and detects
deprecated or weak cryptographic algorithms.

Checks performed:
    - Deprecated protocol support (SSLv3, TLS 1.0, TLS 1.1)
    - Insecure / Anonymous cipher suites (eNULL, aNULL)
    - Negotiated cipher strength and symmetric key bit length (< 128 bits)
    - Vulnerable legacy algorithms in cipher suite (RC4, 3DES / SWEET32)
    - Forward Secrecy (PFS) availability (ECDHE / DHE vs static RSA)
    - Legacy hashing in cipher suite (SHA-1 HMAC)

Severity Logic:
    - Insecure SSL 3.0 protocol accepted -> CRITICAL
    - Null / Anonymous encryption accepted -> CRITICAL
    - Weak symmetric encryption key length (< 128 bits) -> HIGH
    - Insecure RC4 stream cipher in cipher suite -> HIGH
    - Deprecated TLS 1.0 protocol supported -> MEDIUM
    - Vulnerable 3DES (Triple-DES / SWEET32) in cipher suite -> MEDIUM
    - Deprecated TLS 1.1 protocol supported -> LOW
    - Lack of Perfect Forward Secrecy (Static RSA) -> LOW
    - Legacy SHA-1 MAC in cipher suite -> LOW
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Default HTTPS port
_DEFAULT_HTTPS_PORT: int = 443
_SOCKET_TIMEOUT: float = 8.0


@dataclass
class _TlsEvaluationResult:
    """Stores results collected from TLS protocol and cipher suite probes."""

    hostname: str
    port: int
    is_tls_available: bool = False
    error: str | None = None

    # Negotiated default
    default_protocol: str | None = None
    default_cipher_name: str | None = None
    default_cipher_bits: int | None = None
    default_cipher_version: str | None = None

    # Protocol version support
    supports_sslv3: bool = False
    supports_tls1_0: bool = False
    supports_tls1_1: bool = False
    supports_tls1_2: bool = False
    supports_tls1_3: bool = False

    # Dangerous cipher classes
    supports_null_ciphers: bool = False


class TlsCiphersPlugin(BasePlugin):
    """
    Evaluates TLS protocol versions, cipher suite algorithms, key lengths,
    and cryptographic health against industry standards.
    """

    name = "tls_ciphers"
    description = (
        "Evaluates supported TLS protocol versions, negotiated cipher suite strength, "
        "and detects deprecated or weak cryptographic algorithms."
    )
    category = "passive"
    version = "1.0.0"
    priority = 32

    async def run(self, context: ScanContext) -> None:
        """
        Execute TLS cipher and protocol evaluation against the target.
        """
        parsed = urlparse(context.target_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""

        if scheme != "https" or not hostname:
            self.log("Target is not HTTPS — skipping TLS cipher evaluation.")
            return

        port = parsed.port or _DEFAULT_HTTPS_PORT

        # Offload blocking socket / TLS handshake operations to a worker thread
        result: _TlsEvaluationResult = await asyncio.to_thread(
            self._evaluate_tls_posture,
            hostname,
            port,
        )

        if not result.is_tls_available:
            self.log(f"TLS connection to {hostname}:{port} failed: {result.error}")
            return

        self._generate_findings(result, context)

    # ------------------------------------------------------------------
    # Handshake & Probing Engine (Synchronous, run in worker thread)
    # ------------------------------------------------------------------

    @classmethod
    def _evaluate_tls_posture(
        cls,
        hostname: str,
        port: int,
    ) -> _TlsEvaluationResult:
        """Probe the target host for TLS versions and cipher suites."""
        res = _TlsEvaluationResult(hostname=hostname, port=port)

        # 1. Probe Default Connection (to inspect negotiated cipher suite)
        try:
            default_ctx = ssl.create_default_context()
            default_ctx.check_hostname = False
            default_ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=_SOCKET_TIMEOUT) as sock:
                with default_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    res.is_tls_available = True
                    res.default_protocol = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        res.default_cipher_name = cipher_info[0]
                        res.default_cipher_version = cipher_info[1]
                        res.default_cipher_bits = cipher_info[2]
        except Exception as exc:
            res.error = str(exc)
            return res

        # 2. Probe Protocol Versions
        res.supports_tls1_0 = cls._test_protocol_version(hostname, port, ssl.TLSVersion.TLSv1)
        res.supports_tls1_1 = cls._test_protocol_version(hostname, port, ssl.TLSVersion.TLSv1_1)
        res.supports_tls1_2 = cls._test_protocol_version(hostname, port, ssl.TLSVersion.TLSv1_2)
        res.supports_tls1_3 = cls._test_protocol_version(hostname, port, ssl.TLSVersion.TLSv1_3)

        # Probe SSLv3 if available in local Python/OpenSSL runtime
        sslv3_ver = getattr(ssl.TLSVersion, "SSLv3", None)
        if sslv3_ver is not None:
            res.supports_sslv3 = cls._test_protocol_version(hostname, port, sslv3_ver)

        # 3. Probe Dangerous Null / Anonymous Ciphers
        res.supports_null_ciphers = cls._test_cipher_group(hostname, port, "aNULL:eNULL:@SECLEVEL=0")

        return res

    @staticmethod
    def _test_protocol_version(
        hostname: str,
        port: int,
        version: ssl.TLSVersion,
    ) -> bool:
        """Test if a specific TLS protocol version is accepted by the server."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version

            with socket.create_connection((hostname, port), timeout=_SOCKET_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return bool(ssock.version())
        except Exception:
            return False

    @staticmethod
    def _test_cipher_group(
        hostname: str,
        port: int,
        cipher_query: str,
    ) -> bool:
        """Test if the server accepts a connection using a specific cipher query."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher_query)

            with socket.create_connection((hostname, port), timeout=_SOCKET_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return bool(ssock.cipher())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Finding Generation
    # ------------------------------------------------------------------

    def _generate_findings(
        self,
        res: _TlsEvaluationResult,
        context: ScanContext,
    ) -> None:
        """Evaluate probe results and emit findings."""
        target_host = f"{res.hostname}:{res.port}"

        # 1. Null / Anonymous Encryption
        if res.supports_null_ciphers:
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Insecure Anonymous / Null Encryption Cipher Suite Accepted",
                    description=(
                        f"The server at {target_host} accepted an unencrypted or anonymous (aNULL/eNULL) "
                        f"cipher suite. Connections negotiated with null ciphers offer zero encryption or "
                        f"authentication, allowing active eavesdroppers to intercept and modify traffic."
                    ),
                    severity=Severity.CRITICAL,
                    recommendation="Disable all anonymous (aNULL) and null-encryption (eNULL) cipher suites immediately.",
                    evidence=f"Server accepted handshake with cipher suite query 'aNULL:eNULL'.",
                )
            )

        # 2. SSLv3 Support
        if res.supports_sslv3:
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Insecure SSL 3.0 Protocol Supported (POODLE)",
                    description=(
                        f"The server at {target_host} supports the obsolete SSL 3.0 protocol. "
                        f"SSL 3.0 uses vulnerable CBC padding and is vulnerable to the POODLE attack (CVE-2014-3566), "
                        f"which allows plaintext recovery of encrypted data."
                    ),
                    severity=Severity.CRITICAL,
                    recommendation="Disable SSL 3.0 completely on the server. Support only TLS 1.2 and TLS 1.3.",
                    evidence=f"Handshake succeeded using protocol SSLv3 on {target_host}.",
                )
            )

        # 3. TLS 1.0 Support
        if res.supports_tls1_0:
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Deprecated TLS 1.0 Protocol Supported",
                    description=(
                        f"The server at {target_host} supports TLS 1.0. TLS 1.0 was formally deprecated "
                        f"by the IETF in RFC 8996 and violates modern compliance standards (such as PCI DSS 3.2+). "
                        f"It lacks support for modern AEAD ciphers and is vulnerable to known cryptographic attacks (BEAST)."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation="Disable TLS 1.0 in your server configuration. Allow only TLS 1.2 and TLS 1.3.",
                    evidence=f"Handshake succeeded using protocol TLSv1.0 on {target_host}.",
                )
            )

        # 4. TLS 1.1 Support
        if res.supports_tls1_1:
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="Deprecated TLS 1.1 Protocol Supported",
                    description=(
                        f"The server at {target_host} supports TLS 1.1, which was deprecated by the IETF (RFC 8996). "
                        f"While less vulnerable than TLS 1.0, TLS 1.1 does not support modern cryptographic primitives."
                    ),
                    severity=Severity.LOW,
                    recommendation="Disable TLS 1.1 on the server and migrate to TLS 1.2 and TLS 1.3.",
                    evidence=f"Handshake succeeded using protocol TLSv1.1 on {target_host}.",
                )
            )

        # 5. Inspect Default Negotiated Cipher Suite
        if res.default_cipher_name:
            cipher_name = res.default_cipher_name.upper()
            cipher_bits = res.default_cipher_bits or 0
            evidence_cipher = f"Negotiated Protocol: {res.default_protocol}\nCipher Suite: {res.default_cipher_name} ({cipher_bits} bits)"

            # Check weak symmetric key length (< 128 bits)
            if 0 < cipher_bits < 128:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Weak Symmetric Cipher Key Length: {cipher_bits} bits",
                        description=(
                            f"The default cipher negotiated by {target_host} ('{res.default_cipher_name}') uses "
                            f"a {cipher_bits}-bit symmetric key. Keys shorter than 128 bits are vulnerable to brute-force attacks."
                        ),
                        severity=Severity.HIGH,
                        recommendation="Configure the server to require cipher suites with a minimum of 128-bit encryption keys.",
                        evidence=evidence_cipher,
                    )
                )

            # Check RC4 in cipher name
            if "RC4" in cipher_name:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Insecure RC4 Stream Cipher in Negotiated Suite",
                        description=(
                            f"The server negotiated the RC4 stream cipher ('{res.default_cipher_name}'). "
                            f"RC4 has known statistical biases (Bar Mitzvah attack, CVE-2013-2566) and is prohibited by RFC 7465."
                        ),
                        severity=Severity.HIGH,
                        recommendation="Disable all RC4 cipher suites in your TLS configuration.",
                        evidence=evidence_cipher,
                    )
                )

            # Check 3DES in cipher name (SWEET32)
            elif "3DES" in cipher_name or "DES-CBC3" in cipher_name:
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Vulnerable 3DES (Triple-DES) Cipher Suite - SWEET32",
                        description=(
                            f"The server negotiated a 3DES cipher suite ('{res.default_cipher_name}'). "
                            f"3DES uses a 64-bit block size and is susceptible to collision attacks (SWEET32, CVE-2016-2183) "
                            f"over long-lived HTTPS sessions."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation="Disable 3DES/Triple-DES cipher suites and enable AES-GCM or ChaCha20-Poly1305.",
                        evidence=evidence_cipher,
                    )
                )

            # Check Lack of Forward Secrecy (Static RSA key exchange in TLS 1.2)
            if res.default_protocol == "TLSv1.2" and not any(k in cipher_name for k in ("ECDHE", "DHE", "CHACHA")):
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Lack of Perfect Forward Secrecy (Static RSA Key Exchange)",
                        description=(
                            f"The negotiated TLS 1.2 cipher suite ('{res.default_cipher_name}') uses static RSA key exchange "
                            f"rather than Ephemeral Diffie-Hellman (ECDHE / DHE). Without Perfect Forward Secrecy (PFS), "
                            f"if the server's private key is compromised in the future, past recorded traffic can be decrypted."
                        ),
                        severity=Severity.LOW,
                        recommendation="Prioritize ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key exchange cipher suites.",
                        evidence=evidence_cipher,
                    )
                )

            # Check SHA-1 HMAC in TLS 1.2
            if res.default_protocol == "TLSv1.2" and cipher_name.endswith("-SHA") and not any(k in cipher_name for k in ("SHA256", "SHA384", "GCM", "POLY1305")):
                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title="Legacy SHA-1 Integrity Algorithm in Cipher Suite",
                        description=(
                            f"The negotiated cipher suite ('{res.default_cipher_name}') uses SHA-1 for message authentication. "
                            f"SHA-1 is cryptographically weak; modern deployments should use AEAD ciphers (AES-GCM, ChaCha20) or SHA-256/384 HMAC."
                        ),
                        severity=Severity.LOW,
                        recommendation="Configure modern AEAD cipher suites (e.g. TLS_AES_128_GCM_SHA256, ECDHE-ECDSA-AES128-GCM-SHA256).",
                        evidence=evidence_cipher,
                    )
                )

        # Store metadata
        context.set_metadata(
            "tls_ciphers_evaluation",
            {
                "protocol": res.default_protocol,
                "cipher": res.default_cipher_name,
                "bits": res.default_cipher_bits,
                "supports_tls1_0": res.supports_tls1_0,
                "supports_tls1_1": res.supports_tls1_1,
                "supports_tls1_2": res.supports_tls1_2,
                "supports_tls1_3": res.supports_tls1_3,
            },
        )
