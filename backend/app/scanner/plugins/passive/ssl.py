"""
app/scanner/plugins/passive/ssl.py
------------------------------------
SSL/TLS Plugin — inspects the SSL/TLS configuration and certificate health
of the target host.

Behaviour:
    - HTTP targets: emits a single HIGH finding ("HTTPS Not Enabled") and
      exits immediately. Certificate and TLS checks are skipped entirely
      (as directed by user).
    - HTTPS targets: performs a raw TLS socket handshake (blocking, offloaded
      to a thread via ``asyncio.to_thread``) to inspect:
        * Certificate validity (verifiable chain)
        * Certificate expiry
        * Self-signed certificate
        * Negotiated TLS version

This plugin does NOT use ``context.session`` for SSL inspection — raw socket
access is required to read certificate and protocol details unavailable
through httpx.

Dependencies:
    - ``ssl`` (stdlib)
    - ``socket`` (stdlib)
    - ``cryptography`` (already in requirements.txt)
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Certificate expiry thresholds (days remaining before expiry).
_EXPIRY_CRITICAL_DAYS: int = 7
_EXPIRY_HIGH_DAYS: int = 30

# TLS versions considered weak.
_WEAK_TLS_VERSIONS: frozenset[str] = frozenset(
    {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
)

# Default HTTPS port.
_DEFAULT_HTTPS_PORT: int = 443

# Socket connection timeout in seconds.
_SOCKET_TIMEOUT: float = 10.0


# ---------------------------------------------------------------------------
# Internal data transfer object
# ---------------------------------------------------------------------------


@dataclass
class _SslInspectionResult:
    """Raw data collected from a TLS handshake inspection."""

    tls_version: str | None = None
    cert: x509.Certificate | None = None
    not_valid_after: datetime | None = None
    self_signed: bool = False
    is_valid: bool = True
    verification_error: str | None = None
    connection_error: str | None = None


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class SslPlugin(BasePlugin):
    """
    Inspects SSL/TLS configuration and X.509 certificate health.

    For HTTP targets: emits one finding ("HTTPS Not Enabled") and returns.
    For HTTPS targets: performs a raw TLS handshake to check cert validity,
    expiry, self-signing, and negotiated TLS version.
    """

    name = "ssl_tls"
    description = (
        "Inspects SSL/TLS configuration, certificate validity, "
        "expiry, and negotiated protocol version"
    )
    category = "passive"
    version = "1.0.0"
    priority = 30

    async def run(self, context: ScanContext) -> None:
        """
        Evaluate SSL/TLS posture of the target.

        Args:
            context: Shared scan context. Reads ``target_url``.
                     Writes findings via ``context.add_finding()``.
        """
        parsed = urlparse(context.target_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""

        # ------------------------------------------------------------------
        # HTTP target — emit single finding, skip all cert/TLS checks.
        # ------------------------------------------------------------------
        if scheme == "http":
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title="HTTPS Not Enabled",
                    description=(
                        "The target is served over plain HTTP. Traffic "
                        "transmitted over HTTP is unencrypted and can be "
                        "intercepted, read, or modified by any party on the "
                        "network path (man-in-the-middle attacks). Sensitive "
                        "data including session cookies, credentials, and "
                        "personal information are exposed."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Migrate the application to HTTPS. Obtain a TLS "
                        "certificate from a trusted CA (e.g. Let's Encrypt). "
                        "Configure permanent 301 redirects from HTTP to HTTPS "
                        "and enable Strict-Transport-Security."
                    ),
                    evidence=f"Target URL uses scheme: '{scheme}'",
                )
            )
            self.log("HTTP target detected — cert and TLS checks skipped.")
            return

        # ------------------------------------------------------------------
        # HTTPS target — inspect TLS via raw socket (blocking → thread).
        # ------------------------------------------------------------------
        port: int = parsed.port or _DEFAULT_HTTPS_PORT

        self.log(f"Inspecting SSL/TLS for {hostname}:{port}...")

        result = await asyncio.to_thread(
            _inspect_ssl_sync,
            hostname,
            port,
        )

        if result.connection_error:
            self.log(
                f"SSL inspection connection failed: {result.connection_error}",
                logging.WARNING,
            )
            return

        self._evaluate_verification(result, context)
        self._evaluate_expiry(result, hostname, context)
        self._evaluate_self_signed(result, hostname, context)
        self._evaluate_tls_version(result, hostname, context)

    # ------------------------------------------------------------------
    # Finding generators
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_verification(
        result: _SslInspectionResult,
        context: ScanContext,
    ) -> None:
        """Generate a finding if the certificate chain cannot be verified."""
        if not result.is_valid and result.verification_error:
            context.add_finding(
                Finding(
                    plugin="ssl_tls",
                    title="Invalid or Untrusted SSL Certificate",
                    description=(
                        "The SSL/TLS certificate presented by the server "
                        "could not be verified against a trusted Certificate "
                        "Authority. This may indicate the certificate is "
                        "self-signed, expired, or issued by an untrusted CA."
                    ),
                    severity=Severity.CRITICAL,
                    recommendation=(
                        "Replace the certificate with one issued by a "
                        "publicly trusted CA. Ensure the full certificate "
                        "chain (including intermediate certificates) is "
                        "correctly configured on the server."
                    ),
                    evidence=f"Verification error: {result.verification_error}",
                )
            )

    @staticmethod
    def _evaluate_expiry(
        result: _SslInspectionResult,
        hostname: str,
        context: ScanContext,
    ) -> None:
        """Generate a finding if the certificate is expiring soon."""
        if result.not_valid_after is None:
            return

        now_utc = datetime.now(tz=timezone.utc)

        # Ensure timezone-aware for arithmetic
        expiry = result.not_valid_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        days_remaining = (expiry - now_utc).days

        if days_remaining < 0:
            context.add_finding(
                Finding(
                    plugin="ssl_tls",
                    title="SSL Certificate Has Expired",
                    description=(
                        f"The SSL certificate for '{hostname}' expired "
                        f"{abs(days_remaining)} day(s) ago "
                        f"(expiry: {expiry.strftime('%Y-%m-%d')}). "
                        "Browsers will show a security warning to all visitors."
                    ),
                    severity=Severity.CRITICAL,
                    recommendation=(
                        "Renew the SSL certificate immediately. Consider "
                        "using Let's Encrypt with automatic renewal (certbot) "
                        "to prevent future expirations."
                    ),
                    evidence=f"Certificate expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                )
            )
        elif days_remaining <= _EXPIRY_CRITICAL_DAYS:
            context.add_finding(
                Finding(
                    plugin="ssl_tls",
                    title="SSL Certificate Expiring in Less Than 7 Days",
                    description=(
                        f"The SSL certificate for '{hostname}' expires in "
                        f"{days_remaining} day(s) "
                        f"({expiry.strftime('%Y-%m-%d')}). "
                        "Failure to renew will result in browser security "
                        "warnings and service disruption."
                    ),
                    severity=Severity.CRITICAL,
                    recommendation="Renew the SSL certificate immediately.",
                    evidence=f"Certificate expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                )
            )
        elif days_remaining <= _EXPIRY_HIGH_DAYS:
            context.add_finding(
                Finding(
                    plugin="ssl_tls",
                    title="SSL Certificate Expiring Soon",
                    description=(
                        f"The SSL certificate for '{hostname}' expires in "
                        f"{days_remaining} day(s) "
                        f"({expiry.strftime('%Y-%m-%d')}). "
                        "Plan renewal before expiry to avoid disruption."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Renew the SSL certificate within the next few days. "
                        "Automate renewal with certbot or your CA's tooling."
                    ),
                    evidence=f"Certificate expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                )
            )

    @staticmethod
    def _evaluate_self_signed(
        result: _SslInspectionResult,
        hostname: str,
        context: ScanContext,
    ) -> None:
        """Generate a finding if the certificate is self-signed."""
        if result.self_signed:
            context.add_finding(
                Finding(
                    plugin="ssl_tls",
                    title="Self-Signed SSL Certificate Detected",
                    description=(
                        f"The SSL certificate for '{hostname}' is self-signed "
                        "(the issuer and subject are identical). Self-signed "
                        "certificates are not trusted by browsers and cannot "
                        "protect against man-in-the-middle attacks, because "
                        "any attacker could generate their own self-signed cert."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Replace the self-signed certificate with one issued "
                        "by a publicly trusted CA such as Let's Encrypt, "
                        "DigiCert, or Sectigo."
                    ),
                    evidence="Certificate issuer == subject (self-signed).",
                )
            )

    @staticmethod
    def _evaluate_tls_version(
        result: _SslInspectionResult,
        hostname: str,
        context: ScanContext,
    ) -> None:
        """Generate a finding if the negotiated TLS version is outdated."""
        if result.tls_version and result.tls_version in _WEAK_TLS_VERSIONS:
            context.add_finding(
                Finding(
                    plugin="ssl_tls",
                    title=f"Weak TLS Version Negotiated: {result.tls_version}",
                    description=(
                        f"The connection to '{hostname}' negotiated "
                        f"{result.tls_version}, which is considered insecure. "
                        "Older TLS/SSL versions have known cryptographic "
                        "weaknesses (POODLE, BEAST, DROWN, etc.) and are "
                        "no longer considered safe for transmitting sensitive data."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Disable TLS 1.0, TLS 1.1, SSLv2, and SSLv3 on your "
                        "server. Configure the server to support only "
                        "TLS 1.2 and TLS 1.3."
                    ),
                    evidence=f"Negotiated protocol: {result.tls_version}",
                )
            )


# ---------------------------------------------------------------------------
# Synchronous TLS inspection helper (runs in thread pool)
# ---------------------------------------------------------------------------


def _inspect_ssl_sync(
    hostname: str,
    port: int,
) -> _SslInspectionResult:
    """
    Perform a synchronous TLS handshake and collect certificate metadata.

    This function is blocking and must be called via ``asyncio.to_thread``.

    Two connections are made:
      1. With ``CERT_NONE`` to read the raw certificate and TLS version,
         even if the certificate is invalid.
      2. With full verification to determine whether the certificate chain
         is trusted by system CAs.

    Args:
        hostname: The hostname to connect to.
        port:     The TCP port to connect to (default: 443).

    Returns:
        ``_SslInspectionResult`` populated with as much data as was
        retrievable. ``connection_error`` is set if no connection was possible.
    """
    result = _SslInspectionResult()

    # ------------------------------------------------------------------
    # Pass 1 — Connect without verification to read raw cert + TLS version.
    # ------------------------------------------------------------------
    unverified_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified_ctx.check_hostname = False
    unverified_ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=_SOCKET_TIMEOUT,
        ) as raw_sock:
            with unverified_ctx.wrap_socket(
                raw_sock,
                server_hostname=hostname,
            ) as tls_sock:
                result.tls_version = tls_sock.version()
                der_cert = tls_sock.getpeercert(binary_form=True)

                if der_cert:
                    cert = x509.load_der_x509_certificate(
                        der_cert,
                        default_backend(),
                    )
                    result.cert = cert

                    # Certificate expiry — use utc-aware attribute (cryptography >= 42)
                    try:
                        result.not_valid_after = cert.not_valid_after_utc
                    except AttributeError:
                        # Fallback for older cryptography versions
                        result.not_valid_after = cert.not_valid_after  # type: ignore[attr-defined]

                    # Self-signed: issuer equals subject
                    result.self_signed = cert.issuer == cert.subject

    except (OSError, socket.error) as exc:
        result.connection_error = str(exc)
        logger.debug("SSL pass-1 connection error for %s:%d: %s", hostname, port, exc)
        return result

    # ------------------------------------------------------------------
    # Pass 2 — Connect with full verification to test certificate trust.
    # ------------------------------------------------------------------
    verified_ctx = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=_SOCKET_TIMEOUT,
        ) as raw_sock:
            with verified_ctx.wrap_socket(
                raw_sock,
                server_hostname=hostname,
            ):
                pass  # Verification succeeded — certificate is valid.
    except ssl.SSLCertVerificationError as exc:
        result.is_valid = False
        result.verification_error = str(exc)
    except (OSError, socket.error):
        # Network issue on pass-2 — ignore; result from pass-1 is sufficient.
        pass

    return result
