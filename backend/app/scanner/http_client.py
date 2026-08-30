"""
app/scanner/http_client.py
--------------------------
Shared async HTTP client for the ShadowScan scanner framework.

Architecture rule:
    ONLY this module creates ``httpx.AsyncClient`` instances.
    Plugins that need to make HTTP requests MUST use ``context.session``
    (injected by the engine). Plugins must NEVER instantiate their own clients.

Features:
    - Async context manager via ``create_http_client()``
    - Connection pooling via ``httpx.Limits``
    - Granular timeouts (connect / read / write / pool)
    - Automatic redirect following (capped at a safe maximum)
    - SSL verification enabled by default
    - Exponential-backoff retry strategy via ``RetryTransport``
      (pure stdlib — no external retry library required)
    - Custom User-Agent header
    - Configurable via ``HttpClientConfig`` dataclass
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCANNER_USER_AGENT: str = (
    "ShadowScan/1.0 (+https://shadowscan.io; Security Scanner)"
)

# HTTP status codes that warrant a retry (rate-limit and server errors).
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

# Network-level exception types that warrant a retry.
_RETRYABLE_EXCEPTIONS: tuple[type[Exception], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class HttpClientConfig:
    """
    Configuration for the shared scanner HTTP client.

    All timeout values are in seconds. The defaults are tuned for external
    web application scanning and represent a reasonable balance between
    thoroughness and scan speed.

    Attributes:
        timeout_connect:           Max seconds to wait for a TCP connection.
        timeout_read:              Max seconds to wait for response data.
        timeout_write:             Max seconds to wait when sending request data.
        timeout_pool:              Max seconds to wait for a connection from the pool.
        max_connections:           Maximum concurrent connections across all hosts.
        max_keepalive_connections: Maximum keep-alive connections in the pool.
        follow_redirects:          Whether to follow HTTP redirects automatically.
        max_redirects:             Maximum number of redirects before aborting.
        verify_ssl:                Verify SSL certificates (always True in production).
        user_agent:                Value of the ``User-Agent`` request header.
        max_retries:               Maximum retry attempts per request (not counting
                                   the initial attempt).
        retry_backoff_factor:      Base sleep seconds between retries. Sleep duration
                                   is calculated as ``factor * 2^(attempt - 1)``.
        extra_headers:             Additional headers merged into every request.
    """

    # Timeouts
    timeout_connect: float = 10.0
    timeout_read: float = 30.0
    timeout_write: float = 10.0
    timeout_pool: float = 10.0

    # Connection pool
    max_connections: int = 20
    max_keepalive_connections: int = 10

    # Redirect behaviour
    follow_redirects: bool = True
    max_redirects: int = 10

    # Security — SSL verification is always enabled by default
    verify_ssl: bool = True

    # Identity
    user_agent: str = SCANNER_USER_AGENT

    # Retry strategy
    max_retries: int = 3
    retry_backoff_factor: float = 0.5

    # Optional extra headers for every request
    extra_headers: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Retry Transport
# ---------------------------------------------------------------------------


from app.core.ssrf import SSRFSecurityError, validate_url_for_ssrf


class RetryTransport(httpx.AsyncBaseTransport):
    """
    Thin ``httpx.AsyncBaseTransport`` wrapper that adds exponential-backoff
    retries and strict SSRF destination validation.

    Retries are triggered by:
      - Network-level exceptions (``ConnectError``, timeouts, protocol errors).
      - HTTP responses with retryable status codes (``429``, ``5xx``).

    SSRF Protection:
      - Every outbound request URL (including redirects) is validated against
        non-routable, private, loopback, and cloud metadata network boundaries.
      - Disallowed destinations raise ``SSRFSecurityError`` immediately without retry.
    """

    def __init__(
        self,
        transport: httpx.AsyncHTTPTransport,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        retryable_codes: frozenset[int] = _RETRYABLE_STATUS_CODES,
    ) -> None:
        self._transport = transport
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._retryable_codes = retryable_codes

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        """
        Handle a single request, validating destination for SSRF safety and
        retrying on transient network failures.

        Args:
            request: The outgoing ``httpx.Request`` object.

        Returns:
            The ``httpx.Response`` from the server.

        Raises:
            SSRFSecurityError: If destination resolves to a private/internal IP.
            Network-level exception: If all retry attempts are exhausted.
        """
        # --- Pre-request SSRF Validation (Validates initial URL & all redirects) ---
        validate_url_for_ssrf(str(request.url))

        last_exception: Exception | None = None

        for attempt in range(self._max_retries + 1):

            # Exponential back-off before every retry (not before the first try).
            if attempt > 0:
                sleep_seconds = self._backoff_factor * (2 ** (attempt - 1))
                logger.debug(
                    "RetryTransport: attempt %d/%d for %s — "
                    "sleeping %.2fs before retry.",
                    attempt,
                    self._max_retries,
                    request.url,
                    sleep_seconds,
                )
                await asyncio.sleep(sleep_seconds)

            # --- Attempt the request ------------------------------------------
            try:
                response = await self._transport.handle_async_request(request)
            except _RETRYABLE_EXCEPTIONS as exc:
                last_exception = exc
                if attempt < self._max_retries:
                    logger.warning(
                        "RetryTransport: network error on attempt %d "
                        "for %s: %s",
                        attempt,
                        request.url,
                        exc,
                    )
                    continue
                # Final attempt — re-raise the exception.
                raise

            # --- Inspect response status -------------------------------------
            if response.status_code not in self._retryable_codes:
                return response

            if attempt == self._max_retries:
                # Final attempt — return whatever status code we got.
                return response

            logger.warning(
                "RetryTransport: HTTP %d on attempt %d for %s — will retry.",
                response.status_code,
                attempt,
                request.url,
            )

            # Drain the body before releasing the connection back to the pool.
            await response.aclose()

        # Unreachable in practice; satisfies the type checker.
        if last_exception is not None:
            raise last_exception
        raise RuntimeError("RetryTransport: exhausted retries with no result.")

    async def aclose(self) -> None:
        """Delegate close to the underlying transport."""
        await self._transport.aclose()


# ---------------------------------------------------------------------------
# Factory — public API
# ---------------------------------------------------------------------------


@asynccontextmanager
async def create_http_client(
    config: HttpClientConfig | None = None,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """
    Async context manager that yields a fully-configured ``httpx.AsyncClient``.

    The client is closed automatically when the ``async with`` block exits,
    releasing all pooled connections.

    Usage::

        async with create_http_client() as client:
            response = await client.get("https://example.com")
            print(response.status_code)

    Args:
        config: Optional ``HttpClientConfig`` instance. Uses production
                defaults when ``None``.

    Yields:
        A ready-to-use ``httpx.AsyncClient`` with retry, pooling,
        and timeout support.
    """
    cfg = config or HttpClientConfig()

    timeout = httpx.Timeout(
        connect=cfg.timeout_connect,
        read=cfg.timeout_read,
        write=cfg.timeout_write,
        pool=cfg.timeout_pool,
    )

    limits = httpx.Limits(
        max_connections=cfg.max_connections,
        max_keepalive_connections=cfg.max_keepalive_connections,
    )

    base_transport = httpx.AsyncHTTPTransport(
        limits=limits,
        verify=cfg.verify_ssl,
    )

    retry_transport = RetryTransport(
        transport=base_transport,
        max_retries=cfg.max_retries,
        backoff_factor=cfg.retry_backoff_factor,
    )

    default_headers: dict[str, str] = {
        "User-Agent": cfg.user_agent,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        **cfg.extra_headers,
    }

    logger.debug(
        "HttpClient: opening session "
        "(ssl_verify=%s, max_retries=%d, timeout_read=%.1fs).",
        cfg.verify_ssl,
        cfg.max_retries,
        cfg.timeout_read,
    )

    async with httpx.AsyncClient(
        transport=retry_transport,
        timeout=timeout,
        follow_redirects=cfg.follow_redirects,
        max_redirects=cfg.max_redirects,
        verify=cfg.verify_ssl,
        headers=default_headers,
    ) as client:
        yield client

    logger.debug("HttpClient: session closed.")
