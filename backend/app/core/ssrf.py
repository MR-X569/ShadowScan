"""
app/core/ssrf.py
----------------
Centralized Server-Side Request Forgery (SSRF) Protection & DNS/IP Validation.

Defines non-routable, private, loopback, link-local, multicast, and cloud-metadata
network boundaries for IPv4 and IPv6, with DNS resolution verification to protect
against direct and redirect-based SSRF attacks.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Standard Non-Public IPv4 Networks
_DISALLOWED_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("0.0.0.0/8"),        # "This" network
    ipaddress.IPv4Network("10.0.0.0/8"),       # Private RFC 1918
    ipaddress.IPv4Network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.IPv4Network("127.0.0.0/8"),      # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-local / Cloud metadata (AWS, GCP, Azure)
    ipaddress.IPv4Network("172.16.0.0/12"),    # Private RFC 1918
    ipaddress.IPv4Network("192.0.0.0/24"),     # IETF Protocol Assignments
    ipaddress.IPv4Network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.IPv4Network("192.88.99.0/24"),   # 6to4 Relay Anycast
    ipaddress.IPv4Network("192.168.0.0/16"),   # Private RFC 1918
    ipaddress.IPv4Network("198.18.0.0/15"),    # Benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # Reserved for future use
    ipaddress.IPv4Network("255.255.255.255/32"), # Limited Broadcast
)

# Standard Non-Public IPv6 Networks
_DISALLOWED_IPV6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::/128"),           # Unspecified
    ipaddress.IPv6Network("::1/128"),          # Loopback
    ipaddress.IPv6Network("::ffff:0:0/96"),    # IPv4-mapped IPv6
    ipaddress.IPv6Network("64:ff9b::/96"),     # IPv4/IPv6 translation
    ipaddress.IPv6Network("100::/64"),         # Discard prefix
    ipaddress.IPv6Network("2001::/23"),        # IETF Protocol Assignments
    ipaddress.IPv6Network("2001:db8::/32"),    # Documentation
    ipaddress.IPv6Network("fc00::/7"),         # Unique local (ULA)
    ipaddress.IPv6Network("fe80::/10"),        # Link-local
    ipaddress.IPv6Network("ff00::/8"),         # Multicast
)

# Hostname keywords explicitly associated with cloud metadata or internal aliases
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "instance-data",
    "metadata.google.internal",
    "metadata.internal",
})


class SSRFSecurityError(ValueError):
    """Raised when a URL or resolved destination violates SSRF protection boundaries."""


def is_ip_allowed(ip_str: str) -> bool:
    """
    Check whether an IP address is a public, routable destination.
    Returns False for private, loopback, link-local, multicast, or reserved IPs.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if isinstance(ip, ipaddress.IPv4Address):
        if not ip.is_global:
            return False
        for net in _DISALLOWED_IPV4_NETWORKS:
            if ip in net:
                return False
        return True

    if isinstance(ip, ipaddress.IPv6Address):
        if not ip.is_global:
            return False
        for net in _DISALLOWED_IPV6_NETWORKS:
            if ip in net:
                return False
        return True

    return False


def resolve_hostname_ips(hostname: str) -> list[str]:
    """
    Resolve all IPv4 and IPv6 addresses for a hostname.
    """
    resolved_ips: set[str] = set()
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            resolved_ips.add(ip_str)
    except socket.gaierror as exc:
        raise SSRFSecurityError(f"Cannot resolve target hostname '{hostname}': {exc}") from exc
    except Exception as exc:
        raise SSRFSecurityError(f"DNS resolution failure for '{hostname}': {exc}") from exc

    if not resolved_ips:
        raise SSRFSecurityError(f"No IP addresses resolved for hostname '{hostname}'.")

    return list(resolved_ips)


def validate_url_for_ssrf(url_str: str) -> str:
    """
    Validate a URL string for SSRF safety.

    Checks:
        1. Scheme must be http or https.
        2. Hostname must be present and not an internal/localhost alias.
        3. All resolved IP addresses must be publicly routable.

    Returns:
        The validated URL string.

    Raises:
        SSRFSecurityError if the URL targets a forbidden destination.
    """
    if not url_str:
        raise SSRFSecurityError("Target URL cannot be empty.")

    try:
        parsed = urlparse(url_str.strip())
    except Exception as exc:
        raise SSRFSecurityError(f"Invalid URL structure: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise SSRFSecurityError(f"Prohibited URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.hostname or "").lower().strip("[]")
    if not hostname:
        raise SSRFSecurityError("Target URL does not specify a valid hostname.")

    if hostname in _BLOCKED_HOSTNAMES or hostname.endswith(".internal") or hostname.endswith(".local"):
        raise SSRFSecurityError(f"Prohibited internal hostname '{hostname}'.")

    # If the hostname is a direct literal IP address
    try:
        direct_ip = ipaddress.ip_address(hostname)
        if not is_ip_allowed(str(direct_ip)):
            raise SSRFSecurityError(
                f"Target IP address '{direct_ip}' belongs to a private, loopback, or non-public network range."
            )
        return url_str
    except ValueError:
        # Hostname is a domain name — resolve all DNS records
        pass

    resolved_ips = resolve_hostname_ips(hostname)
    for ip in resolved_ips:
        if not is_ip_allowed(ip):
            raise SSRFSecurityError(
                f"Hostname '{hostname}' resolved to prohibited IP '{ip}' (private/loopback/cloud metadata address)."
            )

    return url_str
