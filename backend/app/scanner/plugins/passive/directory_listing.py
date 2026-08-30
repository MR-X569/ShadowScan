"""
app/scanner/plugins/passive/directory_listing.py
------------------------------------------------
Directory Listing & Backup Exposure Plugin — identifies exposed web server
directory indexes (Apache, Nginx, IIS) and sensitive archive/database backup files.

Checks performed:
    - Web server directory listing detection (Index of /, nginx autoindex, IIS directory listing)
    - Sensitive database dump discovery (.sql, .dump)
    - Archive and backup file exposure (.zip, .tar.gz, .bak, .old)
    - Strict SPA fallback anti-signature validation to prevent false positives

Severity Logic:
    - Confirmed exposed database backup (.sql dump) -> CRITICAL
    - Confirmed exposed application/source archive (.zip, .tar.gz, .bak) -> HIGH
    - Sensitive directory index (/backup/, /tmp/, /old/) -> HIGH
    - General directory index (/uploads/, /files/, /static/, /assets/) -> MEDIUM
    - Root directory index (/) -> LOW
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

# Max bytes to inspect from file responses to avoid large downloads
_MAX_RESPONSE_PEEK_BYTES: int = 2048

# ---------------------------------------------------------------------------
# Directory Indexing Signatures
# ---------------------------------------------------------------------------

_DIR_LISTING_REGEXES: list[re.Pattern[str]] = [
    re.compile(r"<title>\s*Index of\s+/[^<]*</title>", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of\s+/[^<]*</h1>", re.IGNORECASE),
    re.compile(r"<pre><a href=\"\.\./\">\[To Parent Directory\]</a>", re.IGNORECASE),
    re.compile(r"<a href=\"/[^\"]*\">\[To Parent Directory\]</a>", re.IGNORECASE),
    re.compile(r"<title>Directory Listing -- /[^<]*</title>", re.IGNORECASE),
    re.compile(r"<pre><a href=\"\.\./\">\.\./</a>", re.IGNORECASE),
]

_DIR_PATHS_TO_CHECK: list[tuple[str, str, Severity]] = [
    ("/backup/", "Backup Directory", Severity.HIGH),
    ("/backups/", "Backups Directory", Severity.HIGH),
    ("/old/", "Old Files Directory", Severity.HIGH),
    ("/tmp/", "Temporary Files Directory", Severity.HIGH),
    ("/uploads/", "Uploads Directory", Severity.MEDIUM),
    ("/files/", "Files Directory", Severity.MEDIUM),
    ("/static/", "Static Assets Directory", Severity.MEDIUM),
    ("/assets/", "Assets Directory", Severity.MEDIUM),
]


# ---------------------------------------------------------------------------
# Backup & Archive File Definitions
# ---------------------------------------------------------------------------

@dataclass
class _BackupProbe:
    path: str
    title: str
    severity: Severity
    description: str
    is_database: bool = False
    is_archive: bool = False


_BACKUP_FILE_PROBES: list[_BackupProbe] = [
    _BackupProbe(
        path="/backup.sql",
        title="Exposed Database Dump File (backup.sql)",
        severity=Severity.CRITICAL,
        description="A database dump file (backup.sql) is publicly accessible, exposing tables, schemas, and user data.",
        is_database=True,
    ),
    _BackupProbe(
        path="/db.sql",
        title="Exposed Database Dump File (db.sql)",
        severity=Severity.CRITICAL,
        description="A database dump file (db.sql) is publicly accessible without authentication.",
        is_database=True,
    ),
    _BackupProbe(
        path="/database.sql",
        title="Exposed Database Dump File (database.sql)",
        severity=Severity.CRITICAL,
        description="A database backup file (database.sql) is publicly downloadable from the web root.",
        is_database=True,
    ),
    _BackupProbe(
        path="/dump.sql",
        title="Exposed Database Dump File (dump.sql)",
        severity=Severity.CRITICAL,
        description="A raw SQL database dump file (dump.sql) is publicly accessible.",
        is_database=True,
    ),
    _BackupProbe(
        path="/backup.zip",
        title="Exposed Backup Archive File (backup.zip)",
        severity=Severity.HIGH,
        description="A compressed backup archive (backup.zip) is publicly accessible on the web server.",
        is_archive=True,
    ),
    _BackupProbe(
        path="/site.zip",
        title="Exposed Site Archive File (site.zip)",
        severity=Severity.HIGH,
        description="A full web application archive (site.zip) is publicly accessible.",
        is_archive=True,
    ),
    _BackupProbe(
        path="/backup.tar.gz",
        title="Exposed Compressed Archive File (backup.tar.gz)",
        severity=Severity.HIGH,
        description="A compressed tar archive (backup.tar.gz) is publicly downloadable.",
        is_archive=True,
    ),
]

_SQL_SIGNATURES: re.Pattern[str] = re.compile(
    r"(?:CREATE\s+TABLE|INSERT\s+INTO|--\s*MySQL\s+dump|--\s*PostgreSQL\s+database\s+dump|CREATE\s+DATABASE|DROP\s+TABLE)",
    re.IGNORECASE,
)

_HTML_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)


class DirectoryListingPlugin(BasePlugin):
    """
    Scans for exposed directory indexes and accessible backup/archive files.
    """

    name = "directory_listing"
    description = (
        "Detects exposed web server directory indexes and sensitive backup/archive file disclosures."
    )
    category = "passive"
    version = "1.0.0"
    priority = 65

    async def run(self, context: ScanContext) -> None:
        """
        Execute directory listing and backup exposure checks.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping directory listing checks.")
            return

        client = context.session
        base_url = self._get_base_url(context.target_url)

        # 1. Check Root & Common Directory Paths
        await self._check_directory_indexes(client, base_url, context)

        # 2. Check High-Signal Backup & Archive Files
        await self._check_backup_files(client, base_url, context)

    # ------------------------------------------------------------------
    # Directory Index Checks
    # ------------------------------------------------------------------

    async def _check_directory_indexes(
        self,
        client: Any,
        base_url: str,
        context: ScanContext,
    ) -> None:
        """Probe common directories to see if directory indexing is enabled."""
        for path, label, severity in _DIR_PATHS_TO_CHECK:
            target_dir_url = urljoin(base_url, path)

            try:
                response = await client.get(target_dir_url)

                if response.status_code == 200:
                    text = response.text[:_MAX_RESPONSE_PEEK_BYTES]

                    # Check for directory indexing signature
                    if self._is_directory_listing(text):
                        evidence = (
                            f"Directory URL: {target_dir_url}\n"
                            f"HTTP Status: 200 OK\n"
                            f"Content-Type: {response.headers.get('content-type', 'unknown')}\n"
                            f"Matched Directory Index Signature: 'Index of {path}'"
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=f"Directory Indexing Enabled on {path}",
                                description=(
                                    f"Directory listing is enabled on '{target_dir_url}' ({label}). "
                                    f"The web server automatically generates an index of all files in this directory, "
                                    f"allowing attackers to discover sensitive uploaded files, source files, "
                                    f"and internal folder structures."
                                ),
                                severity=severity,
                                recommendation=(
                                    f"Disable directory indexing on the web server. For Apache, set 'Options -Indexes'. "
                                    f"For Nginx, set 'autoindex off;'. For IIS, disable Directory Browsing in IIS Manager."
                                ),
                                evidence=evidence,
                            )
                        )

            except Exception as exc:
                self.log(f"Directory index check for '{target_dir_url}' failed: {exc}")

    # ------------------------------------------------------------------
    # Backup & Archive File Checks
    # ------------------------------------------------------------------

    async def _check_backup_files(
        self,
        client: Any,
        base_url: str,
        context: ScanContext,
    ) -> None:
        """Probe high-signal backup and database archive files."""
        for probe in _BACKUP_FILE_PROBES:
            target_file_url = urljoin(base_url, probe.path)

            try:
                response = await client.get(target_file_url)

                if response.status_code == 200:
                    raw_bytes = response.content[:_MAX_RESPONSE_PEEK_BYTES]
                    text = response.text[:_MAX_RESPONSE_PEEK_BYTES] if response.text else ""
                    content_type = response.headers.get("content-type", "").lower()

                    is_valid, signature_desc = self._verify_backup_content(probe, raw_bytes, text, content_type)

                    if is_valid:
                        evidence = (
                            f"File URL: {target_file_url}\n"
                            f"HTTP Status: 200 OK\n"
                            f"Content-Type: {content_type}\n"
                            f"Verified Signature: {signature_desc}\n"
                            f"Content Peek: {text[:200].strip() if text else '[Binary Archive Bytes]'}"
                        )

                        context.add_finding(
                            Finding(
                                plugin=self.name,
                                title=probe.title,
                                description=(
                                    f"{probe.description} Public exposure of backup and archive files enables "
                                    f"attackers to access database schemas, private customer records, configuration "
                                    f"passwords, or complete source code."
                                ),
                                severity=probe.severity,
                                recommendation=(
                                    f"Immediately remove publicly accessible backup files from the web root '{probe.path}'. "
                                    f"Configure web server rules to deny access to .sql, .zip, .tar.gz, and .bak files."
                                ),
                                evidence=evidence,
                            )
                        )

            except Exception as exc:
                self.log(f"Backup file probe for '{target_file_url}' failed: {exc}")

    # ------------------------------------------------------------------
    # Content & Signature Verification Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_directory_listing(html_text: str) -> bool:
        """Check if HTML content contains authentic directory indexing signatures."""
        if not html_text:
            return False

        # If it's an SPA or generic website template, skip
        if "<div id=\"root\"" in html_text or "<div id=\"app\"" in html_text:
            return False

        for pattern in _DIR_LISTING_REGEXES:
            if pattern.search(html_text):
                return True

        # Check table headers characteristic of directory listings
        if "parent directory" in html_text.lower() and ("last modified" in html_text.lower() or "size" in html_text.lower()):
            return True

        return False

    @staticmethod
    def _verify_backup_content(
        probe: _BackupProbe,
        raw_bytes: bytes,
        text: str,
        content_type: str,
    ) -> tuple[bool, str]:
        """
        Verify that the response is an actual database dump or archive file,
        not an HTML SPA 200 OK fallback.
        """
        # If content starts with HTML anti-signature and is text/html, it's a fallback page
        if "text/html" in content_type and _HTML_ANTI_SIGNATURE.search(text):
            return False, ""

        if probe.is_database:
            if _SQL_SIGNATURES.search(text):
                return True, "SQL DDL/DML Statement Signature (CREATE TABLE / INSERT INTO / Dump Header)"

        elif probe.is_archive:
            # Check Zip Magic Bytes (PK\x03\x04 or PK\x05\x06)
            if raw_bytes.startswith(b"PK\x03\x04") or raw_bytes.startswith(b"PK\x05\x06") or "application/zip" in content_type:
                return True, "Valid ZIP Archive Magic Header (PK\x03\x04)"

            # Check Gzip Magic Bytes (\x1f\x8b)
            if raw_bytes.startswith(b"\x1f\x8b") or "application/gzip" in content_type:
                return True, "Valid GZIP/TAR Archive Magic Header (\x1f\x8b)"

            # Check general non-HTML binary archive
            if "application/octet-stream" in content_type and not _HTML_ANTI_SIGNATURE.search(text):
                return True, "Binary Stream Archive Header"

        return False, ""

    @staticmethod
    def _get_base_url(target_url: str) -> str:
        """Extract scheme and netloc from target URL."""
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}"
