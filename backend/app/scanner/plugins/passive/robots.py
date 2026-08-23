"""
app/scanner/plugins/passive/robots.py
---------------------------------------
robots.txt Plugin — fetches and analyses the robots.txt file for sensitive
path disclosures that could assist attackers in mapping the application.

Checks:
    - robots.txt reachable and non-empty
    - robots.txt absent (LOW informational)
    - Sensitive or interesting paths in Disallow/Allow rules
      (admin panels, backup files, config endpoints, etc.)

Output:
    - ``context.metadata["robots_disallowed_paths"]`` → ``list[str]``
    - Zero or more ``Finding`` objects

The plugin uses ``context.session`` (the shared httpx.AsyncClient injected
by the engine) to fetch ``/robots.txt``. It must never create its own client.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import httpx

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Patterns in Disallow/Allow paths that indicate sensitive endpoints.
# Each entry is (compiled_regex, human-readable description).
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"admin|administrator|wp-admin|backend|dashboard", re.I), "Admin panel"),
    (re.compile(r"backup|back-?up|\.bak|\.sql|\.tar|\.zip", re.I), "Backup file/directory"),
    (re.compile(r"config|configuration|settings|setup", re.I), "Configuration endpoint"),
    (re.compile(r"secret|private|confidential|internal|intranet", re.I), "Private area"),
    (re.compile(r"/api/|/graphql|/rest/|/swagger|/openapi", re.I), "API endpoint"),
    (re.compile(r"login|signin|auth|oauth|sso", re.I), "Authentication endpoint"),
    (re.compile(r"phpmyadmin|cpanel|webmail|plesk|whm", re.I), "Hosting control panel"),
    (re.compile(r"debug|test|dev|staging|qa|demo", re.I), "Development/test path"),
    (re.compile(r"upload|uploads|files|media|static", re.I), "File upload directory"),
    (re.compile(r"log|logs|error_log|access_log", re.I), "Log directory"),
    (re.compile(r"database|db|\.db|\.sqlite", re.I), "Database file/directory"),
    (re.compile(r"\.env|\.git|\.svn|\.htaccess|\.htpasswd", re.I), "Sensitive dotfile"),
    (re.compile(r"tmp|temp|cache|\.cache", re.I), "Temporary/cache directory"),
    (re.compile(r"cron|cgi-bin|scripts|cmd|shell", re.I), "Script/cron endpoint"),
]


class RobotsPlugin(BasePlugin):
    """
    Fetches and analyses ``/robots.txt`` for sensitive path disclosures.

    Reads ``context.session`` for HTTP access.
    Writes to ``context.metadata["robots_disallowed_paths"]``.
    """

    name = "robots_txt"
    description = (
        "Fetches robots.txt and analyses Disallow rules for "
        "sensitive path disclosures"
    )
    category = "passive"
    version = "1.0.0"
    priority = 40

    async def run(self, context: ScanContext) -> None:
        """
        Fetch ``/robots.txt`` and evaluate its directives.

        Args:
            context: Shared scan context. Uses ``target_url`` and ``session``.
        """
        if context.session is None:
            self.log("No HTTP session in context — skipping.", logging.WARNING)
            return

        client: httpx.AsyncClient = context.session
        robots_url = self._build_robots_url(context.target_url)

        self.log(f"Fetching {robots_url}")

        # ------------------------------------------------------------------
        # Fetch robots.txt
        # ------------------------------------------------------------------
        try:
            response = await client.get(robots_url)
        except Exception as exc:  # noqa: BLE001
            self.log(
                f"Failed to fetch {robots_url}: {exc}",
                logging.WARNING,
            )
            return

        # ------------------------------------------------------------------
        # Not found — informational finding
        # ------------------------------------------------------------------
        if response.status_code == 404:
            context.set_metadata("robots_disallowed_paths", [])
            self.log("robots.txt not found (HTTP 404).")
            return

        # Non-200, non-404 — skip silently
        if response.status_code != 200:
            self.log(
                f"Unexpected HTTP {response.status_code} for {robots_url} — skipping.",
                logging.WARNING,
            )
            return

        content = response.text.strip()

        if not content:
            self.log("robots.txt is empty.")
            return

        # ------------------------------------------------------------------
        # Parse directives
        # ------------------------------------------------------------------
        disallowed_paths = self._parse_directives(content)
        context.set_metadata("robots_disallowed_paths", disallowed_paths)

        self.log(
            f"Found {len(disallowed_paths)} Disallow/Allow path(s) in robots.txt."
        )

        # ------------------------------------------------------------------
        # Check for sensitive paths
        # ------------------------------------------------------------------
        sensitive_hits: list[tuple[str, str]] = []

        for path in disallowed_paths:
            for pattern, description in _SENSITIVE_PATH_PATTERNS:
                if pattern.search(path):
                    sensitive_hits.append((path, description))
                    break  # One match per path is enough

        if not sensitive_hits:
            return

        # Emit one finding per sensitive path for granular severity tracking.
        for path, description in sensitive_hits:
            context.add_finding(
                Finding(
                    plugin=self.name,
                    title=f"Sensitive Path Exposed in robots.txt: {path}",
                    description=(
                        f"The robots.txt file contains a directive for the "
                        f"path '{path}', which appears to be a {description}. "
                        "While robots.txt is intended to guide search engine "
                        "crawlers, it is publicly accessible and frequently "
                        "used by attackers to enumerate sensitive application "
                        "endpoints that the site owner intended to keep hidden."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Do not rely on robots.txt to hide sensitive endpoints. "
                        "Protect sensitive paths with proper authentication and "
                        "authorisation controls. If the path does not need to "
                        "exist publicly, remove it entirely."
                    ),
                    evidence=f"robots.txt directive for: {path} ({description})",
                )
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_robots_url(target_url: str) -> str:
        """Construct the absolute URL for robots.txt from the target URL."""
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    @staticmethod
    def _parse_directives(content: str) -> list[str]:
        """
        Extract all Disallow and Allow path values from robots.txt content.

        Handles:
            - Multiple ``User-agent`` blocks
            - Both ``Disallow`` and ``Allow`` directives
            - Comments (lines starting with ``#``)
            - Wildcard paths (``*``)

        Args:
            content: Raw text content of robots.txt.

        Returns:
            Deduplicated list of path values from all directives.
        """
        paths: list[str] = []
        seen: set[str] = set()

        for line in content.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Match Disallow or Allow directives
            match = re.match(
                r"^(?:Disallow|Allow)\s*:\s*(.+)$",
                line,
                re.IGNORECASE,
            )
            if not match:
                continue

            path = match.group(1).strip()

            # Strip inline comments
            if "#" in path:
                path = path[: path.index("#")].strip()

            # Skip empty paths (a blank Disallow means "allow all")
            if not path:
                continue

            if path not in seen:
                seen.add(path)
                paths.append(path)

        return paths
