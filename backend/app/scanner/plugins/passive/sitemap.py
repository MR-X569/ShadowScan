"""
app/scanner/plugins/passive/sitemap.py
----------------------------------------
Sitemap Plugin — fetches ``sitemap.xml``, extracts the URL inventory, and
checks for information-disclosure risks.

Checks:
    - sitemap.xml reachable
    - sitemap.xml absent (informational)
    - Number of exposed URLs (large sitemaps indicate significant surface area)
    - Non-HTTPS URLs present in an HTTPS site's sitemap (mixed-content risk)
    - Sitemap index files (``<sitemapindex>``) — discovers sub-sitemaps

Output:
    - ``context.metadata["sitemap_urls"]``   → ``list[str]`` of all discovered URLs
    - ``context.metadata["sitemap_found"]``  → ``bool``
    - Zero or more ``Finding`` objects

The plugin uses ``context.session`` (shared httpx.AsyncClient injected by
the engine) for all HTTP requests. Parsing uses stdlib ``xml.etree.ElementTree``.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import httpx

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# XML namespaces used in sitemaps and sitemap index files.
_SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"

# Findings thresholds.
_LARGE_SITEMAP_THRESHOLD: int = 500  # URL count above which we flag disclosure risk

# Maximum sub-sitemaps to follow in a sitemap index (prevents runaway requests).
_MAX_SITEMAP_INDEX_DEPTH: int = 5


class SitemapPlugin(BasePlugin):
    """
    Fetches ``sitemap.xml``, extracts URL inventory, and identifies
    information-disclosure risks.

    Reads ``context.session`` for HTTP access.
    Writes to ``context.metadata["sitemap_urls"]`` and
    ``context.metadata["sitemap_found"]``.
    """

    name = "sitemap_xml"
    description = (
        "Fetches sitemap.xml, extracts URL inventory, and checks for "
        "information-disclosure risks"
    )
    category = "passive"
    version = "1.0.0"
    priority = 50

    async def run(self, context: ScanContext) -> None:
        """
        Fetch and analyse ``sitemap.xml``.

        Args:
            context: Shared scan context. Uses ``target_url`` and ``session``.
        """
        if context.session is None:
            self.log("No HTTP session in context — skipping.", logging.WARNING)
            return

        client: httpx.AsyncClient = context.session
        target_is_https = context.target_url.lower().startswith("https://")
        sitemap_url = self._build_sitemap_url(context.target_url)

        self.log(f"Fetching {sitemap_url}")

        # ------------------------------------------------------------------
        # Fetch the primary sitemap
        # ------------------------------------------------------------------
        content = await self._fetch_xml(client, sitemap_url)

        if content is None:
            context.set_metadata("sitemap_found", False)
            context.set_metadata("sitemap_urls", [])
            self.log("sitemap.xml not found or not accessible.")
            return

        context.set_metadata("sitemap_found", True)

        # ------------------------------------------------------------------
        # Parse and collect all URLs
        # ------------------------------------------------------------------
        all_urls: list[str] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            self.log(f"Failed to parse sitemap XML: {exc}", logging.WARNING)
            context.set_metadata("sitemap_urls", [])
            return

        tag = root.tag.lower()

        if "sitemapindex" in tag:
            # This is a sitemap index — discover and follow sub-sitemaps.
            all_urls = await self._process_sitemap_index(client, root)
        else:
            # Standard URL set sitemap.
            all_urls = self._extract_urls(root)

        context.set_metadata("sitemap_urls", all_urls)

        self.log(f"Extracted {len(all_urls)} URL(s) from sitemap.")

        # ------------------------------------------------------------------
        # Evaluate findings
        # ------------------------------------------------------------------
        self._check_large_sitemap(all_urls, sitemap_url, context)

        if target_is_https:
            self._check_non_https_urls(all_urls, context)

    # ------------------------------------------------------------------
    # Finding generators
    # ------------------------------------------------------------------

    @staticmethod
    def _check_large_sitemap(
        urls: list[str],
        sitemap_url: str,
        context: ScanContext,
    ) -> None:
        """Flag large URL inventories as a potential information disclosure."""
        if len(urls) > _LARGE_SITEMAP_THRESHOLD:
            context.add_finding(
                Finding(
                    plugin="sitemap_xml",
                    title="Large URL Inventory Exposed in sitemap.xml",
                    description=(
                        f"The sitemap.xml exposes {len(urls):,} URLs, providing "
                        "attackers with a comprehensive map of the application's "
                        "URL structure. This significantly reduces the effort "
                        "required to enumerate endpoints for further attacks."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Review the sitemap to ensure only public-facing pages "
                        "are included. Remove internal, administrative, or "
                        "sensitive URLs from the sitemap. Consider restricting "
                        "sitemap access to search engine bots via IP allowlisting."
                    ),
                    evidence=(
                        f"sitemap.xml at '{sitemap_url}' contains "
                        f"{len(urls):,} URLs."
                    ),
                )
            )

    @staticmethod
    def _check_non_https_urls(
        urls: list[str],
        context: ScanContext,
    ) -> None:
        """Flag HTTP URLs present in an HTTPS site's sitemap."""
        http_urls = [u for u in urls if u.lower().startswith("http://")]

        if not http_urls:
            return

        sample = http_urls[:5]
        sample_str = "\n".join(f"  - {u}" for u in sample)
        count_remaining = len(http_urls) - len(sample)
        suffix = (
            f"\n  ... and {count_remaining} more."
            if count_remaining > 0
            else ""
        )

        context.add_finding(
            Finding(
                plugin="sitemap_xml",
                title="Non-HTTPS URLs Found in sitemap.xml",
                description=(
                    f"The sitemap.xml of this HTTPS site contains "
                    f"{len(http_urls)} URL(s) using the plain HTTP scheme. "
                    "These URLs may be accessible over unencrypted HTTP, "
                    "exposing users to interception and mixed-content warnings."
                ),
                severity=Severity.MEDIUM,
                recommendation=(
                    "Update all URLs in the sitemap to use HTTPS. "
                    "Ensure HTTP-to-HTTPS redirects are in place for all "
                    "pages. Regenerate the sitemap after fixing the redirects."
                ),
                evidence=f"Non-HTTPS URLs (sample):\n{sample_str}{suffix}",
            )
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_sitemap_url(target_url: str) -> str:
        """Construct the absolute URL for sitemap.xml from the target URL."""
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"

    @staticmethod
    async def _fetch_xml(
        client: httpx.AsyncClient,
        url: str,
    ) -> str | None:
        """
        Fetch a URL and return the response body as a string if successful.

        Returns:
            Response body text, or ``None`` if the resource was not found
            or the request failed.
        """
        try:
            response = await client.get(url)
        except Exception as exc:  # noqa: BLE001
            logger.debug("sitemap_xml: failed to fetch '%s': %s", url, exc)
            return None

        if response.status_code != 200:
            logger.debug(
                "sitemap_xml: HTTP %d for '%s'.",
                response.status_code,
                url,
            )
            return None

        content_type = response.headers.get("content-type", "").lower()
        # Accept XML and text content types.
        if "html" in content_type and "xml" not in content_type:
            logger.debug(
                "sitemap_xml: '%s' returned HTML — not a sitemap.",
                url,
            )
            return None

        return response.text

    @staticmethod
    def _extract_urls(root: ET.Element) -> list[str]:
        """
        Extract ``<loc>`` values from a standard ``<urlset>`` sitemap element.

        Args:
            root: Parsed root XML element.

        Returns:
            List of URL strings.
        """
        urls: list[str] = []

        for url_el in root.iter(f"{{{_SITEMAP_NS}}}url"):
            loc_el = url_el.find(f"{{{_SITEMAP_NS}}}loc")
            if loc_el is not None and loc_el.text:
                urls.append(loc_el.text.strip())

        # Fallback: try without namespace prefix (some sitemaps omit it).
        if not urls:
            for url_el in root.iter("url"):
                loc_el = url_el.find("loc")
                if loc_el is not None and loc_el.text:
                    urls.append(loc_el.text.strip())

        return urls

    async def _process_sitemap_index(
        self,
        client: httpx.AsyncClient,
        root: ET.Element,
    ) -> list[str]:
        """
        Extract sub-sitemap URLs from a ``<sitemapindex>`` document, fetch each
        sub-sitemap, and aggregate all URLs.

        Fetches at most ``_MAX_SITEMAP_INDEX_DEPTH`` sub-sitemaps to prevent
        runaway requests.

        Args:
            client: Shared HTTP client.
            root:   Parsed root element of the sitemap index.

        Returns:
            Aggregated list of all URL strings from all sub-sitemaps.
        """
        sub_sitemap_urls: list[str] = []

        for sitemap_el in root.iter(f"{{{_SITEMAP_NS}}}sitemap"):
            loc_el = sitemap_el.find(f"{{{_SITEMAP_NS}}}loc")
            if loc_el is not None and loc_el.text:
                sub_sitemap_urls.append(loc_el.text.strip())

        # Fallback: try without namespace.
        if not sub_sitemap_urls:
            for sitemap_el in root.iter("sitemap"):
                loc_el = sitemap_el.find("loc")
                if loc_el is not None and loc_el.text:
                    sub_sitemap_urls.append(loc_el.text.strip())

        self.log(
            f"Sitemap index detected — "
            f"following {min(len(sub_sitemap_urls), _MAX_SITEMAP_INDEX_DEPTH)} "
            f"of {len(sub_sitemap_urls)} sub-sitemap(s)."
        )

        all_urls: list[str] = []

        for sub_url in sub_sitemap_urls[:_MAX_SITEMAP_INDEX_DEPTH]:
            content = await self._fetch_xml(client, sub_url)
            if content is None:
                continue
            try:
                sub_root = ET.fromstring(content)
                all_urls.extend(self._extract_urls(sub_root))
            except ET.ParseError as exc:
                self.log(
                    f"Failed to parse sub-sitemap '{sub_url}': {exc}",
                    logging.WARNING,
                )

        return all_urls
