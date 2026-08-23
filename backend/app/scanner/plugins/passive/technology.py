"""
app/scanner/plugins/passive/technology.py
------------------------------------------
Technology Detection Plugin — passively fingerprints web technologies from
HTTP headers and HTML without sending additional requests.

Detection sources:
    Headers:    Server, X-Powered-By, Set-Cookie (session cookie names)
    HTML meta:  <meta name="generator"> tags
    HTML body:  Script src paths, link href paths, body text patterns

Technologies detected:

    Web Servers:      Apache, Nginx, Microsoft IIS, LiteSpeed, Cloudflare
    Languages:        PHP, ASP.NET, Node.js (Express)
    Frameworks:       Django, Laravel, Ruby on Rails, Spring
    CMS:              WordPress, Joomla, Drupal, Ghost, Wix, Squarespace
    Frontend:         React, Angular, Vue.js, Next.js, jQuery, Bootstrap
    Java:             (via JSESSIONID cookie)

Output:
    - Stores ``list[str]`` of detected technology names in
      ``context.metadata["detected_technologies"]``.
    - Emits exactly ONE ``Finding`` summarising all detections
      (or zero findings if nothing is detected).
    - Finding severity is ``LOW`` — technology disclosure is a risk
      factor, not a direct vulnerability.
"""

from __future__ import annotations

import logging
import re

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# Header-based signatures: (header_name_lower, regex_pattern, tech_label)
_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    # Web servers
    ("server", r"apache", "Apache"),
    ("server", r"nginx", "Nginx"),
    ("server", r"microsoft-iis|iis", "Microsoft IIS"),
    ("server", r"litespeed", "LiteSpeed"),
    ("server", r"cloudflare", "Cloudflare"),
    ("server", r"openresty", "OpenResty"),
    # Languages / runtimes
    ("x-powered-by", r"php", "PHP"),
    ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-powered-by", r"express", "Express (Node.js)"),
    ("x-powered-by", r"next\.js", "Next.js"),
    # Frameworks via response headers
    ("x-generator", r"drupal", "Drupal"),
    ("x-drupal-cache", r".*", "Drupal"),
]

# Cookie-name-based signatures: (cookie_name_pattern, tech_label)
_COOKIE_SIGNATURES: list[tuple[str, str]] = [
    (r"PHPSESSID", "PHP"),
    (r"JSESSIONID", "Java / J2EE"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"laravel_session", "Laravel"),
    (r"^csrftoken$", "Django"),
    (r"_rails_session|_session_id", "Ruby on Rails"),
]

# HTML patterns: (regex_pattern, tech_label)
# Applied to the full HTML body.
_HTML_SIGNATURES: list[tuple[str, str]] = [
    # WordPress
    (r"/wp-content/", "WordPress"),
    (r"/wp-includes/", "WordPress"),
    # Joomla
    (r"/media/jui/", "Joomla"),
    (r'generator.*?joomla', "Joomla"),
    # Drupal
    (r'Drupal\.settings', "Drupal"),
    (r'/sites/default/files/', "Drupal"),
    # React
    (r'react(?:\.min)?\.js|react-dom', "React"),
    (r'data-reactroot|__REACT_DEVTOOLS', "React"),
    # Angular
    (r'ng-app=|ng-version=|angular(?:\.min)?\.js', "Angular"),
    # Vue.js
    (r'vue(?:\.min)?\.js|__vue__', "Vue.js"),
    # Next.js
    (r'_next/static|__NEXT_DATA__', "Next.js"),
    # jQuery
    (r'jquery(?:-\d[\d.]*)?(?:\.min)?\.js', "jQuery"),
    # Bootstrap
    (r'bootstrap(?:\.min)?\.(?:css|js)', "Bootstrap"),
    # Ghost CMS
    (r'ghost-url|content="Ghost', "Ghost"),
]

# <meta name="generator"> pattern → tech label
_META_GENERATOR_SIGNATURES: list[tuple[str, str]] = [
    (r"wordpress", "WordPress"),
    (r"joomla", "Joomla"),
    (r"drupal", "Drupal"),
    (r"ghost", "Ghost"),
    (r"wix", "Wix"),
    (r"squarespace", "Squarespace"),
    (r"webflow", "Webflow"),
]


class TechnologyDetectionPlugin(BasePlugin):
    """
    Passively fingerprints web technologies from headers and HTML content.

    Emits a single consolidated ``Finding`` listing all detected technologies.
    If no technologies are identified, no finding is generated.
    """

    name = "technology_detection"
    description = (
        "Passively detects web technologies from HTTP headers and HTML content"
    )
    category = "passive"
    version = "1.0.0"
    priority = 20

    async def run(self, context: ScanContext) -> None:
        """
        Fingerprint technologies and emit one summary finding if anything
        is detected.

        Args:
            context: Shared scan context. Reads ``headers``, ``html``,
                     ``cookies``. Writes to ``metadata["detected_technologies"]``
                     and calls ``context.add_finding()`` at most once.
        """
        detected: set[str] = set()

        headers = {k.lower(): v for k, v in context.headers.items()}

        self._scan_headers(headers, detected)
        self._scan_cookies(context.cookies, detected)

        if context.html:
            self._scan_html(context.html, detected)
            self._scan_meta_generator(context.html, detected)

        # Store normalised sorted list in metadata for downstream plugins.
        tech_list = sorted(detected)
        context.set_metadata("detected_technologies", tech_list)

        self.log(f"Detected {len(tech_list)} technology/technologies: {tech_list}")

        if not tech_list:
            return

        # Emit exactly one consolidated finding.
        context.add_finding(
            Finding(
                plugin=self.name,
                title="Technology Stack Identified",
                description=(
                    "Passive analysis of HTTP headers and page content "
                    "identified the following technologies running on the "
                    "target server. Technology disclosure can assist attackers "
                    "in targeting known vulnerabilities specific to these "
                    "frameworks, libraries, or server software."
                ),
                severity=Severity.LOW,
                recommendation=(
                    "Where possible, suppress or obscure technology-revealing "
                    "headers (Server, X-Powered-By). Keep all detected "
                    "software up to date and monitor their security advisories."
                ),
                evidence=f"Detected: {', '.join(tech_list)}",
            )
        )

    # ------------------------------------------------------------------
    # Private scanning methods
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_headers(
        headers: dict[str, str],
        detected: set[str],
    ) -> None:
        """Scan response headers against known technology signatures."""
        for header_name, pattern, label in _HEADER_SIGNATURES:
            value = headers.get(header_name, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                detected.add(label)

    @staticmethod
    def _scan_cookies(
        cookies: dict[str, str],
        detected: set[str],
    ) -> None:
        """Scan cookie names against known technology signatures."""
        for cookie_name in cookies:
            for pattern, label in _COOKIE_SIGNATURES:
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    detected.add(label)
                    break

    @staticmethod
    def _scan_html(
        html: str,
        detected: set[str],
    ) -> None:
        """Scan the raw HTML body against technology fingerprint patterns."""
        for pattern, label in _HTML_SIGNATURES:
            if re.search(pattern, html, re.IGNORECASE):
                detected.add(label)

    @staticmethod
    def _scan_meta_generator(
        html: str,
        detected: set[str],
    ) -> None:
        """
        Extract and inspect the content of <meta name="generator"> tags.

        Uses a lightweight regex rather than a full HTML parser to avoid
        a dependency on BeautifulSoup for this single tag type.
        """
        # Match: <meta name="generator" content="..."> (attribute order varies)
        pattern = re.compile(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']'
            r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
            re.IGNORECASE,
        )
        for match in pattern.finditer(html):
            content = match.group(1) or match.group(2) or ""
            for sig_pattern, label in _META_GENERATOR_SIGNATURES:
                if re.search(sig_pattern, content, re.IGNORECASE):
                    detected.add(label)
