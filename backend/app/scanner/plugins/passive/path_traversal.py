"""
app/scanner/plugins/passive/path_traversal.py
---------------------------------------------
Path Traversal Analysis Plugin — safely identifies local file inclusion (LFI)
and arbitrary file read vulnerabilities in URL parameters.

Checks performed:
    - Candidate parameter identification (file, path, template, include, download, etc.)
    - Harmless, read-only traversal probes (Linux /etc/passwd, Windows win.ini)
    - Strong content signature validation:
        * Linux passwd signature (root:x:0:0:) -> HIGH
        * Windows win.ini signature ([fonts], for 16-bit app support) -> HIGH
    - Strict Single Page Application (SPA) 200 OK fallback suppression

Severity Logic:
    - Confirmed local system file contents disclosed -> HIGH
    - Traversal error / file system access restriction messages -> MEDIUM
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.core.enums import Severity
from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)

# Candidate parameter names for file inclusion / path traversal
_TRAVERSAL_PARAM_CANDIDATES: frozenset[str] = frozenset(
    {
        "file",
        "filename",
        "filepath",
        "path",
        "page",
        "template",
        "document",
        "doc",
        "include",
        "resource",
        "download",
        "download_file",
        "image",
        "img",
        "attachment",
        "view",
        "read",
        "folder",
        "root",
        "dir",
    }
)


@dataclass
class _TraversalProbe:
    os_type: str
    payload: str
    signature: re.Pattern[str]
    description: str


_PROBES: list[_TraversalProbe] = [
    _TraversalProbe(
        os_type="Linux",
        payload="../../../../etc/passwd",
        signature=re.compile(r"root:[^:]*:[0-9]+:[0-9]+:[^:]*:[^:]*:", re.MULTILINE),
        description="/etc/passwd user database file",
    ),
    _TraversalProbe(
        os_type="Linux (Absolute)",
        payload="/etc/passwd",
        signature=re.compile(r"root:[^:]*:[0-9]+:[0-9]+:[^:]*:[^:]*:", re.MULTILINE),
        description="/etc/passwd user database file",
    ),
    _TraversalProbe(
        os_type="Windows",
        payload="../../../../windows/win.ini",
        signature=re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE),
        description="C:\\Windows\\win.ini configuration file",
    ),
    _TraversalProbe(
        os_type="Windows (Backslash)",
        payload="..\\..\\..\\..\\windows\\win.ini",
        signature=re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE),
        description="C:\\Windows\\win.ini configuration file",
    ),
]

_SPA_HTML_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)

_TRAVERSAL_ERROR_REGEX: re.Pattern[str] = re.compile(
    r"(?:open_basedir restriction in effect|java\.io\.FileNotFoundException|failed to open stream: Permission denied"
    r"|System\.IO\.DirectoryNotFoundException|System\.IO\.FileNotFoundException)",
    re.IGNORECASE,
)


class PathTraversalPlugin(BasePlugin):
    """
    Safely tests parameters for directory traversal and arbitrary file read vulnerabilities.
    """

    name = "path_traversal"
    description = (
        "Detects local file path traversal and arbitrary file read vulnerabilities in URL parameters."
    )
    category = "passive"
    version = "1.0.0"
    priority = 80

    async def run(self, context: ScanContext) -> None:
        """
        Execute path traversal parameter checks against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping path traversal checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Identify parameters to test
        params_to_test = self._get_parameters_to_test(parsed_target)
        if not params_to_test:
            self.log("No candidate path traversal parameters detected.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for path traversal: {params_to_test}")

        baseline_text = context.html or ""
        tested_params: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested_params:
                continue
            tested_params.add(param_name)

            for probe in _PROBES:
                is_vulnerable = await self._test_single_probe(
                    client,
                    parsed_target,
                    param_name,
                    probe,
                    baseline_text,
                    context,
                )
                if is_vulnerable:
                    break  # Stop probing once a parameter is confirmed vulnerable

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any) -> list[str]:
        """Extract candidate traversal parameters from query string or defaults."""
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found = [k for k in query_dict if k.lower() in _TRAVERSAL_PARAM_CANDIDATES]

        if found:
            return found

        for k in query_dict:
            k_lower = k.lower()
            if any(cand in k_lower for cand in ("file", "path", "page", "template", "doc", "view")):
                found.append(k)

        if found:
            return found

        return ["file", "page", "template", "path", "doc", "view"]

    # ------------------------------------------------------------------
    # Probe Execution
    # ------------------------------------------------------------------

    async def _test_single_probe(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        probe: _TraversalProbe,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Inject traversal probe into parameter and check for valid file signatures."""
        query_dict = parse_qs(parsed_target.query, keep_blank_values=True)
        query_dict[param_name] = [probe.payload]

        flattened = [(k, v[0] if isinstance(v, list) and v else "") for k, v in query_dict.items()]
        new_query = urlencode(flattened)

        test_url = urlunparse((
            parsed_target.scheme,
            parsed_target.netloc,
            parsed_target.path,
            parsed_target.params,
            new_query,
            parsed_target.fragment,
        ))

        try:
            response = await client.get(test_url)
            text = response.text or ""
            content_type = response.headers.get("content-type", "").lower()

            # Anti-signature check for HTML Single Page Applications
            if "text/html" in content_type and _SPA_HTML_ANTI_SIGNATURE.search(text):
                # Ensure the signature is not just part of a generic HTML template
                if not probe.signature.search(text):
                    return False

            # Check if signature matches and was not in baseline
            match = probe.signature.search(text)
            if match and not probe.signature.search(baseline_text):
                matched_snippet = text[:300].strip()
                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Injected Traversal Payload: {probe.payload}\n"
                    f"Target OS Profile: {probe.os_type}\n"
                    f"Test Request URL: {test_url}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Matched System File Signature: {probe.description}\n\n"
                    f"File Content Excerpt:\n{matched_snippet}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Path Traversal / Arbitrary File Read via Parameter: {param_name}",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to local path traversal. "
                            f"Supplying relative directory traversal sequences ({probe.payload}) resulted in the disclosure "
                            f"of {probe.description}. Attackers can exploit this vulnerability to read sensitive configuration files, "
                            f"source code, application credentials, or system password hashes."
                        ),
                        severity=Severity.HIGH,
                        recommendation=(
                            f"Validate user-supplied file names against a strict whitelist. Avoid passing unvalidated user input "
                            f"directly to filesystem APIs. Use path canonicalization (e.g. os.path.realpath / Path.resolve) "
                            f"and ensure the resolved path remains strictly within the intended base directory."
                        ),
                        evidence=evidence,
                    )
                )
                return True

            # Check for error indicators (open_basedir / FileNotFoundException)
            err_match = _TRAVERSAL_ERROR_REGEX.search(text)
            if err_match and not _TRAVERSAL_ERROR_REGEX.search(baseline_text):
                err_snippet = err_match.group(0)
                evidence = (
                    f"Tested Parameter: {param_name}\n"
                    f"Injected Traversal Payload: {probe.payload}\n"
                    f"Test Request URL: {test_url}\n"
                    f"HTTP Status: {response.status_code}\n"
                    f"Observed File System Error: {err_snippet}"
                )

                context.add_finding(
                    Finding(
                        plugin=self.name,
                        title=f"Potential Path Traversal Indicator via Parameter: {param_name}",
                        description=(
                            f"The parameter '{param_name}' triggered a filesystem error ({err_snippet}) when supplied with "
                            f"directory traversal sequences. Ensure all file operations are strictly sandboxed."
                        ),
                        severity=Severity.MEDIUM,
                        recommendation="Sanitize file parameters and restrict file operations using strict whitelisting.",
                        evidence=evidence,
                    )
                )
                return True

            return False

        except Exception as exc:
            self.log(f"Path traversal probe for '{param_name}' on '{test_url}' failed: {exc}")
            return False
