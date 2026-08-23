"""
app/scanner/context.py
----------------------
ScanContext — the single shared-state object for an entire scan run.

The engine creates one ScanContext per scan and passes it to every plugin
in sequence. Plugins READ target metadata from it and WRITE findings back
through ``add_finding()``. Plugins must NEVER access the database directly.

Design decisions:
- `@dataclass` — explicit fields with type hints; easy to inspect and test.
- Mutable — plugins append findings and may write to `metadata`.
- `session` / `response` typed as `Any` intentionally: the HTTP layer
  (httpx.AsyncClient) will be added when the crawling module is built.
  Tighten the type annotation at that point.
- `metadata` is a free-form `dict[str, Any]` that allows passive plugins
  to expose discovered artefacts (form endpoints, JS URLs, etc.) for
  downstream active plugins to consume. No typed contract is imposed at
  this layer — plugin authors document their keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.scanner.result import Finding


@dataclass
class ScanContext:
    """
    Shared state container for a single scan execution.

    Created by ``ScannerEngine`` before plugins run. One instance per scan.

    Attributes:
        scan_id:    Primary key of the ``Scan`` DB record this run belongs to.
        target_url: Normalised target URL (scheme + host + path).
        user_id:    ID of the owning user — for audit logging inside plugins.

        session:    HTTP client session injected by the engine.
                    ``None`` until the engine opens the session.
                    Type: ``httpx.AsyncClient`` (to be tightened when HTTP
                    layer is implemented).

        response:   Raw HTTP response from the initial page fetch.
                    ``None`` until the engine performs the first request.

        headers:    HTTP response headers as a plain ``str → str`` dict.
        html:       Raw HTML body of the first response. ``None`` if the
                    response was not HTML or fetch has not happened yet.
        cookies:    Response cookies as a plain ``str → str`` dict.

        findings:   Accumulated list of ``Finding`` objects produced by
                    plugins. Append via ``add_finding()`` only.
        metadata:   Free-form plugin communication channel.
                    Passive plugins write discovered artefacts here;
                    active plugins read them.
    """

    # --- Required fields (must be supplied at construction) ---------------
    scan_id: int
    target_url: str
    user_id: int

    # --- HTTP state (populated by engine before plugins run) --------------
    session: Any = field(default=None, repr=False)
    response: Any = field(default=None, repr=False)
    headers: dict[str, str] = field(default_factory=dict)
    html: str | None = field(default=None, repr=False)
    cookies: dict[str, str] = field(default_factory=dict)

    # --- Plugin output ----------------------------------------------------
    findings: list[Finding] = field(default_factory=list, repr=False)

    # --- Inter-plugin communication channel ------------------------------
    metadata: dict[str, Any] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """
        Append a finding to this context's findings list.

        Prefer this method over direct list access to allow future hooks
        (e.g. deduplication, real-time streaming) to be added here without
        touching plugin code.

        Args:
            finding: A fully-constructed ``Finding`` instance.
        """
        self.findings.append(finding)

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Safely retrieve a value from the inter-plugin metadata store.

        Args:
            key:     Metadata key written by a previous plugin.
            default: Value to return if the key is absent.
        """
        return self.metadata.get(key, default)

    def set_metadata(self, key: str, value: Any) -> None:
        """
        Write a value to the inter-plugin metadata store.

        Args:
            key:   Unique string key identifying the data.
            value: Arbitrary value (list, dict, str, etc.).
        """
        self.metadata[key] = value

    def __str__(self) -> str:
        return (
            f"ScanContext("
            f"scan_id={self.scan_id}, "
            f"target_url={self.target_url!r}, "
            f"findings={len(self.findings)}"
            f")"
        )
