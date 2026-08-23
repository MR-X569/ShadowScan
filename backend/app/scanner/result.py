"""
app/scanner/result.py
---------------------
In-memory representation of a single vulnerability finding produced by a plugin.

This is a **pure data object** — it has zero database dependency.
When the scan engine finishes, a persistence layer (not part of this module)
is responsible for mapping these objects to the DB `Finding` model.

Design decisions:
- `@dataclass` — lightweight, auto-generates __init__ / __repr__ / __eq__.
- `frozen=False` — findings are mutable so the engine can enrich them if needed.
- `Severity` is reused from `app.core.enums` to stay consistent with the DB model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.enums import Severity


@dataclass
class Finding:
    """
    Represents a single vulnerability finding raised by a scanner plugin.

    Attributes:
        plugin:         Canonical name of the plugin that raised this finding.
                        Must match ``BasePlugin.name`` of the producing plugin.
        title:          Short, human-readable vulnerability title.
                        Example: "Missing X-Frame-Options Header"
        description:    Detailed explanation of the vulnerability, its context,
                        and why it is a security risk.
        severity:       Risk level — one of LOW / MEDIUM / HIGH / CRITICAL.
        recommendation: Actionable remediation advice for the developer.
        evidence:       Optional raw evidence snippet that proves the finding
                        (e.g. a response header value, URL, or HTML fragment).
    """

    plugin: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    evidence: str | None = field(default=None)

    def __post_init__(self) -> None:
        """Validate that mandatory string fields are not blank."""
        for attr in ("plugin", "title", "description", "recommendation"):
            value = getattr(self, attr)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Finding.{attr} must be a non-empty string, got: {value!r}"
                )

    def to_dict(self) -> dict[str, str | None]:
        """
        Serialise the finding to a plain dictionary.

        Useful for logging, JSON responses, and mapping to the DB model.
        """
        return {
            "plugin": self.plugin,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }
