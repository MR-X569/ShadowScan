"""
app/scanner/base.py
-------------------
BasePlugin — the abstract contract that every scanner plugin must satisfy.

All plugins in ``app/scanner/plugins/passive/``, ``/active/``, and ``/ai/``
inherit from this class. The ``PluginManager`` discovers subclasses at runtime
using ``__subclasses__()`` traversal after import.

Design decisions:
- ABC enforces the contract at class definition time, not at call time.
- Class-level attributes (name, description, category, version) are declared
  as class variables to ensure they are defined per plugin class, not per
  instance. ``@classmethod`` properties are avoided for simplicity.
- ``run()`` is ``async`` — plugins are async-first. Synchronous I/O inside a
  plugin should be offloaded with ``asyncio.to_thread()``.
- ``category`` is a free string, but must be one of the conventional values
  ("passive", "active", "ai") to ensure correct sub-package placement.
- ``__init_subclass__`` validates required attributes on the subclass at
  class-definition time, giving developers immediate feedback if they forget
  a required attribute.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from app.scanner.context import ScanContext

logger = logging.getLogger(__name__)

# Conventional category values — plugins should use these.
CATEGORY_PASSIVE = "passive"
CATEGORY_ACTIVE = "active"
CATEGORY_AI = "ai"

# Required class-level string attributes every plugin must declare.
_REQUIRED_ATTRS: tuple[str, ...] = (
    "name",
    "description",
    "category",
    "version",
    "priority",
)


class BasePlugin(ABC):
    """
    Abstract base class for all ShadowScan scanner plugins.

    Subclass this and implement ``run()`` to create a new plugin.

    Class Attributes (must be defined on every subclass):
        name:        Unique machine-readable identifier.
                     Example: ``"missing_x_frame_options"``
        description: Short human-readable description of what the plugin checks.
                     Example: ``"Detects missing X-Frame-Options header"``
        category:    Plugin category — one of "passive", "active", "ai".
        version:     Semantic version string.
                     Example: ``"1.0.0"``

    Example usage::

        class MissingXFrameOptions(BasePlugin):
            name        = "missing_x_frame_options"
            description = "Detects missing X-Frame-Options header"
            category    = "passive"
            version     = "1.0.0"

            async def run(self, context: ScanContext) -> None:
                if "x-frame-options" not in context.headers:
                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title="Missing X-Frame-Options Header",
                            description="...",
                            severity=Severity.MEDIUM,
                            recommendation="Add X-Frame-Options: DENY",
                        )
                    )
    """

    # ------------------------------------------------------------------
    # Required class-level attributes — subclasses MUST override these.
    # ------------------------------------------------------------------
    name: str
    description: str
    category: str
    version: str
    priority: int = 100
    enabled: bool = True

    # ------------------------------------------------------------------
    # Subclass validation
    # ------------------------------------------------------------------

    def __init_subclass__(cls, **kwargs: object) -> None:
        """
        Called automatically when a class inherits from BasePlugin.

        Validates that all required class-level attributes are declared.
        Raises ``TypeError`` immediately at class definition if any are missing,
        giving developers early, clear feedback.
        """
        super().__init_subclass__(**kwargs)

        # Skip validation for abstract intermediate classes that don't
        # define the attributes themselves (they let subclasses do it).
        if not getattr(cls, "__abstractmethods__", None):
            for attr in _REQUIRED_ATTRS:
                if not hasattr(cls, attr) or isinstance(
                    getattr(cls, attr), property
                ):
                    raise TypeError(
                        f"Plugin class '{cls.__name__}' must define "
                        f"class attribute '{attr}'."
                    )

    # ------------------------------------------------------------------
    # Abstract interface — every plugin must implement this.
    # ------------------------------------------------------------------

    @abstractmethod
    async def run(self, context: ScanContext) -> None:
        """
        Execute the plugin against the target described by ``context``.

        This method must:
        - Read target data from ``context`` (URL, headers, HTML, etc.).
        - Call ``context.add_finding(finding)`` for each discovered issue.
        - NOT raise unhandled exceptions — catch and log internally.
        - NOT access the database directly.
        - NOT modify ``context.target_url``, ``context.scan_id``,
          or ``context.user_id``.

        Args:
            context: The shared ``ScanContext`` for this scan run.
                     All findings must be written back to this object.
        """
        ...  # pragma: no cover

    # ------------------------------------------------------------------
    # Helpers available to all plugins
    # ------------------------------------------------------------------

    def log(self, message: str, level: int = logging.DEBUG) -> None:
        """
        Emit a structured log message prefixed with the plugin name.

        Args:
            message: Log message text.
            level:   Python ``logging`` level (default: DEBUG).
        """
        logger.log(level, "[%s] %s", self.name, message)

    # ------------------------------------------------------------------
    # Dunder methods
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"name={self.name!r}, "
            f"category={self.category!r}, "
            f"version={self.version!r}"
            f")"
        )

    def __str__(self) -> str:
        return f"{self.name} v{self.version} [{self.category}]"
