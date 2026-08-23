"""
app/scanner/manager.py
----------------------
PluginManager — auto-discovers, registers, and vends plugin instances.

Responsibility boundary:
- This class knows WHERE plugins live and HOW to load them.
- It does NOT know what plugins do (that is BasePlugin's contract).
- ScannerEngine does NOT import specific plugin classes — it asks
  PluginManager for instances and runs them blindly.

Discovery strategy:
  ``load_plugins()`` walks each plugin sub-package
  (passive / active / ai) using ``pkgutil.walk_packages``.
  Every module is imported via ``importlib``. Python's import machinery
  then triggers ``BasePlugin.__init_subclass__`` on every plugin class
  that is defined in those modules, registering them in the class hierarchy.
  ``_discover_subclasses()`` then walks ``BasePlugin.__subclasses__()``
  recursively to collect every concrete (non-abstract) plugin class.

Adding a new plugin:
  1. Create a file in the appropriate sub-package (passive / active / ai).
  2. Define a class that inherits from ``BasePlugin`` and implements ``run()``.
  3. That's it. No changes to manager.py or engine.py required.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from types import ModuleType
from typing import TYPE_CHECKING

from app.scanner.base import BasePlugin

if TYPE_CHECKING:
    pass  # Future: typed plugin configuration objects

logger = logging.getLogger(__name__)

# Sub-packages to walk during plugin discovery.
# Add new top-level categories here when needed.
_PLUGIN_PACKAGES: tuple[str, ...] = (
    "app.scanner.plugins.passive",
    "app.scanner.plugins.active",
    "app.scanner.plugins.ai",
)


class PluginManager:
    """
    Discovers, loads, registers, and vends scanner plugin instances.

    Usage::

        manager = PluginManager()
        manager.load_plugins()
        plugins = manager.get_plugins()

    Attributes:
        _registry: Ordered list of concrete BasePlugin subclasses that have
                   been discovered and registered. Classes, not instances.
    """

    def __init__(self) -> None:
        self._registry: list[type[BasePlugin]] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_plugins(self) -> None:
        """
        Discover and register all plugins from the plugin sub-packages.

        Walks each package in ``_PLUGIN_PACKAGES``, imports every module,
        then collects all concrete ``BasePlugin`` subclasses into the registry.

        This method is idempotent — calling it multiple times will not
        produce duplicate registrations.
        """
        logger.info("PluginManager: starting plugin discovery...")

        for package_name in _PLUGIN_PACKAGES:
            self._import_package(package_name)

        self._registry = self._discover_subclasses(BasePlugin)

        # Sort by ascending priority so lower-numbered plugins run first.
        self._registry.sort(key=lambda cls: cls.priority)

        logger.info(
            "PluginManager: discovery complete — %d plugin(s) registered: %s",
            len(self._registry),
            [cls.name for cls in self._registry],
        )

    def register(self, plugin_cls: type[BasePlugin]) -> None:
        """
        Manually register a plugin class.

        Use this for programmatic registration in tests or when a plugin
        cannot be auto-discovered (e.g. dynamically generated plugin classes).

        Args:
            plugin_cls: A concrete subclass of ``BasePlugin``.

        Raises:
            TypeError:  If ``plugin_cls`` is not a subclass of ``BasePlugin``.
            ValueError: If ``plugin_cls`` is already registered.
        """
        if not (isinstance(plugin_cls, type) and issubclass(plugin_cls, BasePlugin)):
            raise TypeError(
                f"Expected a BasePlugin subclass, got: {plugin_cls!r}"
            )

        if plugin_cls in self._registry:
            raise ValueError(
                f"Plugin '{plugin_cls.name}' is already registered."
            )

        self._registry.append(plugin_cls)
        logger.debug("PluginManager: manually registered '%s'.", plugin_cls.name)

    def get_plugins(self) -> list[BasePlugin]:
        """
        Instantiate and return one instance of each registered plugin.

        Returns a new list of fresh instances on every call. Plugins are
        stateless (state lives in ScanContext), so per-call instantiation
        is safe and cheap.

        Returns:
            Ordered list of ``BasePlugin`` instances ready for execution.
        """
        return [cls() for cls in self._registry]

    def get_plugin_names(self) -> list[str]:
        """Return the ``name`` attribute of every registered plugin class."""
        return [cls.name for cls in self._registry]

    def plugin_count(self) -> int:
        """Return the total number of registered plugins."""
        return len(self._registry)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _import_package(package_name: str) -> None:
        """
        Import all modules within a given package, recursively.

        Importing a module is enough to trigger class-body execution,
        which registers the class in Python's type hierarchy so that
        ``__subclasses__()`` can find it.

        Args:
            package_name: Dotted Python package path
                          (e.g. ``"app.scanner.plugins.passive"``).
        """
        try:
            package: ModuleType = importlib.import_module(package_name)
        except ModuleNotFoundError:
            logger.warning(
                "PluginManager: package '%s' not found — skipping.",
                package_name,
            )
            return

        package_path: list[str] = getattr(package, "__path__", [])

        for _finder, module_name, _is_pkg in pkgutil.walk_packages(
            path=package_path,
            prefix=package_name + ".",
            onerror=lambda name: logger.error(
                "PluginManager: error importing '%s'.", name
            ),
        ):
            try:
                importlib.import_module(module_name)
                logger.debug("PluginManager: imported module '%s'.", module_name)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "PluginManager: failed to import '%s': %s",
                    module_name,
                    exc,
                )

    @staticmethod
    def _discover_subclasses(
        base: type[BasePlugin],
    ) -> list[type[BasePlugin]]:
        """
        Recursively collect all concrete (non-abstract) subclasses of ``base``.

        Args:
            base: The root abstract class to walk.

        Returns:
            Flat, deduplicated list of concrete subclasses, ordered by
            discovery (depth-first).
        """
        result: list[type[BasePlugin]] = []
        seen: set[type[BasePlugin]] = set()

        def _walk(cls: type[BasePlugin]) -> None:
            for subclass in cls.__subclasses__():
                if subclass in seen:
                    continue
                seen.add(subclass)
                # Only register concrete classes (no unresolved abstractmethods)
                if not getattr(subclass, "__abstractmethods__", None):
                    result.append(subclass)
                # Always recurse — intermediate abstract classes may have
                # concrete grandchildren.
                _walk(subclass)

        _walk(base)
        return result

    def __repr__(self) -> str:
        return (
            f"PluginManager("
            f"registered={self.plugin_count()}, "
            f"plugins={self.get_plugin_names()!r}"
            f")"
        )
