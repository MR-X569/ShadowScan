"""
app/scanner/__init__.py
-----------------------
Public API surface for the ShadowScan scanner framework.

Import from here instead of from internal sub-modules::

    from app.scanner import ScannerEngine, PluginManager, BasePlugin
    from app.scanner import ScanContext, Finding, create_engine

This keeps consumers decoupled from the internal file layout, allowing
internal refactoring without breaking imports.
"""

from app.scanner.base import BasePlugin
from app.scanner.context import ScanContext
from app.scanner.engine import ScannerEngine, create_engine
from app.scanner.manager import PluginManager
from app.scanner.result import Finding

__all__ = [
    "BasePlugin",
    "ScanContext",
    "Finding",
    "PluginManager",
    "ScannerEngine",
    "create_engine",
]
