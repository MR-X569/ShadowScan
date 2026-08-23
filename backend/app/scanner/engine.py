"""
app/scanner/engine.py
---------------------
ScannerEngine — the top-level orchestrator for a full scan lifecycle.

Responsibility boundary:
- Constructs ``ScanContext`` with scan metadata.
- Delegates HTTP setup to TODO stubs (crawling layer, not built yet).
- Iterates plugins returned by ``PluginManager.get_plugins()``.
- Executes each plugin with fault isolation (one failure ≠ abort).
- Returns the collected ``list[Finding]`` to the caller.

What the engine does NOT do:
- Write to the database (caller's responsibility).
- Implement detection logic (plugins' responsibility).
- Make routing or HTTP decisions (future crawling layer's responsibility).

Integration point:
  When the ScanService is updated to trigger real scans, it will call::

      engine = create_engine()
      findings = await engine.run(
          scan_id=scan.id,
          target_url=scan.target_url,
          user_id=scan.user_id,
      )
      # then persist findings via CRUD layer
"""

from __future__ import annotations

import logging

from app.scanner.context import ScanContext
from app.scanner.http_client import create_http_client
from app.scanner.manager import PluginManager
from app.scanner.result import Finding

logger = logging.getLogger(__name__)


class ScannerEngine:
    """
    Orchestrates the full scan lifecycle for a single target URL.

    The engine is intentionally thin — it delegates discovery to
    ``PluginManager`` and detection to individual plugins.

    Args:
        plugin_manager: A fully-loaded ``PluginManager`` instance.
                        Inject via ``create_engine()`` factory or in tests
                        by passing a manager with only the plugins under test.

    Example::

        engine = create_engine()
        findings = await engine.run(
            scan_id=42,
            target_url="https://example.com",
            user_id=1,
        )
    """

    def __init__(self, plugin_manager: PluginManager) -> None:
        self._plugin_manager = plugin_manager

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def run(
        self,
        scan_id: int,
        target_url: str,
        user_id: int,
    ) -> list[Finding]:
        """
        Execute a full scan against ``target_url`` and return all findings.

        Lifecycle:
            1. Create ``ScanContext``.
            2. TODO: Open HTTP session and perform initial page fetch.
            3. Load plugins from ``PluginManager``.
            4. Execute each plugin sequentially, with per-plugin fault isolation.
            5. TODO: Close HTTP session.
            6. Return ``context.findings``.

        Args:
            scan_id:    DB primary key of the ``Scan`` record for this run.
            target_url: Fully-qualified target URL.
            user_id:    ID of the user who owns this scan (for audit logging).

        Returns:
            List of ``Finding`` objects collected from all plugins.
            Empty list if no issues were found or all plugins were skipped.
        """
        logger.info(
            "ScannerEngine: starting scan — scan_id=%d, target=%s",
            scan_id,
            target_url,
        )

        # ------------------------------------------------------------------
        # 1. Create the shared context for this scan run.
        # ------------------------------------------------------------------
        context = ScanContext(
            scan_id=scan_id,
            target_url=target_url,
            user_id=user_id,
        )

        # ------------------------------------------------------------------
        # 2. Open HTTP session and perform the initial page fetch.
        # ------------------------------------------------------------------
        async with create_http_client() as client:
            context.session = client

            try:
                response = await client.get(target_url)
                context.response = response
                context.headers = dict(response.headers)
                context.html = response.text
                context.cookies = dict(response.cookies)
                logger.info(
                    "ScannerEngine: initial fetch complete — HTTP %d for '%s'.",
                    response.status_code,
                    target_url,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "ScannerEngine: initial fetch failed for '%s': %s — "
                    "plugins will run with partial HTTP context.",
                    target_url,
                    exc,
                )

            # ------------------------------------------------------------------
            # 3. Load plugin instances.
            # ------------------------------------------------------------------
            plugins = self._plugin_manager.get_plugins()

            if not plugins:
                logger.warning(
                    "ScannerEngine: no plugins registered — scan_id=%d "
                    "will produce zero findings.",
                    scan_id,
                )

            logger.info(
                "ScannerEngine: executing %d plugin(s) for scan_id=%d.",
                len(plugins),
                scan_id,
            )

            # ------------------------------------------------------------------
            # 4. Execute plugins sequentially with per-plugin fault isolation.
            #    Disabled plugins (enabled=False) are skipped silently.
            # ------------------------------------------------------------------
            plugins = [
                plugin
                for plugin in plugins
                if plugin.enabled
            ]

            for plugin in plugins:
                await self._run_plugin(plugin, context)

        # HTTP session closed automatically by the async context manager.

        # ------------------------------------------------------------------
        # 5. Return all findings collected during this run.
        # ------------------------------------------------------------------
        logger.info(
            "ScannerEngine: scan_id=%d complete — %d finding(s) collected.",
            scan_id,
            len(context.findings),
        )

        return context.findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_plugin(
        plugin: object,
        context: ScanContext,
    ) -> None:
        """
        Execute a single plugin against the shared context.

        Exceptions raised inside a plugin are caught, logged, and silenced
        so that one misbehaving plugin does not abort the entire scan.

        Args:
            plugin:  A ``BasePlugin`` instance returned by ``PluginManager``.
            context: The shared ``ScanContext`` for this scan run.
        """
        plugin_name: str = getattr(plugin, "name", repr(plugin))

        logger.debug(
            "ScannerEngine: running plugin '%s'.",
            plugin_name,
        )

        try:
            await plugin.run(context)  # type: ignore[union-attr]
            logger.debug(
                "ScannerEngine: plugin '%s' completed — "
                "%d finding(s) so far.",
                plugin_name,
                len(context.findings),
            )
        except Exception as exc:  # noqa: BLE001
            # Fault isolation: log the error and continue with the next plugin.
            logger.exception(
                "ScannerEngine: plugin '%s' raised an unexpected exception "
                "and was skipped. Error: %s",
                plugin_name,
                exc,
            )

    def __repr__(self) -> str:
        return (
            f"ScannerEngine("
            f"plugins={self._plugin_manager.plugin_count()}"
            f")"
        )


# ---------------------------------------------------------------------------
# Factory function — use this everywhere instead of constructing manually.
# ---------------------------------------------------------------------------


def create_engine() -> ScannerEngine:
    """
    Build and return a fully-initialised ``ScannerEngine``.

    Creates a ``PluginManager``, triggers plugin discovery, and injects the
    manager into a new ``ScannerEngine`` instance.

    This factory is the recommended entry point for production code::

        engine = create_engine()
        findings = await engine.run(scan_id, target_url, user_id)

    For testing, construct ``PluginManager`` and ``ScannerEngine`` manually
    so you can inject only the plugins under test.

    Returns:
        A ready-to-use ``ScannerEngine`` instance.
    """
    manager = PluginManager()
    manager.load_plugins()
    return ScannerEngine(plugin_manager=manager)
