"""
Tests for CommandInjectionPlugin.
"""

import asyncio
from unittest.mock import AsyncMock
import pytest
import httpx

from app.core.enums import Severity
from app.scanner.context import ScanContext
from app.scanner.plugins.passive.command_injection import (
    CommandInjectionPlugin,
    _CMD_ECHO_TOKEN,
)


@pytest.fixture
def plugin() -> CommandInjectionPlugin:
    return CommandInjectionPlugin()


def test_command_injection_echo_execution_high(plugin: CommandInjectionPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/tools/ping?host=127.0.0.1",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Target server executes subshell/echo and returns the token without raw payload syntax
            if _CMD_ECHO_TOKEN in url or "%24%28" in url or "echo" in url:
                output_text = f"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n{_CMD_ECHO_TOKEN}\n"
                return httpx.Response(status_code=200, text=output_text)
            return httpx.Response(status_code=200, text="Ping Utility Ready")

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "OS Command Injection" in finding.title
        assert finding.severity == Severity.HIGH
        assert "host" in finding.title

    asyncio.run(_run())


def test_shell_syntax_error_medium(plugin: CommandInjectionPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/exec?cmd=status",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Server shell raises syntax error
            error_text = "sh: line 1: syntax error near unexpected token `;'"
            return httpx.Response(status_code=500, text=error_text)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        finding = context.findings[0]
        assert "Command Interpreter Error" in finding.title
        assert finding.severity == Severity.MEDIUM

    asyncio.run(_run())


def test_windows_cmd_error_medium(plugin: CommandInjectionPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/run?action=check",
            user_id=1,
        )

        mock_client = AsyncMock()

        async def mock_get(url):
            # Windows cmd.exe error
            error_text = "'foo' is not recognized as an internal or external command, operable program or batch file."
            return httpx.Response(status_code=500, text=error_text)

        mock_client.get = mock_get
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 1
        assert context.findings[0].severity == Severity.MEDIUM

    asyncio.run(_run())


def test_baseline_error_prevents_false_positive(plugin: CommandInjectionPlugin):
    async def _run():
        # Baseline response already contains the error message
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/docs?query=sh",
            user_id=1,
        )
        context.html = "Documentation about /bin/sh: syntax error handling in scripts"

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(
            status_code=200,
            text="Documentation about /bin/sh: syntax error handling in scripts",
        )
        context.session = mock_client

        await plugin.run(context)

        # Pre-existing error on page should not generate a finding
        assert len(context.findings) == 0

    asyncio.run(_run())


def test_clean_response_no_findings(plugin: CommandInjectionPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/view?file=report.pdf",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = httpx.Response(status_code=200, text="Report Viewer")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())


def test_network_error_handled_gracefully(plugin: CommandInjectionPlugin):
    async def _run():
        context = ScanContext(
            scan_id=1,
            target_url="https://example.com/ping?ip=1",
            user_id=1,
        )

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")
        context.session = mock_client

        await plugin.run(context)

        assert len(context.findings) == 0

    asyncio.run(_run())
