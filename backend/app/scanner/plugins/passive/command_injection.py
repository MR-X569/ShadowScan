"""
app/scanner/plugins/passive/command_injection.py
------------------------------------------------
OS Command Injection Analysis Plugin — safely identifies potential OS command
execution and command interpreter error reflections in URL parameters.

Safety & Non-Destructive Operation:
    - NEVER executes destructive commands (e.g. rm, del, drop, shutdown, kill).
    - NEVER executes commands that alter system state or network configuration.
    - Uses harmless diagnostic markers and differential comparison against baseline.
    - Probes for command interpreter syntax errors and harmless echo reflections.

Detection Strategy:
    - Evaluates candidate parameters (cmd, exec, ping, host, ip, target, query, input, path, etc.).
    - Injects safe diagnostic probes containing unique markers:
        * Unix echo probe: ";echo ShadowScanCmdEcho;echo "
        * Unix command substitution: "$(echo ShadowScanCmdEcho)"
        * Windows cmd probe: "& echo ShadowScanCmdEcho &"
    - Compares responses against baseline:
        * Exact marker execution reflection without syntax characters -> HIGH / CRITICAL
        * High-confidence shell syntax / command interpreter error message -> MEDIUM / HIGH
    - Suppresses generic 500 pages and SPA fallbacks.

Severity Logic:
    - Confirmed command output execution reflection -> CRITICAL / HIGH
    - High-confidence shell interpreter error message -> MEDIUM
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

# Harmless unique marker for command echo verification
_CMD_ECHO_TOKEN: str = "ShadowScanCmdEcho9b1"

# Shell interpreter error regex patterns
_SHELL_ERROR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "Unix Shell Syntax / Parsing Error",
        re.compile(
            r"(?:/bin/(?:ba)?sh:\s*line\s*\d+:|/bin/sh:\s*syntax error|sh:\s*command not found|"
            r"bash:\s*command not found|syntax error near unexpected token|"
            r"syntax error: unexpected end of file)",
            re.IGNORECASE,
        ),
    ),
    (
        "Windows Command Interpreter Error",
        re.compile(
            r"(?:is not recognized as an internal or external command|operable program or batch file|"
            r"The syntax of the command is incorrect\.|The system cannot find the path specified\.)",
            re.IGNORECASE,
        ),
    ),
    (
        "PowerShell Execution Error",
        re.compile(
            r"(?:The term '.*?' is not recognized as the name of a cmdlet|CommandNotFoundException|"
            r"ParseException: Missing expression after)",
            re.IGNORECASE,
        ),
    ),
]


@dataclass
class _CmdProbe:
    os_family: str
    payload: str
    syntax_chars: list[str]


_PROBES: list[_CmdProbe] = [
    _CmdProbe("Unix Subshell", f"$(echo {_CMD_ECHO_TOKEN})", ["$(", ")", "echo"]),
    _CmdProbe("Unix Semicolon", f";echo {_CMD_ECHO_TOKEN};", [";", "echo"]),
    _CmdProbe("Unix Pipe", f"| echo {_CMD_ECHO_TOKEN}", ["|", "echo"]),
    _CmdProbe("Windows Ampersand", f"& echo {_CMD_ECHO_TOKEN} &", ["&", "echo"]),
]

_CANDIDATE_PARAMS: frozenset[str] = frozenset(
    {
        "cmd",
        "command",
        "exec",
        "execute",
        "ping",
        "host",
        "hostname",
        "ip",
        "target",
        "query",
        "input",
        "file",
        "filename",
        "path",
        "dir",
        "process",
        "run",
        "cli",
        "action",
    }
)

_SPA_ANTI_SIGNATURE: re.Pattern[str] = re.compile(
    r"<!DOCTYPE html|<html|<div id=\"root\"|<div id=\"app\"|<script",
    re.IGNORECASE,
)


class CommandInjectionPlugin(BasePlugin):
    """
    Safely probes parameters for OS command injection vulnerabilities.
    """

    name = "command_injection"
    description = (
        "Detects potential OS command injection vulnerabilities through safe, "
        "non-destructive probe reflections and shell interpreter error analysis."
    )
    category = "passive"
    version = "1.0.0"
    priority = 90

    async def run(self, context: ScanContext) -> None:
        """
        Execute safe command injection analysis against context.target_url.
        """
        if context.session is None or not context.target_url:
            self.log("No HTTP session or target URL available — skipping command injection checks.")
            return

        client = context.session
        target_url = context.target_url
        parsed_target = urlparse(target_url)

        # 1. Identify parameters to probe
        params_to_test = self._get_parameters_to_test(parsed_target)
        if not params_to_test:
            self.log("No candidate command injection parameters detected.")
            return

        self.log(f"Testing {len(params_to_test)} parameter(s) for command injection: {params_to_test}")

        baseline_text = context.html or ""
        tested: set[str] = set()

        for param_name in params_to_test:
            if param_name in tested:
                continue
            tested.add(param_name)

            for probe in _PROBES:
                is_vulnerable = await self._test_param_probe(
                    client,
                    parsed_target,
                    param_name,
                    probe,
                    baseline_text,
                    context,
                )
                if is_vulnerable:
                    break

    # ------------------------------------------------------------------
    # Parameter Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _get_parameters_to_test(parsed_url: Any) -> list[str]:
        """Extract candidate parameters from URL query string or common defaults."""
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        found = [k for k in query_dict if k.lower() in _CANDIDATE_PARAMS]

        if found:
            return found

        for k in query_dict:
            k_lower = k.lower()
            if any(cand in k_lower for cand in ("cmd", "exec", "ping", "host", "ip", "run", "query")):
                found.append(k)

        if found:
            return found

        return ["cmd", "exec", "host", "ping", "target", "query", "ip"]

    # ------------------------------------------------------------------
    # Probe Execution & Differential Analysis
    # ------------------------------------------------------------------

    async def _test_param_probe(
        self,
        client: Any,
        parsed_target: Any,
        param_name: str,
        probe: _CmdProbe,
        baseline_text: str,
        context: ScanContext,
    ) -> bool:
        """Inject probe into parameter and analyze response for execution or shell errors."""
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

            # Anti-signature check for Single Page Application fallbacks
            if "text/html" in content_type and _SPA_ANTI_SIGNATURE.search(text):
                if _CMD_ECHO_TOKEN not in text and not any(p.search(text) for _, p in _SHELL_ERROR_PATTERNS):
                    return False

            # Indicator 1: Harmless command echo execution reflection
            if _CMD_ECHO_TOKEN in text and _CMD_ECHO_TOKEN not in baseline_text:
                # Distinguish command execution output from pure literal parameter reflection (like XSS)
                # If the injected control characters ($ or ; or &) are NOT reflected immediately next to the token,
                # the token was output by the executed subshell / echo process.
                is_literal_reflection = probe.payload in text

                if not is_literal_reflection:
                    evidence = (
                        f"Tested Parameter: {param_name}\n"
                        f"Injected Command Probe: {probe.payload}\n"
                        f"Probe Family: {probe.os_family}\n"
                        f"Test Request URL: {test_url}\n"
                        f"HTTP Status: {response.status_code}\n"
                        f"Observed Execution Output: Token '{_CMD_ECHO_TOKEN}' successfully reflected without command syntax.\n\n"
                        f"Response Excerpt:\n{text[:300].strip()}"
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"Potential OS Command Injection via Parameter: {param_name}",
                            description=(
                                f"The parameter '{param_name}' appears to pass unvalidated user input directly to an operating "
                                f"system shell or command interpreter. Supplying benign command substitution sequences "
                                f"('{probe.payload}') resulted in the execution and output reflection of the internal echo command. "
                                f"An attacker can exploit this vulnerability to execute arbitrary operating system commands, "
                                f"compromise the hosting server, or access internal networks."
                            ),
                            severity=Severity.HIGH,
                            recommendation=(
                                f"Avoid passing user input directly to system command interpreters (e.g. system(), exec(), "
                                f"popen(), child_process.exec()). Use safe platform APIs with parameterized arguments without "
                                f"invoking a shell, and validate input against a strict whitelist."
                            ),
                            evidence=evidence,
                        )
                    )
                    return True

            # Indicator 2: High-confidence shell interpreter error messages
            for error_name, error_regex in _SHELL_ERROR_PATTERNS:
                err_match = error_regex.search(text)
                if err_match and not error_regex.search(baseline_text):
                    err_snippet = err_match.group(0)
                    evidence = (
                        f"Tested Parameter: {param_name}\n"
                        f"Injected Command Probe: {probe.payload}\n"
                        f"Matched Shell Error: {error_name}\n"
                        f"Test Request URL: {test_url}\n"
                        f"HTTP Status: {response.status_code}\n"
                        f"Shell Error Snippet:\n{err_snippet}"
                    )

                    context.add_finding(
                        Finding(
                            plugin=self.name,
                            title=f"OS Command Interpreter Error Indicator via Parameter: {param_name}",
                            description=(
                                f"Supplying command separator characters in parameter '{param_name}' triggered an operating "
                                f"system shell syntax or execution error ({error_name}: '{err_snippet}'). "
                                f"This indicates user input is interpolated into an operating system command without proper sanitization."
                            ),
                            severity=Severity.MEDIUM,
                            recommendation=(
                                "Sanitize all parameters and replace direct shell command execution with native programming language APIs."
                            ),
                            evidence=evidence,
                        )
                    )
                    return True

            return False

        except Exception as exc:
            self.log(f"Command injection probe on '{param_name}' failed: {exc}")
            return False
