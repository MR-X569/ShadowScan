"""Bounded Playwright-based browser observation for a single ShadowScan scan."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import Browser, BrowserContext, Error as PlaywrightError, Page, Route, async_playwright

from app.core.enums import Severity
from app.core.ssrf import SSRFSecurityError, validate_url_for_ssrf
from app.scanner.context import ScanContext
from app.scanner.result import Finding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BrowserScanConfig:
    """Hard limits for the browser observer. Values are deliberately conservative."""

    navigation_timeout_ms: int = 10_000
    settle_timeout_ms: int = 3_000
    total_timeout_seconds: float = 20.0
    max_requests: int = 100
    max_observations: int = 100
    max_dom_characters: int = 200_000
    max_links: int = 100
    max_forms: int = 50


class BrowserScanner:
    """Observe one rendered page in a fresh browser context.

    This component never submits forms or clicks links. Its route handler is
    installed before navigation and validates every HTTP(S) request that
    Playwright exposes (documents, redirects, subresources, XHR and fetch).
    """

    def __init__(self, config: BrowserScanConfig | None = None) -> None:
        self.config = config or BrowserScanConfig()

    async def scan(self, context: ScanContext) -> None:
        """Collect browser observations and add them to ``context``.

        Cleanup is unconditional: page, BrowserContext and browser process are
        closed even if navigation, evaluation, or SSRF routing fails.
        """
        observation: dict[str, Any] = {
            "status": "started",
            "requests": [],
            "responses": [],
            "blocked_requests": [],
        }
        browser: Browser | None = None
        browser_context: BrowserContext | None = None
        page: Page | None = None

        try:
            # Validate before Chromium is launched so an unsafe initial target
            # never reaches a browser network stack.
            validate_url_for_ssrf(context.target_url)

            async with asyncio.timeout(self.config.total_timeout_seconds):
                async with async_playwright() as playwright:
                    browser = await playwright.chromium.launch(headless=True)
                    browser_context = await browser.new_context()
                    await browser_context.route("**/*", self._route_handler(observation))
                    page = await browser_context.new_page()
                    page.set_default_navigation_timeout(self.config.navigation_timeout_ms)
                    page.set_default_timeout(self.config.navigation_timeout_ms)
                    page.on("response", self._response_handler(observation))

                    await page.goto(context.target_url, wait_until="domcontentloaded")
                    try:
                        await page.wait_for_load_state(
                            "networkidle", timeout=self.config.settle_timeout_ms
                        )
                    except Exception:  # A live app may keep connections open.
                        observation["settle_timed_out"] = True

                    await self._collect_page(page, browser_context, observation)

            observation["status"] = "completed"
        except SSRFSecurityError as exc:
            observation["status"] = "blocked"
            observation["error"] = str(exc)
            observation["blocked_requests"].append(
                {"url": context.target_url, "reason": str(exc), "phase": "initial_navigation"}
            )
        except TimeoutError:
            observation["status"] = "timed_out"
            observation["error"] = "Browser scan exceeded the total execution timeout."
        except Exception as exc:  # browser failures are deliberately isolated by engine too
            logger.warning("Browser scan failed for %s: %s", context.target_url, exc)
            observation["status"] = "failed"
            observation["error"] = str(exc)
        finally:
            if page is not None:
                try:
                    await page.close()
                except PlaywrightError:
                    pass
            if browser_context is not None:
                try:
                    await browser_context.close()
                except PlaywrightError:
                    pass
            if browser is not None:
                try:
                    await browser.close()
                except PlaywrightError:
                    pass

        self._merge_observation(context, observation)

    def _route_handler(self, observation: dict[str, Any]):
        async def handle(route: Route) -> None:
            request = route.request
            url = request.url
            if len(observation["requests"]) >= self.config.max_requests:
                observation["blocked_requests"].append(
                    {"url": url, "reason": "browser request limit reached", "phase": "resource_limit"}
                )
                await route.abort("blockedbyclient")
                return

            entry = {"url": url, "method": request.method, "resource_type": request.resource_type}
            observation["requests"].append(entry)
            scheme = urlparse(url).scheme.lower()
            if scheme in {"http", "https"}:
                try:
                    # This happens before continue_(), so Chromium does not
                    # establish an interceptable HTTP(S) connection first.
                    validate_url_for_ssrf(url)
                except SSRFSecurityError as exc:
                    observation["blocked_requests"].append(
                        {"url": url, "reason": str(exc), "phase": "browser_request"}
                    )
                    await route.abort("blockedbyclient")
                    return
            await route.continue_()

        return handle

    def _response_handler(self, observation: dict[str, Any]):
        def handle(response: Any) -> None:
            if len(observation["responses"]) < self.config.max_observations:
                observation["responses"].append(
                    {
                        "url": response.url,
                        "status": response.status,
                        "content_type": response.headers.get("content-type", ""),
                    }
                )

        return handle

    async def _collect_page(
        self, page: Page, browser_context: BrowserContext, observation: dict[str, Any]
    ) -> None:
        dom = await page.content()
        observation["rendered_dom"] = dom[: self.config.max_dom_characters]
        observation["dom_truncated"] = len(dom) > self.config.max_dom_characters
        observation["title"] = await page.title()
        observation["final_url"] = page.url
        observation["links"] = await page.locator("a[href]").evaluate_all(
            """(nodes, limit) => nodes.slice(0, limit).map(n => ({
                href: n.href, text: (n.textContent || '').trim().slice(0, 200)
            }))""",
            self.config.max_links,
        )
        observation["forms"] = await page.locator("form").evaluate_all(
            """(nodes, limit) => nodes.slice(0, limit).map(form => ({
                action: form.action || location.href,
                method: (form.method || 'get').toUpperCase(),
                parameters: Array.from(form.querySelectorAll('input[name], textarea[name], select[name]'))
                    .map(input => input.name).filter(Boolean)
            }))""",
            self.config.max_forms,
        )
        observation["scripts"] = await page.locator("script[src]").evaluate_all(
            "(nodes, limit) => nodes.slice(0, limit).map(n => n.src)", self.config.max_links
        )
        observation["cookies"] = [
            {key: cookie[key] for key in ("name", "domain", "path", "secure", "httpOnly", "sameSite")}
            for cookie in await browser_context.cookies()
        ]
        observation["storage"] = await page.evaluate(
            """() => ({
                local_storage_keys: Object.keys(localStorage).slice(0, 100),
                session_storage_keys: Object.keys(sessionStorage).slice(0, 100)
            })"""
        )

    @staticmethod
    def _merge_observation(context: ScanContext, observation: dict[str, Any]) -> None:
        context.metadata["browser"] = observation
        if observation.get("rendered_dom"):
            # Existing passive plugins can now inspect JavaScript-rendered
            # content without changing their contracts.
            context.metadata["http_html"] = context.html
            context.html = observation["rendered_dom"]

        browser_urls = {item["href"] for item in observation.get("links", []) if item.get("href")}
        browser_urls.update(item["url"] for item in observation.get("requests", []) if item.get("url"))
        current_urls = set(context.metadata.get("discovered_urls", []))
        context.metadata["browser_discovered_urls"] = sorted(browser_urls)
        context.metadata["discovered_urls"] = sorted(current_urls | browser_urls)

        browser_forms = observation.get("forms", [])
        context.metadata["browser_forms"] = browser_forms
        existing_forms = list(context.metadata.get("discovered_forms", []))
        context.metadata["discovered_forms"] = existing_forms + browser_forms

        if observation.get("blocked_requests"):
            evidence = "; ".join(item["url"] for item in observation["blocked_requests"][:5])
            context.add_finding(
                Finding(
                    plugin="browser_scanner",
                    title="Browser request blocked by SSRF protection",
                    description=(
                        "The rendered application attempted to request a private or otherwise "
                        "prohibited network destination. ShadowScan blocked the request before "
                        "the browser continued it."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation="Review client-side URLs and do not reference private network resources.",
                    evidence=evidence,
                )
            )
