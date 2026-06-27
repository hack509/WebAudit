"""
Playwright Browser Pool — shared browser instance for all audit modules.

Instead of launching a new Chromium browser per module (4 cold starts),
all Playwright-using modules (e2e, javascript, mobile, screenshots) share
a single browser managed by AuditRunner.

Usage in AuditRunner:
    async with BrowserPool() as pool:
        set_pool(pool)
        await runner.run_all()
    set_pool(None)

Usage in audit modules:
    pool = get_pool()
    if pool:
        context = await pool.new_context(viewport={"width": 1920, "height": 1080})
    else:
        # fallback: own browser (standalone module run)
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(...)
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Optional

from utils.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Browser, BrowserContext, Playwright

logger = get_logger("playwright_pool")

# Module-level singleton — set by AuditRunner before running modules
_current_pool: Optional["BrowserPool"] = None


def get_pool() -> Optional["BrowserPool"]:
    """Return the active BrowserPool, or None if not initialised."""
    return _current_pool


def set_pool(pool: Optional["BrowserPool"]) -> None:
    """Register (or clear) the module-level pool."""
    global _current_pool
    _current_pool = pool


class BrowserPool:
    """Manages a single shared Playwright + Chromium instance.

    Use as an async context manager so teardown is guaranteed:

        async with BrowserPool() as pool:
            set_pool(pool)
            ...
        set_pool(None)
    """

    def __init__(self, headless: bool = True, args: Optional[list[str]] = None):
        self._headless = headless
        self._args = args or ["--no-sandbox", "--disable-dev-shm-usage"]
        self._pw: Optional["Playwright"] = None
        self._browser: Optional["Browser"] = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Launch Playwright and Chromium. Idempotent."""
        async with self._lock:
            if self._browser is not None:
                return
            try:
                from playwright.async_api import async_playwright
                self._pw = await async_playwright().start()
                self._browser = await self._pw.chromium.launch(
                    headless=self._headless,
                    args=self._args,
                )
                logger.info("Playwright BrowserPool started (shared Chromium)")
            except Exception as e:
                logger.error(f"Failed to start BrowserPool: {e}")
                raise

    async def stop(self) -> None:
        """Close the browser and stop Playwright. Idempotent."""
        async with self._lock:
            if self._browser:
                try:
                    await self._browser.close()
                except Exception:
                    pass
                self._browser = None

            if self._pw:
                try:
                    await self._pw.stop()
                except Exception:
                    pass
                self._pw = None

            logger.info("Playwright BrowserPool stopped")

    async def new_context(self, **kwargs: Any) -> "BrowserContext":
        """Open a new browser context with the given viewport/options.

        Each module should close its own context when done.
        """
        if self._browser is None:
            raise RuntimeError("BrowserPool is not started — call start() first")
        return await self._browser.new_context(**kwargs)

    @property
    def is_ready(self) -> bool:
        return self._browser is not None

    async def __aenter__(self) -> "BrowserPool":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()
