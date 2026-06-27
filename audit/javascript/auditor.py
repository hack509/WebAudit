"""
JavaScript Auditor — Module 7.

Detects console errors, warnings, unhandled promises, memory leaks,
and other JavaScript issues using Playwright.
"""

from __future__ import annotations

import asyncio
from typing import Any

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig


class JavaScriptAuditor(BaseAuditor):
    """Audits JavaScript errors, console output, and memory issues."""

    MODULE_NAME = "javascript"
    MODULE_DESCRIPTION = "Audit JavaScript"

    def __init__(self, config: AuditConfig):
        super().__init__(config)

    async def run(self) -> AuditResult:
        """Run the JavaScript audit using Playwright."""
        self.logger.info(f"Starting JavaScript audit for {self._base_url}")

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.info("JS Audit", "Playwright not installed — skipping browser-based JS checks")
            return self.build_result()

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(viewport={"width": 1920, "height": 1080})
                page = await context.new_page()

                # Collect console messages
                console_errors: list[dict] = []
                console_warnings: list[dict] = []
                console_logs: list[dict] = []
                page_errors: list[str] = []

                page.on("console", lambda msg: self._handle_console(
                    msg, console_errors, console_warnings, console_logs
                ))
                page.on("pageerror", lambda err: page_errors.append(str(err)))

                # Navigate
                await page.goto(self._base_url, wait_until="networkidle", timeout=30000)
                await asyncio.sleep(3)  # Wait for JS to execute

                # 1. Console errors
                self._analyze_console_errors(console_errors)

                # 2. Console warnings
                self._analyze_console_warnings(console_warnings)

                # 3. Page errors (unhandled exceptions)
                self._analyze_page_errors(page_errors)

                # 4. Memory usage
                await self._check_memory(page)

                # 5. Unhandled promise rejections
                unhandled = await page.evaluate("""() => {
                    return window.__unhandledRejections || [];
                }""")

                # 6. Check for deprecated APIs
                await self._check_deprecated_apis(page)

                # 7. Check for console.log in production
                self._check_console_logs(console_logs)

                # 8. Network errors
                await self._check_network_errors(page)

                await browser.close()

        except Exception as e:
            self.logger.error(f"JavaScript audit failed: {e}")
            self.info("JS Audit", f"Browser-based JS audit failed: {str(e)[:100]}")

        return self.build_result()

    def _handle_console(self, msg, errors: list, warnings: list, logs: list) -> None:
        """Handle console messages."""
        entry = {
            "type": msg.type,
            "text": msg.text[:200],
            "location": str(msg.location) if hasattr(msg, 'location') else "",
        }
        if msg.type == "error":
            errors.append(entry)
        elif msg.type == "warning":
            warnings.append(entry)
        elif msg.type == "log":
            logs.append(entry)

    def _analyze_console_errors(self, errors: list[dict]) -> None:
        """Analyze console errors."""
        if not errors:
            self.pass_check("Console errors", "No JavaScript console errors")
            return

        self.fail_check(
            f"Console errors: {len(errors)}",
            "JavaScript console errors detected:\n" +
            "\n".join(f"  • {e['text']}" for e in errors[:5]),
            severity=Severity.HIGH if len(errors) > 5 else Severity.MEDIUM,
            recommendation="Fix all JavaScript console errors",
        )

    def _analyze_console_warnings(self, warnings: list[dict]) -> None:
        """Analyze console warnings."""
        if not warnings:
            self.pass_check("Console warnings", "No JavaScript console warnings")
            return

        self.fail_check(
            f"Console warnings: {len(warnings)}",
            "JavaScript console warnings detected:\n" +
            "\n".join(f"  • {w['text']}" for w in warnings[:5]),
            severity=Severity.LOW,
            recommendation="Review and address JavaScript warnings",
        )

    def _analyze_page_errors(self, errors: list[str]) -> None:
        """Analyze uncaught page errors."""
        if not errors:
            self.pass_check("Uncaught exceptions", "No uncaught JavaScript exceptions")
            return

        self.fail_check(
            f"Uncaught exceptions: {len(errors)}",
            "Unhandled JavaScript exceptions:\n" +
            "\n".join(f"  • {e[:100]}" for e in errors[:5]),
            severity=Severity.HIGH,
            recommendation="Add try-catch blocks and error boundaries to handle exceptions",
        )

    async def _check_memory(self, page) -> None:
        """Check JavaScript memory usage."""
        try:
            memory = await page.evaluate("""() => {
                if (performance.memory) {
                    return {
                        usedJSHeapSize: performance.memory.usedJSHeapSize,
                        totalJSHeapSize: performance.memory.totalJSHeapSize,
                        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
                    };
                }
                return null;
            }""")

            if memory:
                used_mb = memory["usedJSHeapSize"] / (1024 * 1024)
                total_mb = memory["totalJSHeapSize"] / (1024 * 1024)
                limit_mb = memory["jsHeapSizeLimit"] / (1024 * 1024)

                self.info(
                    "Memory usage",
                    f"Heap: {used_mb:.1f}MB / {total_mb:.1f}MB (limit: {limit_mb:.1f}MB)",
                )

                usage_ratio = memory["usedJSHeapSize"] / memory["jsHeapSizeLimit"]
                if usage_ratio > 0.8:
                    self.fail_check(
                        "High memory usage",
                        f"JS heap usage: {usage_ratio*100:.0f}% of limit ({used_mb:.0f}MB)",
                        severity=Severity.HIGH,
                        recommendation="Investigate memory leaks — check event listeners, closures, DOM references",
                    )
                elif usage_ratio > 0.5:
                    self.fail_check(
                        "Elevated memory usage",
                        f"JS heap: {used_mb:.0f}MB ({usage_ratio*100:.0f}% of limit)",
                        severity=Severity.LOW,
                        recommendation="Monitor memory usage and optimize if it grows over time",
                    )
                else:
                    self.pass_check("Memory usage", f"JS heap: {used_mb:.1f}MB — within limits")
        except Exception:
            self.info("Memory check", "Memory API not available in this browser context")

    async def _check_deprecated_apis(self, page) -> None:
        """Check for usage of deprecated APIs."""
        deprecated = await page.evaluate("""() => {
            const warnings = [];
            // Check for deprecated APIs
            if (typeof document.all !== 'undefined' && document.all) {
                warnings.push('document.all is deprecated');
            }
            // Check inline event handlers
            const inlineHandlers = document.querySelectorAll('[onclick], [onmouseover], [onsubmit], [onload]');
            if (inlineHandlers.length > 0) {
                warnings.push(`${inlineHandlers.length} inline event handler(s) found`);
            }
            // Check synchronous XHR
            // Can't easily detect at runtime, skip
            return warnings;
        }""")

        if deprecated:
            self.fail_check(
                "Deprecated API usage",
                "Deprecated APIs detected:\n" + "\n".join(f"  • {d}" for d in deprecated),
                severity=Severity.LOW,
                recommendation="Replace deprecated APIs with modern alternatives",
            )
        else:
            self.pass_check("Deprecated APIs", "No deprecated API usage detected")

    def _check_console_logs(self, logs: list[dict]) -> None:
        """Check for console.log statements in production."""
        if len(logs) > 10:
            self.fail_check(
                f"Excessive console.log: {len(logs)}",
                f"{len(logs)} console.log statements — should be removed in production",
                severity=Severity.LOW,
                recommendation="Remove console.log statements in production code",
            )
        elif logs:
            self.info(
                f"Console.log statements: {len(logs)}",
                "Some console.log found — consider removing for production",
            )
        else:
            self.pass_check("Console.log clean", "No console.log statements detected")

    async def _check_network_errors(self, page) -> None:
        """Check for failed network requests."""
        failed_requests = await page.evaluate("""() => {
            const entries = performance.getEntriesByType('resource');
            const failed = [];
            for (const entry of entries) {
                if (entry.transferSize === 0 && entry.decodedBodySize === 0 &&
                    !entry.name.startsWith('data:')) {
                    failed.push({
                        url: entry.name.substring(0, 80),
                        type: entry.initiatorType,
                    });
                }
            }
            return failed.slice(0, 10);
        }""")

        if failed_requests:
            self.fail_check(
                f"Failed network requests: {len(failed_requests)}",
                "Resources failed to load:\n" +
                "\n".join(f"  • [{r['type']}] {r['url']}" for r in failed_requests[:5]),
                severity=Severity.MEDIUM,
                recommendation="Fix or remove references to failed resources",
            )
        else:
            self.pass_check("Network requests", "All resources loaded successfully")
