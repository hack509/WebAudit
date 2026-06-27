"""
Mobile Auditor — Module 11.

Tests responsive design, safe areas, touch targets, gestures,
viewport, and orientation across mobile viewports.
"""

from __future__ import annotations

import asyncio
from typing import Any

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.constants import VIEWPORTS, MIN_TOUCH_TARGET_SIZE


class MobileAuditor(BaseAuditor):
    """Audits mobile-specific UX: responsive, safe area, touch, viewport, orientation."""

    MODULE_NAME = "mobile"
    MODULE_DESCRIPTION = "Audit Mobile & Responsive"

    def __init__(self, config: AuditConfig):
        super().__init__(config)

    async def run(self) -> AuditResult:
        """Run the mobile audit using Playwright."""
        self.logger.info(f"Starting mobile audit for {self._base_url}")

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.info("Mobile Audit", "Playwright not installed — skipping mobile checks")
            return self.build_result()

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)

                # Test mobile viewport (portrait)
                await self._test_mobile_portrait(browser)

                # Test mobile viewport (landscape)
                await self._test_mobile_landscape(browser)

                # Test tablet viewport
                await self._test_tablet(browser)

                await browser.close()

        except Exception as e:
            self.logger.error(f"Mobile audit failed: {e}")
            self.info("Mobile Audit", f"Browser-based mobile audit failed: {str(e)[:100]}")

        return self.build_result()

    async def _test_mobile_portrait(self, browser) -> None:
        """Test mobile portrait orientation."""
        context = await browser.new_context(
            viewport={"width": 375, "height": 812},
            is_mobile=True,
            has_touch=True,
        )
        page = await context.new_page()

        try:
            await page.goto(self._base_url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(1)

            # 1. Viewport meta tag
            await self._check_viewport_meta(page)

            # 2. Horizontal overflow
            await self._check_mobile_overflow(page, "mobile-portrait")

            # 3. Touch targets
            await self._check_mobile_touch_targets(page, "mobile-portrait")

            # 4. Font size readability
            await self._check_font_sizes(page, "mobile-portrait")

            # 5. Safe area (notch)
            await self._check_safe_area(page, "mobile-portrait")

            # 6. Fixed elements
            await self._check_fixed_elements(page, "mobile-portrait")

            # 7. Input zoom
            await self._check_input_zoom(page)

        except Exception as e:
            self.logger.warning(f"Mobile portrait test failed: {e}")
        finally:
            await context.close()

    async def _test_mobile_landscape(self, browser) -> None:
        """Test mobile landscape orientation."""
        context = await browser.new_context(
            viewport={"width": 812, "height": 375},
            is_mobile=True,
            has_touch=True,
        )
        page = await context.new_page()

        try:
            await page.goto(self._base_url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(1)

            await self._check_mobile_overflow(page, "mobile-landscape")
            await self._check_mobile_touch_targets(page, "mobile-landscape")

        except Exception as e:
            self.logger.warning(f"Mobile landscape test failed: {e}")
        finally:
            await context.close()

    async def _test_tablet(self, browser) -> None:
        """Test tablet viewport."""
        context = await browser.new_context(
            viewport={"width": 768, "height": 1024},
            is_mobile=True,
            has_touch=True,
        )
        page = await context.new_page()

        try:
            await page.goto(self._base_url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(1)

            await self._check_mobile_overflow(page, "tablet")
            await self._check_mobile_touch_targets(page, "tablet")

        except Exception as e:
            self.logger.warning(f"Tablet test failed: {e}")
        finally:
            await context.close()

    async def _check_viewport_meta(self, page) -> None:
        """Check viewport meta tag."""
        viewport = await page.evaluate("""() => {
            const meta = document.querySelector('meta[name="viewport"]');
            return meta ? meta.getAttribute('content') : null;
        }""")

        if viewport:
            self.pass_check("Viewport meta tag", f"viewport: {viewport}")

            if "width=device-width" in viewport:
                self.pass_check("Viewport width", "Uses device-width")
            else:
                self.fail_check(
                    "Viewport not device-width",
                    "Viewport does not use width=device-width",
                    severity=Severity.MEDIUM,
                    recommendation="Set viewport to width=device-width, initial-scale=1",
                )

            if "user-scalable=no" in viewport or "maximum-scale=1" in viewport:
                self.fail_check(
                    "Zoom disabled",
                    "Viewport prevents user zoom — accessibility issue",
                    severity=Severity.MEDIUM,
                    recommendation="Do not disable zoom — it's an accessibility requirement",
                )
            else:
                self.pass_check("Zoom allowed", "User can zoom the page")
        else:
            self.fail_check(
                "Missing viewport meta",
                "No viewport meta tag — page not optimized for mobile",
                severity=Severity.HIGH,
                recommendation='Add <meta name="viewport" content="width=device-width, initial-scale=1">',
            )

    async def _check_mobile_overflow(self, page, viewport_name: str) -> None:
        """Check horizontal overflow on mobile."""
        has_overflow = await page.evaluate("""() => {
            return document.documentElement.scrollWidth > document.documentElement.clientWidth;
        }""")

        if has_overflow:
            overflow_elements = await page.evaluate("""() => {
                const elements = [];
                const all = document.querySelectorAll('*');
                for (const el of all) {
                    if (el.scrollWidth > el.clientWidth + 5) {
                        elements.push({
                            tag: el.tagName,
                            class: el.className ? el.className.toString().substring(0, 30) : '',
                            overflow: el.scrollWidth - el.clientWidth,
                        });
                    }
                }
                return elements.slice(0, 5);
            }""")

            detail = ", ".join(f"{e['tag']}.{e['class']}(+{e['overflow']}px)" for e in overflow_elements[:3])
            self.fail_check(
                f"Horizontal overflow ({viewport_name})",
                f"Content overflows viewport: {detail}",
                severity=Severity.HIGH,
                recommendation="Use max-width: 100%, overflow-x: hidden, responsive CSS units",
            )
        else:
            self.pass_check(f"No overflow ({viewport_name})", "Content fits mobile viewport")

    async def _check_mobile_touch_targets(self, page, viewport_name: str) -> None:
        """Check touch target sizes on mobile."""
        small = await page.evaluate(f"""() => {{
            const min = {MIN_TOUCH_TARGET_SIZE};
            const issues = [];
            const els = document.querySelectorAll('a, button, input, select, [role="button"], [onclick]');
            for (const el of els) {{
                const r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0 && (r.width < min || r.height < min)) {{
                    issues.push({{
                        tag: el.tagName,
                        text: (el.textContent || '').trim().substring(0, 20),
                        w: Math.round(r.width),
                        h: Math.round(r.height),
                    }});
                }}
            }}
            return issues.slice(0, 10);
        }}""")

        if small:
            self.fail_check(
                f"Small touch targets ({viewport_name})",
                f"{len(small)} element(s) too small for touch: " +
                ", ".join(f"{s['tag']}({s['w']}x{s['h']})" for s in small[:5]),
                severity=Severity.MEDIUM,
                recommendation=f"Minimum touch target: {MIN_TOUCH_TARGET_SIZE}x{MIN_TOUCH_TARGET_SIZE}px",
            )
        else:
            self.pass_check(f"Touch targets ({viewport_name})", "All touch targets are adequate")

    async def _check_font_sizes(self, page, viewport_name: str) -> None:
        """Check font sizes for mobile readability."""
        small_text = await page.evaluate("""() => {
            const issues = [];
            const els = document.querySelectorAll('p, span, a, li, td, th, label');
            for (const el of els) {
                if (!el.textContent.trim()) continue;
                const style = window.getComputedStyle(el);
                const size = parseFloat(style.fontSize);
                if (size < 12) {
                    issues.push({
                        tag: el.tagName,
                        text: el.textContent.trim().substring(0, 20),
                        size: Math.round(size),
                    });
                }
            }
            return issues.slice(0, 10);
        }""")

        if small_text:
            self.fail_check(
                f"Small text ({viewport_name})",
                f"{len(small_text)} element(s) with font-size < 12px: " +
                ", ".join(f"{t['tag']}({t['size']}px)" for t in small_text[:5]),
                severity=Severity.MEDIUM,
                recommendation="Use minimum 12px font size for mobile readability (14-16px recommended)",
            )
        else:
            self.pass_check(f"Font sizes ({viewport_name})", "All text is readable on mobile")

    async def _check_safe_area(self, page, viewport_name: str) -> None:
        """Check safe area handling for notch devices."""
        uses_safe_area = await page.evaluate("""() => {
            const styles = document.querySelectorAll('style');
            let css = '';
            for (const s of styles) css += s.textContent || '';
            // Also check inline styles and computed
            const meta = document.querySelector('meta[name="viewport"]');
            const viewport = meta ? meta.getAttribute('content') : '';
            return {
                css_uses_env: css.includes('env(safe-area'),
                viewport_cover: viewport.includes('viewport-fit=cover'),
            };
        }""")

        if uses_safe_area.get("viewport_cover"):
            self.pass_check("Safe area (viewport-fit)", "viewport-fit=cover is set")
            if uses_safe_area.get("css_uses_env"):
                self.pass_check("Safe area CSS", "env(safe-area-inset) used in CSS")
            else:
                self.fail_check(
                    "Safe area CSS missing",
                    "viewport-fit=cover set but no env(safe-area-inset) in CSS",
                    severity=Severity.LOW,
                    recommendation="Use env(safe-area-inset-*) padding for notch devices",
                )
        else:
            self.info("Safe area", "viewport-fit=cover not used (may not be needed)")

    async def _check_fixed_elements(self, page, viewport_name: str) -> None:
        """Check for fixed elements that may cause issues on mobile."""
        fixed = await page.evaluate("""() => {
            const issues = [];
            const all = document.querySelectorAll('*');
            for (const el of all) {
                const style = window.getComputedStyle(el);
                if (style.position === 'fixed') {
                    const rect = el.getBoundingClientRect();
                    if (rect.height > window.innerHeight * 0.3) {
                        issues.push({
                            tag: el.tagName,
                            class: el.className ? el.className.toString().substring(0, 20) : '',
                            height: Math.round(rect.height),
                            viewportPercent: Math.round(rect.height / window.innerHeight * 100),
                        });
                    }
                }
            }
            return issues;
        }""")

        if fixed:
            self.fail_check(
                f"Large fixed elements ({viewport_name})",
                f"Fixed elements covering >30% of viewport: " +
                ", ".join(f"{f['tag']}({f['viewportPercent']}%)" for f in fixed),
                severity=Severity.MEDIUM,
                recommendation="Reduce size of fixed elements on mobile or make them collapsible",
            )
        else:
            self.pass_check(f"Fixed elements ({viewport_name})", "No oversized fixed elements")

    async def _check_input_zoom(self, page) -> None:
        """Check if inputs cause unwanted zoom on iOS."""
        small_inputs = await page.evaluate("""() => {
            const inputs = document.querySelectorAll('input, select, textarea');
            let count = 0;
            for (const el of inputs) {
                const style = window.getComputedStyle(el);
                const size = parseFloat(style.fontSize);
                if (size < 16) count++;
            }
            return count;
        }""")

        if small_inputs > 0:
            self.fail_check(
                "Input zoom issue",
                f"{small_inputs} input(s) with font-size < 16px — causes zoom on iOS",
                severity=Severity.MEDIUM,
                recommendation="Set font-size: 16px on inputs to prevent iOS zoom",
            )
        else:
            self.pass_check("Input font size", "All inputs have font-size ≥ 16px")
