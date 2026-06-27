"""
UX Auditor — Module 5.

Detects UX issues: small buttons, bad contrast, spacing, overflow,
horizontal scroll, broken layout, clipped text, deformed images, invisible components.
"""

from __future__ import annotations

import asyncio
from typing import Any

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.constants import MIN_TOUCH_TARGET_SIZE, WCAG_AA_NORMAL, VIEWPORTS


class UXAuditor(BaseAuditor):
    """Audits UX quality: contrast, touch targets, layout, overflow, visibility."""

    MODULE_NAME = "ux"
    MODULE_DESCRIPTION = "Audit UX"

    def __init__(self, config: AuditConfig):
        super().__init__(config)

    async def run(self) -> AuditResult:
        """Run the UX audit using Playwright for real-browser analysis."""
        self.logger.info(f"Starting UX audit for {self._base_url}")

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.info("UX Audit", "Playwright not installed — skipping browser-based UX checks")
            return self.build_result()

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)

                # Test desktop viewport
                await self._audit_viewport(browser, "desktop", VIEWPORTS["desktop"])
                # Test mobile viewport
                await self._audit_viewport(browser, "mobile", VIEWPORTS["mobile"])

                await browser.close()
        except Exception as e:
            self.logger.error(f"UX audit failed: {e}")
            self.info("UX Audit", f"Browser-based UX audit failed: {str(e)[:100]}")

        return self.build_result()

    async def _audit_viewport(self, browser, viewport_name: str, viewport: dict) -> None:
        """Audit UX for a specific viewport."""
        context = await browser.new_context(
            viewport={"width": viewport["width"], "height": viewport["height"]}
        )
        page = await context.new_page()

        try:
            await page.goto(self._base_url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(1)

            # 1. Check touch targets (buttons, links)
            await self._check_touch_targets(page, viewport_name)

            # 2. Check horizontal overflow
            await self._check_overflow(page, viewport_name)

            # 3. Check text clipping
            await self._check_text_clipping(page, viewport_name)

            # 4. Check contrast (basic)
            await self._check_contrast(page, viewport_name)

            # 5. Check invisible elements
            await self._check_invisible_elements(page, viewport_name)

            # 6. Check image distortion
            await self._check_image_distortion(page, viewport_name)

        except Exception as e:
            self.logger.warning(f"UX audit error for {viewport_name}: {e}")
        finally:
            await context.close()

    async def _check_touch_targets(self, page, viewport_name: str) -> None:
        """Check if interactive elements are large enough for touch."""
        small_targets = await page.evaluate(f"""() => {{
            const minSize = {MIN_TOUCH_TARGET_SIZE};
            const issues = [];
            const elements = document.querySelectorAll('a, button, input, select, textarea, [role="button"]');
            for (const el of elements) {{
                const rect = el.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0) {{
                    if (rect.width < minSize || rect.height < minSize) {{
                        issues.push({{
                            tag: el.tagName,
                            text: (el.textContent || '').trim().substring(0, 30),
                            width: Math.round(rect.width),
                            height: Math.round(rect.height),
                        }});
                    }}
                }}
            }}
            return issues.slice(0, 10);
        }}""")

        if small_targets:
            self.fail_check(
                f"Small touch targets ({viewport_name})",
                f"{len(small_targets)} element(s) smaller than {MIN_TOUCH_TARGET_SIZE}px: " +
                ", ".join(f"{t['tag']}({t['width']}x{t['height']})" for t in small_targets[:5]),
                severity=Severity.MEDIUM,
                recommendation=f"Ensure all interactive elements are at least {MIN_TOUCH_TARGET_SIZE}x{MIN_TOUCH_TARGET_SIZE}px",
            )
        else:
            self.pass_check(f"Touch targets ({viewport_name})", "All interactive elements meet minimum size")

    async def _check_overflow(self, page, viewport_name: str) -> None:
        """Check for horizontal overflow / horizontal scroll."""
        has_overflow = await page.evaluate("""() => {
            return document.documentElement.scrollWidth > document.documentElement.clientWidth;
        }""")

        if has_overflow:
            self.fail_check(
                f"Horizontal overflow ({viewport_name})",
                "Page has horizontal scroll — content overflows viewport",
                severity=Severity.HIGH if viewport_name == "mobile" else Severity.MEDIUM,
                recommendation="Fix CSS overflow — use max-width: 100%, overflow-x: hidden, or responsive units",
            )
        else:
            self.pass_check(f"No horizontal overflow ({viewport_name})", "Content fits within viewport")

    async def _check_text_clipping(self, page, viewport_name: str) -> None:
        """Check for clipped text (overflow:hidden with single-line text)."""
        clipped = await page.evaluate("""() => {
            const issues = [];
            const elements = document.querySelectorAll('p, span, h1, h2, h3, h4, h5, h6, a, button, li, td');
            for (const el of elements) {
                const style = window.getComputedStyle(el);
                if (style.overflow === 'hidden' && style.textOverflow !== 'ellipsis') {
                    if (el.scrollHeight > el.clientHeight + 2 || el.scrollWidth > el.clientWidth + 2) {
                        issues.push({
                            tag: el.tagName,
                            text: (el.textContent || '').trim().substring(0, 30),
                        });
                    }
                }
            }
            return issues.slice(0, 10);
        }""")

        if clipped:
            self.fail_check(
                f"Clipped text ({viewport_name})",
                f"{len(clipped)} element(s) with clipped text: " +
                ", ".join(f"{c['tag']}('{c['text']}')" for c in clipped[:5]),
                severity=Severity.LOW,
                recommendation="Use text-overflow: ellipsis or adjust container sizes",
            )
        else:
            self.pass_check(f"No clipped text ({viewport_name})", "No text overflow issues detected")

    async def _check_contrast(self, page, viewport_name: str) -> None:
        """Check basic color contrast on text elements."""
        low_contrast = await page.evaluate(f"""() => {{
            function getLuminance(r, g, b) {{
                const [rs, gs, bs] = [r/255, g/255, b/255].map(c =>
                    c <= 0.03928 ? c/12.92 : Math.pow((c+0.055)/1.055, 2.4)
                );
                return 0.2126*rs + 0.7152*gs + 0.0722*bs;
            }}

            function parseColor(str) {{
                const m = str.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/);
                if (m) return [parseInt(m[1]), parseInt(m[2]), parseInt(m[3])];
                return null;
            }}

            function contrastRatio(c1, c2) {{
                const l1 = getLuminance(...c1);
                const l2 = getLuminance(...c2);
                const lighter = Math.max(l1, l2);
                const darker = Math.min(l1, l2);
                return (lighter + 0.05) / (darker + 0.05);
            }}

            const issues = [];
            const els = document.querySelectorAll('p, span, h1, h2, h3, a, button, label, li, td, th');
            for (const el of els) {{
                if (!el.textContent.trim()) continue;
                const style = window.getComputedStyle(el);
                const fg = parseColor(style.color);
                const bg = parseColor(style.backgroundColor);
                if (fg && bg && bg[3] !== 0) {{
                    const ratio = contrastRatio(fg, bg);
                    if (ratio < {WCAG_AA_NORMAL}) {{
                        issues.push({{
                            tag: el.tagName,
                            text: el.textContent.trim().substring(0, 20),
                            ratio: Math.round(ratio * 100) / 100,
                            fg: style.color,
                            bg: style.backgroundColor,
                        }});
                    }}
                }}
            }}
            return issues.slice(0, 10);
        }}""")

        if low_contrast:
            self.fail_check(
                f"Low contrast ({viewport_name})",
                f"{len(low_contrast)} element(s) with insufficient contrast: " +
                ", ".join(f"{c['tag']}(ratio:{c['ratio']})" for c in low_contrast[:5]),
                severity=Severity.MEDIUM,
                recommendation=f"Ensure text contrast ratio is at least {WCAG_AA_NORMAL}:1 (WCAG AA)",
            )
        else:
            self.pass_check(f"Color contrast ({viewport_name})", "All text meets WCAG AA contrast requirements")

    async def _check_invisible_elements(self, page, viewport_name: str) -> None:
        """Check for interactive elements that are invisible."""
        invisible = await page.evaluate("""() => {
            const issues = [];
            const els = document.querySelectorAll('a, button, input, select, [role="button"]');
            for (const el of els) {
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0 || style.visibility === 'hidden' ||
                    parseFloat(style.opacity) === 0) {
                    if (el.offsetParent !== null) {
                        issues.push({
                            tag: el.tagName,
                            text: (el.textContent || '').trim().substring(0, 20),
                            reason: rect.width === 0 ? 'zero-width' : rect.height === 0 ? 'zero-height' :
                                    style.visibility === 'hidden' ? 'hidden' : 'transparent',
                        });
                    }
                }
            }
            return issues.slice(0, 10);
        }""")

        if invisible:
            self.fail_check(
                f"Invisible interactive elements ({viewport_name})",
                f"{len(invisible)} interactive element(s) are invisible: " +
                ", ".join(f"{i['tag']}({i['reason']})" for i in invisible[:5]),
                severity=Severity.MEDIUM,
                recommendation="Ensure all interactive elements are visible and accessible",
            )
        else:
            self.pass_check(f"Element visibility ({viewport_name})", "All interactive elements are visible")

    async def _check_image_distortion(self, page, viewport_name: str) -> None:
        """Check for distorted images (aspect ratio issues)."""
        distorted = await page.evaluate("""() => {
            const issues = [];
            const images = document.querySelectorAll('img');
            for (const img of images) {
                if (img.naturalWidth > 0 && img.naturalHeight > 0) {
                    const naturalRatio = img.naturalWidth / img.naturalHeight;
                    const displayRatio = img.clientWidth / img.clientHeight;
                    if (img.clientWidth > 0 && img.clientHeight > 0) {
                        const diff = Math.abs(naturalRatio - displayRatio) / naturalRatio;
                        if (diff > 0.1) {
                            issues.push({
                                src: img.src.substring(0, 60),
                                natural: `${img.naturalWidth}x${img.naturalHeight}`,
                                display: `${img.clientWidth}x${img.clientHeight}`,
                                diff: Math.round(diff * 100),
                            });
                        }
                    }
                }
            }
            return issues.slice(0, 10);
        }""")

        if distorted:
            self.fail_check(
                f"Distorted images ({viewport_name})",
                f"{len(distorted)} image(s) with aspect ratio distortion: " +
                ", ".join(f"{d['natural']}→{d['display']}({d['diff']}%)" for d in distorted[:5]),
                severity=Severity.LOW,
                recommendation="Use object-fit: cover/contain or set correct aspect ratios",
            )
        else:
            self.pass_check(f"Image aspect ratios ({viewport_name})", "No distorted images detected")
