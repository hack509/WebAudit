"""
Performance Auditor — Module 6.

Measures loading times, Web Vitals (LCP, CLS, FID, TTFB),
cache, compression, bundle sizes, images, and lazy loading.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.http_client import HttpClient
from utils.helpers import bytes_to_human, ms_to_human


class PerformanceAuditor(BaseAuditor):
    """Audits web performance including Web Vitals and resource optimization."""

    MODULE_NAME = "performance"
    MODULE_DESCRIPTION = "Audit de Performance"

    def __init__(self, config: AuditConfig):
        super().__init__(config)
        self.client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
            jwt_token=config.auth.jwt_token,
        )
        self.metrics: dict[str, Any] = {}

    async def run(self) -> AuditResult:
        """Run the performance audit."""
        self.logger.info(f"Starting performance audit for {self._base_url}")

        # 1. TTFB
        self._measure_ttfb()

        # 2. Page load time
        self._measure_page_load()

        # 3. Compression
        self._check_compression()

        # 4. Cache headers
        self._check_cache_headers()

        # 5. Resource sizes
        self._check_resource_sizes()

        # 6. Web Vitals via Playwright
        await self._measure_web_vitals()

        # 7. Redirect chain
        self._check_redirect_chain()

        # 8. DNS prefetch / preconnect
        self._check_resource_hints()

        return self.build_result()

    def _measure_ttfb(self) -> None:
        """Measure Time to First Byte."""
        times = []
        for _ in range(3):
            start = time.perf_counter()
            resp = self.client.get(self._base_url)
            ttfb = (time.perf_counter() - start) * 1000
            if not resp.error:
                times.append(ttfb)

        if not times:
            self.fail_check("TTFB measurement", "Could not measure TTFB", severity=Severity.HIGH)
            return

        avg_ttfb = sum(times) / len(times)
        self.metrics["ttfb"] = avg_ttfb

        threshold = self.config.performance.ttfb_threshold_ms
        if avg_ttfb <= threshold:
            self.pass_check(
                "TTFB (Time to First Byte)",
                f"Average TTFB: {avg_ttfb:.0f}ms (threshold: {threshold}ms)",
            )
        else:
            self.fail_check(
                "TTFB too slow",
                f"Average TTFB: {avg_ttfb:.0f}ms exceeds threshold ({threshold}ms)",
                severity=Severity.HIGH if avg_ttfb > threshold * 2 else Severity.MEDIUM,
                recommendation="Optimize server response time — check database queries, caching, server config",
            )

    def _measure_page_load(self) -> None:
        """Measure full page load time."""
        start = time.perf_counter()
        resp = self.client.get(self._base_url)
        load_time = (time.perf_counter() - start) * 1000

        if resp.error:
            return

        self.metrics["page_load_ms"] = load_time
        self.metrics["page_size_bytes"] = resp.size_bytes

        threshold = self.config.performance.max_page_load_ms
        if load_time <= threshold:
            self.pass_check(
                "Page load time",
                f"Page loaded in {load_time:.0f}ms ({bytes_to_human(resp.size_bytes)})",
            )
        else:
            self.fail_check(
                "Page load too slow",
                f"Page load: {load_time:.0f}ms (threshold: {threshold}ms), Size: {bytes_to_human(resp.size_bytes)}",
                severity=Severity.MEDIUM,
                recommendation="Optimize page size and server response time",
            )

        # Check page size
        if resp.size_bytes > 3 * 1024 * 1024:  # 3MB
            self.fail_check(
                "Page too large",
                f"Page size: {bytes_to_human(resp.size_bytes)} — exceeds 3MB",
                severity=Severity.MEDIUM,
                recommendation="Reduce page size — optimize images, minify CSS/JS, enable compression",
            )
        elif resp.size_bytes > 1 * 1024 * 1024:  # 1MB
            self.fail_check(
                "Large page size",
                f"Page size: {bytes_to_human(resp.size_bytes)} — consider optimization",
                severity=Severity.LOW,
                recommendation="Consider reducing page size for faster load times",
            )
        else:
            self.pass_check("Page size", f"Page size: {bytes_to_human(resp.size_bytes)}")

    def _check_compression(self) -> None:
        """Check if server supports compression."""
        resp = self.client.get(self._base_url, headers={"Accept-Encoding": "gzip, deflate, br"})
        if resp.error:
            return

        encoding = resp.headers.get("Content-Encoding", "")
        if "br" in encoding:
            self.pass_check("Brotli compression", "Server uses Brotli compression")
        elif "gzip" in encoding:
            self.pass_check("Gzip compression", "Server uses gzip compression")
        elif "deflate" in encoding:
            self.pass_check("Deflate compression", "Server uses deflate compression")
        else:
            self.fail_check(
                "No compression",
                "Server does not compress responses",
                severity=Severity.MEDIUM,
                recommendation="Enable gzip or Brotli compression on the server",
            )

    def _check_cache_headers(self) -> None:
        """Check caching headers."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        cache_control = resp.headers.get("Cache-Control", "")
        etag = resp.headers.get("ETag", "")
        last_modified = resp.headers.get("Last-Modified", "")

        if cache_control:
            self.pass_check("Cache-Control", f"Cache-Control: {cache_control}")

            if "no-store" in cache_control and "no-cache" in cache_control:
                self.info("Cache disabled", "Caching is completely disabled")
            elif "max-age=0" in cache_control:
                self.fail_check(
                    "Cache max-age is 0",
                    "Cache-Control max-age=0 — resources won't be cached",
                    severity=Severity.LOW,
                    recommendation="Set appropriate max-age for static resources",
                )
        else:
            self.fail_check(
                "No Cache-Control header",
                "No Cache-Control header — browser caching not configured",
                severity=Severity.MEDIUM,
                recommendation="Add Cache-Control headers for static resources",
            )

        if etag:
            self.pass_check("ETag header", "ETag present for conditional requests")

        if last_modified:
            self.pass_check("Last-Modified header", f"Last-Modified: {last_modified}")

        if not etag and not last_modified:
            self.fail_check(
                "No conditional caching",
                "Neither ETag nor Last-Modified — no conditional request support",
                severity=Severity.LOW,
                recommendation="Add ETag or Last-Modified headers for efficient caching",
            )

    def _check_resource_sizes(self) -> None:
        """Check JS/CSS resource sizes."""
        from bs4 import BeautifulSoup
        from utils.helpers import is_same_domain
        from urllib.parse import urljoin

        resp = self.client.get(self._base_url)
        if resp.error:
            return

        soup = BeautifulSoup(resp.body, "lxml")
        total_js_size = 0
        total_css_size = 0

        # Check JS bundles
        for script in soup.find_all("script", src=True):
            src = script["src"]
            url = urljoin(self._base_url, src)
            if not is_same_domain(url, self._base_url):
                continue
            head_resp = self.client.head(url)
            try:
                size = int(head_resp.headers.get("Content-Length", "0"))
                total_js_size += size
                max_kb = self.config.performance.max_bundle_size_kb
                if size > max_kb * 1024:
                    self.fail_check(
                        f"Large JS: {src.split('/')[-1][:40]}",
                        f"JS bundle: {bytes_to_human(size)} (max: {max_kb}KB)",
                        severity=Severity.MEDIUM,
                        recommendation="Use code splitting and tree shaking to reduce bundle size",
                    )
            except (ValueError, TypeError):
                pass

        # Check CSS
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "")
            if not href:
                continue
            url = urljoin(self._base_url, href)
            if not is_same_domain(url, self._base_url):
                continue
            head_resp = self.client.head(url)
            try:
                size = int(head_resp.headers.get("Content-Length", "0"))
                total_css_size += size
            except (ValueError, TypeError):
                pass

        self.metrics["total_js_size"] = total_js_size
        self.metrics["total_css_size"] = total_css_size

        self.info(
            "Total resource sizes",
            f"JS: {bytes_to_human(total_js_size)} | CSS: {bytes_to_human(total_css_size)}",
        )

    async def _measure_web_vitals(self) -> None:
        """Measure Web Vitals using Playwright."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.info("Web Vitals", "Playwright not installed — skipping browser-based metrics")
            return

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(viewport={"width": 1920, "height": 1080})
                page = await context.new_page()

                # Inject Web Vitals observer
                await page.add_init_script("""
                    window.__webVitals = {};
                    new PerformanceObserver((list) => {
                        for (const entry of list.getEntries()) {
                            if (entry.entryType === 'largest-contentful-paint') {
                                window.__webVitals.lcp = entry.startTime;
                            }
                            if (entry.entryType === 'layout-shift' && !entry.hadRecentInput) {
                                window.__webVitals.cls = (window.__webVitals.cls || 0) + entry.value;
                            }
                            if (entry.entryType === 'first-input') {
                                window.__webVitals.fid = entry.processingStart - entry.startTime;
                            }
                        }
                    }).observe({type: 'largest-contentful-paint', buffered: true});
                    new PerformanceObserver((list) => {
                        for (const entry of list.getEntries()) {
                            if (entry.entryType === 'layout-shift' && !entry.hadRecentInput) {
                                window.__webVitals.cls = (window.__webVitals.cls || 0) + entry.value;
                            }
                        }
                    }).observe({type: 'layout-shift', buffered: true});
                    new PerformanceObserver((list) => {
                        for (const entry of list.getEntries()) {
                            window.__webVitals.fid = entry.processingStart - entry.startTime;
                        }
                    }).observe({type: 'first-input', buffered: true});
                """)

                start = time.perf_counter()
                await page.goto(self._base_url, wait_until="networkidle", timeout=30000)
                load_time = (time.perf_counter() - start) * 1000

                # Wait a bit for metrics to settle
                await asyncio.sleep(2)

                # Get metrics
                vitals = await page.evaluate("() => window.__webVitals || {}")

                # Get performance timing
                perf_timing = await page.evaluate("""() => {
                    const t = performance.timing;
                    return {
                        dns: t.domainLookupEnd - t.domainLookupStart,
                        tcp: t.connectEnd - t.connectStart,
                        ttfb: t.responseStart - t.requestStart,
                        dom_interactive: t.domInteractive - t.navigationStart,
                        dom_complete: t.domComplete - t.navigationStart,
                        load_event: t.loadEventEnd - t.navigationStart,
                    };
                }""")

                # LCP
                lcp = vitals.get("lcp")
                if lcp is not None:
                    self.metrics["lcp"] = lcp
                    threshold = self.config.performance.lcp_threshold_ms
                    if lcp <= threshold:
                        self.pass_check("LCP (Largest Contentful Paint)", f"LCP: {lcp:.0f}ms (good ≤ {threshold}ms)")
                    else:
                        self.fail_check(
                            "LCP too slow",
                            f"LCP: {lcp:.0f}ms (threshold: {threshold}ms)",
                            severity=Severity.HIGH if lcp > threshold * 1.6 else Severity.MEDIUM,
                            recommendation="Optimize LCP — reduce image sizes, preload critical resources",
                        )

                # CLS
                cls_val = vitals.get("cls", 0)
                self.metrics["cls"] = cls_val
                threshold_cls = self.config.performance.cls_threshold
                if cls_val <= threshold_cls:
                    self.pass_check("CLS (Cumulative Layout Shift)", f"CLS: {cls_val:.3f} (good ≤ {threshold_cls})")
                else:
                    self.fail_check(
                        "CLS too high",
                        f"CLS: {cls_val:.3f} (threshold: {threshold_cls})",
                        severity=Severity.MEDIUM,
                        recommendation="Set explicit dimensions on images/embeds, avoid dynamic content insertion",
                    )

                # Performance timing
                if perf_timing.get("dom_interactive", 0) > 0:
                    self.info(
                        "Browser performance timing",
                        f"DNS: {perf_timing.get('dns', 0)}ms | "
                        f"TCP: {perf_timing.get('tcp', 0)}ms | "
                        f"TTFB: {perf_timing.get('ttfb', 0)}ms | "
                        f"DOM Interactive: {perf_timing.get('dom_interactive', 0)}ms | "
                        f"DOM Complete: {perf_timing.get('dom_complete', 0)}ms",
                    )

                await browser.close()

        except Exception as e:
            self.logger.warning(f"Web Vitals measurement failed: {e}")
            self.info("Web Vitals", f"Browser-based measurement failed: {str(e)[:100]}")

    def _check_redirect_chain(self) -> None:
        """Check for excessive redirect chains."""
        resp = self.client.request("GET", self._base_url, allow_redirects=False)

        redirect_count = 0
        current_url = self._base_url
        max_redirects = 10

        while resp.is_redirect and redirect_count < max_redirects:
            redirect_count += 1
            location = resp.headers.get("Location", "")
            if not location:
                break
            current_url = location
            resp = self.client.request("GET", current_url, allow_redirects=False)

        if redirect_count > 3:
            self.fail_check(
                "Excessive redirects",
                f"{redirect_count} redirects before reaching final URL",
                severity=Severity.MEDIUM,
                recommendation="Reduce redirect chain — aim for maximum 1-2 redirects",
            )
        elif redirect_count > 0:
            self.pass_check("Redirect chain", f"{redirect_count} redirect(s) — acceptable")
        else:
            self.pass_check("No redirects", "Direct response — no redirects")

    def _check_resource_hints(self) -> None:
        """Check for resource hints (preconnect, prefetch, preload)."""
        from bs4 import BeautifulSoup

        resp = self.client.get(self._base_url)
        if resp.error:
            return

        soup = BeautifulSoup(resp.body, "lxml")

        preconnect = soup.find_all("link", rel="preconnect")
        prefetch = soup.find_all("link", rel="dns-prefetch")
        preload = soup.find_all("link", rel="preload")

        if preconnect:
            self.pass_check("Preconnect hints", f"{len(preconnect)} preconnect hint(s) found")
        if prefetch:
            self.pass_check("DNS prefetch", f"{len(prefetch)} DNS prefetch hint(s) found")
        if preload:
            self.pass_check("Preload hints", f"{len(preload)} preload hint(s) found")

        if not preconnect and not prefetch and not preload:
            self.fail_check(
                "No resource hints",
                "No preconnect, dns-prefetch, or preload hints found",
                severity=Severity.LOW,
                recommendation="Add resource hints for critical third-party origins",
            )
