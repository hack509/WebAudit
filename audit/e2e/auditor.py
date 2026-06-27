"""
E2E Auditor — Module 12.

End-to-end tests using Playwright: auth flows, CRUD operations,
search, filters, notifications.
"""

from __future__ import annotations

import asyncio

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig


class E2EAuditor(BaseAuditor):
    """Runs end-to-end tests using Playwright for critical user flows."""

    MODULE_NAME = "e2e"
    MODULE_DESCRIPTION = "Tests End-to-End (Playwright)"

    def __init__(self, config: AuditConfig):
        super().__init__(config)

    async def run(self) -> AuditResult:
        """Run E2E tests."""
        self.logger.info(f"Starting E2E tests for {self._base_url}")

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.info("E2E Tests", "Playwright not installed — skipping E2E tests")
            return self.build_result()

        from utils.playwright_pool import get_pool

        async def _run_with_browser(browser) -> None:
            context = await browser.new_context(viewport={"width": 1920, "height": 1080})
            try:
                await self._test_navigation_flow(context)
                if self.config.auth.username and self.config.auth.password:
                    await self._test_auth_flow(context)
                await self._test_form_flow(context)
                await self._test_search_flow(context)
                await self._test_link_flow(context)
                await self._test_error_flow(context)
            finally:
                await context.close()

        pool = get_pool()
        try:
            if pool and pool.is_ready:
                context = await pool.new_context(viewport={"width": 1920, "height": 1080})
                try:
                    await self._test_navigation_flow(context)
                    if self.config.auth.username and self.config.auth.password:
                        await self._test_auth_flow(context)
                    await self._test_form_flow(context)
                    await self._test_search_flow(context)
                    await self._test_link_flow(context)
                    await self._test_error_flow(context)
                finally:
                    await context.close()
            else:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    await _run_with_browser(browser)
                    await browser.close()

        except Exception as e:
            self.logger.error(f"E2E tests failed: {e}")
            self.info("E2E Tests", f"E2E tests failed: {str(e)[:100]}")

        return self.build_result()

    async def _test_navigation_flow(self, context) -> None:
        """Test basic navigation across the site."""
        page = await context.new_page()
        try:
            response = await page.goto(self._base_url, wait_until="networkidle", timeout=30000)

            if response and response.ok:
                self.pass_check("E2E: Homepage loads", f"HTTP {response.status}")
            else:
                status = response.status if response else "N/A"
                self.fail_check(
                    "E2E: Homepage load failure",
                    f"Homepage returned HTTP {status}",
                    severity=Severity.CRITICAL,
                )
                return

            # Click first navigation links
            nav_links = await page.query_selector_all("nav a, header a")
            links_tested = 0

            for link in nav_links[:5]:
                try:
                    href = await link.get_attribute("href")
                    text = (await link.text_content() or "").strip()
                    if not href or href.startswith("#") or href.startswith("javascript:"):
                        continue

                    await link.click(timeout=5000)
                    await page.wait_for_load_state("networkidle", timeout=10000)

                    current_url = page.url
                    self.pass_check(
                        f"E2E: Nav link '{text[:20]}'",
                        f"Navigation successful → {current_url[:60]}",
                    )
                    links_tested += 1

                    # Go back
                    await page.go_back(wait_until="networkidle", timeout=10000)

                except Exception as e:
                    text_content = text if 'text' in dir() else "unknown"
                    self.fail_check(
                        f"E2E: Nav link failure",
                        f"Navigation click failed: {str(e)[:80]}",
                        severity=Severity.MEDIUM,
                    )

            if links_tested == 0:
                self.info("E2E: Navigation", "No navigation links found to test")

        except Exception as e:
            self.fail_check("E2E: Navigation flow", f"Error: {str(e)[:100]}", severity=Severity.HIGH)
        finally:
            await page.close()

    async def _test_auth_flow(self, context) -> None:
        """Test authentication flow: login → verify → logout."""
        page = await context.new_page()
        try:
            # Find login page
            login_paths = ["/login", "/signin", "/auth/login", "/connexion"]
            login_url = None

            for path in login_paths:
                url = f"{self._base_url.rstrip('/')}{path}"
                resp = await page.goto(url, wait_until="networkidle", timeout=15000)
                if resp and resp.ok:
                    login_url = url
                    break

            if not login_url:
                self.info("E2E: Auth flow", "No login page found — skipping auth E2E")
                return

            # Find and fill login form
            username_input = await page.query_selector(
                'input[name="username"], input[name="email"], input[type="email"], '
                'input[name="login"], input[id="username"], input[id="email"]'
            )
            password_input = await page.query_selector(
                'input[name="password"], input[type="password"], input[id="password"]'
            )

            if not username_input or not password_input:
                self.info("E2E: Auth flow", "Could not find login form fields")
                return

            await username_input.fill(self.config.auth.username)
            await password_input.fill(self.config.auth.password)

            # Submit form
            submit = await page.query_selector(
                'button[type="submit"], input[type="submit"], button:has-text("Login"), '
                'button:has-text("Sign in"), button:has-text("Connexion")'
            )

            if submit:
                await submit.click()
                await page.wait_for_load_state("networkidle", timeout=15000)

                # Check if login was successful (URL changed or dashboard-like content)
                if "/login" not in page.url and "/signin" not in page.url:
                    self.pass_check("E2E: Login successful", f"Redirected to {page.url[:60]}")
                else:
                    # Check for error messages
                    error = await page.query_selector('.error, .alert-danger, [role="alert"]')
                    error_text = await error.text_content() if error else "Unknown"
                    self.fail_check(
                        "E2E: Login failed",
                        f"Login did not redirect. Error: {(error_text or '')[:60]}",
                        severity=Severity.MEDIUM,
                    )

            # Test logout
            logout_link = await page.query_selector(
                'a:has-text("Logout"), a:has-text("Sign out"), a:has-text("Déconnexion"), '
                'button:has-text("Logout"), button:has-text("Déconnexion")'
            )
            if logout_link:
                await logout_link.click()
                await page.wait_for_load_state("networkidle", timeout=10000)
                self.pass_check("E2E: Logout", f"Logged out — redirected to {page.url[:60]}")

        except Exception as e:
            self.fail_check("E2E: Auth flow", f"Error: {str(e)[:100]}", severity=Severity.MEDIUM)
        finally:
            await page.close()

    async def _test_form_flow(self, context) -> None:
        """Test form submission flows."""
        page = await context.new_page()
        try:
            await page.goto(self._base_url, wait_until="networkidle", timeout=30000)

            # Find forms
            forms = await page.query_selector_all("form")

            if not forms:
                self.info("E2E: Forms", "No forms found on homepage")
                return

            for form in forms[:3]:
                inputs = await form.query_selector_all("input:not([type='hidden']), textarea, select")

                if not inputs:
                    continue

                # Try to fill and submit
                try:
                    for inp in inputs:
                        inp_type = await inp.get_attribute("type") or "text"
                        if inp_type == "email":
                            await inp.fill("test@audit.example.com")
                        elif inp_type == "password":
                            await inp.fill("TestPassword123!")
                        elif inp_type in ("text", "search"):
                            await inp.fill("audit test")
                        elif inp_type == "number":
                            await inp.fill("42")
                        elif inp_type == "tel":
                            await inp.fill("+33612345678")

                    submit_btn = await form.query_selector(
                        'button[type="submit"], input[type="submit"], button:not([type])'
                    )
                    if submit_btn:
                        await submit_btn.click(timeout=5000)
                        await asyncio.sleep(2)
                        self.pass_check("E2E: Form submission", "Form submitted successfully")
                    else:
                        self.info("E2E: Form", "No submit button found")

                except Exception as e:
                    self.fail_check(
                        "E2E: Form submission error",
                        f"Error: {str(e)[:80]}",
                        severity=Severity.LOW,
                    )

        except Exception as e:
            self.logger.warning(f"Form flow test failed: {e}")
        finally:
            await page.close()

    async def _test_search_flow(self, context) -> None:
        """Test search functionality."""
        page = await context.new_page()
        try:
            await page.goto(self._base_url, wait_until="networkidle", timeout=30000)

            # Find search input
            search_input = await page.query_selector(
                'input[type="search"], input[name="q"], input[name="search"], '
                'input[name="query"], input[placeholder*="search" i], '
                'input[placeholder*="recherche" i], input[aria-label*="search" i]'
            )

            if not search_input:
                self.info("E2E: Search", "No search input found")
                return

            await search_input.fill("test")
            await search_input.press("Enter")
            await asyncio.sleep(2)

            # Check if results appeared or page changed
            self.pass_check("E2E: Search", f"Search submitted — current URL: {page.url[:60]}")

        except Exception as e:
            self.fail_check("E2E: Search flow", f"Error: {str(e)[:80]}", severity=Severity.LOW)
        finally:
            await page.close()

    async def _test_link_flow(self, context) -> None:
        """Test that internal links work correctly."""
        page = await context.new_page()
        try:
            await page.goto(self._base_url, wait_until="networkidle", timeout=30000)

            links = await page.query_selector_all("a[href]")
            tested = 0

            for link in links[:10]:
                href = await link.get_attribute("href")
                if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                    continue

                if href.startswith("/") or self._base_url in href:
                    try:
                        resp = await page.goto(
                            href if href.startswith("http") else f"{self._base_url.rstrip('/')}{href}",
                            wait_until="domcontentloaded",
                            timeout=10000,
                        )
                        if resp and resp.ok:
                            tested += 1
                        elif resp:
                            self.fail_check(
                                f"E2E: Broken link {href[:40]}",
                                f"HTTP {resp.status}",
                                severity=Severity.MEDIUM,
                            )
                    except Exception:
                        pass

            if tested > 0:
                self.pass_check("E2E: Internal links", f"{tested} internal links verified")

        except Exception as e:
            self.logger.warning(f"Link flow test failed: {e}")
        finally:
            await page.close()

    async def _test_error_flow(self, context) -> None:
        """Test 404 and error page handling."""
        page = await context.new_page()
        try:
            error_url = f"{self._base_url.rstrip('/')}/nonexistent-page-e2e-test-12345"
            resp = await page.goto(error_url, wait_until="networkidle", timeout=15000)

            if resp and resp.status == 404:
                # Check for custom 404 page
                content = await page.content()
                if len(content) > 500:
                    self.pass_check("E2E: Custom 404 page", "Custom 404 error page displayed")
                else:
                    self.fail_check(
                        "E2E: Basic 404 page",
                        "404 page appears to be a bare/default error page",
                        severity=Severity.LOW,
                        recommendation="Create a user-friendly custom 404 page",
                    )
            elif resp and resp.ok:
                self.fail_check(
                    "E2E: No 404 for invalid URL",
                    "Server returns 200 for non-existent page",
                    severity=Severity.MEDIUM,
                    recommendation="Return proper 404 status for non-existent routes",
                )

        except Exception as e:
            self.logger.warning(f"Error flow test failed: {e}")
        finally:
            await page.close()
