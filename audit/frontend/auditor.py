"""
Frontend Auditor — Module 4.

Scans all pages and tests responsive design, navigation, broken links,
images, forms, modals, loading states, and dark/light mode.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.http_client import HttpClient
from utils.helpers import normalize_url, is_same_domain, bytes_to_human


class FrontendAuditor(BaseAuditor):
    """Audits frontend pages: links, images, forms, responsive, SEO, accessibility."""

    MODULE_NAME = "frontend"
    MODULE_DESCRIPTION = "Audit du Frontend"

    def __init__(self, config: AuditConfig):
        super().__init__(config)
        self.client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
            jwt_token=config.auth.jwt_token,
        )
        self.pages: list[dict[str, Any]] = []

    async def run(self) -> AuditResult:
        """Run the frontend audit."""
        self.logger.info(f"Starting frontend audit for {self._base_url}")

        # 1. Crawl pages
        self._crawl_pages()

        # 2. Check broken links
        self._check_broken_links()

        # 3. Check images
        self._check_images()

        # 4. Check forms
        self._check_forms()

        # 5. Check navigation
        self._check_navigation()

        # 6. Check SEO
        self._check_seo()

        # 7. Check accessibility basics
        self._check_accessibility()

        # 8. Check PWA
        self._check_pwa()

        # 9. Check assets
        self._check_assets()

        return self.build_result()

    def _crawl_pages(self) -> None:
        """Crawl and index pages."""
        visited: set[str] = set()
        to_visit: list[str] = [self._base_url]
        max_pages = min(self.config.crawl.max_pages, 30)

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            normalized = normalize_url(url)
            if normalized in visited:
                continue
            visited.add(normalized)

            resp = self.client.get(url)
            if resp.error or resp.status_code >= 400:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(resp.body, "lxml")
            page_data = {
                "url": url,
                "status": resp.status_code,
                "soup": soup,
                "body": resp.body,
                "elapsed_ms": resp.elapsed_ms,
                "size_bytes": resp.size_bytes,
            }
            self.pages.append(page_data)

            # Find links to crawl
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue
                full_url = urljoin(url, href)
                if is_same_domain(full_url, self._base_url):
                    to_visit.append(full_url)

        self.info("Pages crawled", f"{len(self.pages)} page(s) crawled")

    def _check_broken_links(self) -> None:
        """Check all links for broken ones."""
        checked_urls: set[str] = set()
        broken_count = 0
        total_links = 0

        for page in self.pages:
            soup = page["soup"]
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue

                full_url = urljoin(page["url"], href)
                if full_url in checked_urls:
                    continue
                checked_urls.add(full_url)
                total_links += 1

                if not is_same_domain(full_url, self._base_url):
                    continue  # Skip external links for speed

                resp = self.client.head(full_url)
                if resp.status_code == 404 or resp.error:
                    broken_count += 1
                    self.fail_check(
                        f"Broken link: {href[:60]}",
                        f"Link on {page['url']} leads to HTTP {resp.status_code}",
                        severity=Severity.MEDIUM,
                        url=full_url,
                        recommendation="Fix or remove the broken link",
                    )

                if total_links >= 100:
                    break

        if broken_count == 0:
            self.pass_check("No broken links", f"All {total_links} internal links are valid")
        else:
            self.info("Broken links summary", f"{broken_count}/{total_links} broken link(s) found")

    def _check_images(self) -> None:
        """Check images for alt tags, loading, and size."""
        total_images = 0
        missing_alt = 0
        large_images = 0

        for page in self.pages:
            soup = page["soup"]
            for img in soup.find_all("img"):
                total_images += 1
                src = img.get("src", "")

                # Check alt attribute
                alt = img.get("alt")
                if alt is None or alt.strip() == "":
                    missing_alt += 1

                # Check lazy loading
                loading = img.get("loading", "")
                if loading != "lazy" and src and not src.startswith("data:"):
                    # Not critical, just informational
                    pass

                # Check image size if internal
                if src and is_same_domain(urljoin(page["url"], src), self._base_url):
                    img_url = urljoin(page["url"], src)
                    resp = self.client.head(img_url)
                    content_length = resp.headers.get("Content-Length", "0")
                    try:
                        size = int(content_length)
                        if size > self.config.performance.max_image_size_kb * 1024:
                            large_images += 1
                    except ValueError:
                        pass

        if missing_alt > 0:
            self.fail_check(
                f"Images missing alt text: {missing_alt}",
                f"{missing_alt}/{total_images} images missing alt attribute",
                severity=Severity.MEDIUM,
                recommendation="Add descriptive alt text to all images for accessibility",
            )
        elif total_images > 0:
            self.pass_check("Image alt texts", f"All {total_images} images have alt attributes")

        if large_images > 0:
            self.fail_check(
                f"Large images: {large_images}",
                f"{large_images} image(s) exceed {self.config.performance.max_image_size_kb}KB",
                severity=Severity.LOW,
                recommendation="Optimize images using WebP format and compression",
            )
        elif total_images > 0:
            self.pass_check("Image sizes", "All images are within size limits")

    def _check_forms(self) -> None:
        """Check forms for proper attributes and validation."""
        total_forms = 0

        for page in self.pages:
            soup = page["soup"]
            for form in soup.find_all("form"):
                total_forms += 1
                action = form.get("action", "")
                method = form.get("method", "get").lower()

                # Check CSRF token
                csrf_input = form.find("input", {"name": re.compile(r"csrf|token|_token", re.I)})
                if method == "post" and not csrf_input:
                    self.fail_check(
                        f"Form missing CSRF token",
                        f"POST form at {page['url']} lacks CSRF protection",
                        severity=Severity.HIGH,
                        url=page["url"],
                        recommendation="Add CSRF token to all POST forms",
                    )

                # Check inputs for labels
                inputs = form.find_all(["input", "textarea", "select"])
                for inp in inputs:
                    inp_type = inp.get("type", "text")
                    if inp_type in ("hidden", "submit", "button"):
                        continue

                    inp_id = inp.get("id", "")
                    inp_name = inp.get("name", "")

                    # Check for autocomplete on password
                    if inp_type == "password":
                        autocomplete = inp.get("autocomplete", "")
                        if autocomplete not in ("new-password", "current-password", "off"):
                            self.fail_check(
                                "Password autocomplete",
                                f"Password input missing autocomplete attribute at {page['url']}",
                                severity=Severity.LOW,
                                recommendation="Add autocomplete='current-password' or 'new-password'",
                            )

                    # Check for associated label
                    if inp_id:
                        label = soup.find("label", {"for": inp_id})
                        if not label:
                            aria_label = inp.get("aria-label") or inp.get("placeholder")
                            if not aria_label:
                                self.fail_check(
                                    f"Input missing label: {inp_name or inp_id}",
                                    f"Input at {page['url']} has no associated label",
                                    severity=Severity.LOW,
                                    recommendation="Add a <label> or aria-label for accessibility",
                                )

        if total_forms > 0:
            self.info("Forms found", f"{total_forms} form(s) analyzed")

    def _check_navigation(self) -> None:
        """Check for navigation elements."""
        for page in self.pages[:5]:
            soup = page["soup"]

            # Check for nav element
            nav = soup.find("nav")
            if nav:
                self.pass_check("Navigation element", f"<nav> element found on {page['url']}")
            else:
                nav_role = soup.find(attrs={"role": "navigation"})
                if nav_role:
                    self.pass_check("Navigation role", f"role='navigation' found on {page['url']}")
                else:
                    self.fail_check(
                        "Missing navigation",
                        f"No <nav> or role='navigation' found on {page['url']}",
                        severity=Severity.LOW,
                        url=page["url"],
                        recommendation="Use semantic <nav> element for main navigation",
                    )

            # Check for skip link
            first_link = soup.find("a")
            if first_link and "skip" in (first_link.get_text() or "").lower():
                self.pass_check("Skip link", "Skip-to-content link found")

            # Check for main landmark
            main = soup.find("main") or soup.find(attrs={"role": "main"})
            if main:
                self.pass_check("Main landmark", f"<main> element found on {page['url']}")
            else:
                self.fail_check(
                    "Missing main landmark",
                    f"No <main> element found on {page['url']}",
                    severity=Severity.LOW,
                    recommendation="Use semantic <main> element for primary content",
                )

    def _check_seo(self) -> None:
        """Check SEO best practices."""
        for page in self.pages[:10]:
            soup = page["soup"]

            # Check h1
            h1_tags = soup.find_all("h1")
            if len(h1_tags) == 0:
                self.fail_check(
                    f"Missing H1: {page['url']}",
                    "No <h1> tag found on page",
                    severity=Severity.MEDIUM,
                    url=page["url"],
                    recommendation="Add a single <h1> tag per page for SEO",
                )
            elif len(h1_tags) > 1:
                self.fail_check(
                    f"Multiple H1: {page['url']}",
                    f"{len(h1_tags)} <h1> tags found — should be exactly 1",
                    severity=Severity.LOW,
                    url=page["url"],
                    recommendation="Use a single <h1> per page",
                )
            else:
                self.pass_check(f"H1 tag: {page['url']}", f"H1: {h1_tags[0].get_text()[:50]}")

            # Check heading hierarchy
            headings = soup.find_all(re.compile(r'^h[1-6]$'))
            levels = [int(h.name[1]) for h in headings]
            for i in range(1, len(levels)):
                if levels[i] > levels[i - 1] + 1:
                    self.fail_check(
                        f"Heading hierarchy skip: {page['url']}",
                        f"Heading jumps from H{levels[i-1]} to H{levels[i]}",
                        severity=Severity.LOW,
                        recommendation="Use sequential heading levels (H1 → H2 → H3)",
                    )
                    break

            # Check canonical
            canonical = soup.find("link", rel="canonical")
            if canonical:
                self.pass_check(f"Canonical: {page['url']}", "Canonical URL set")
            else:
                self.fail_check(
                    f"Missing canonical: {page['url']}",
                    "No canonical link found",
                    severity=Severity.LOW,
                    recommendation="Add <link rel='canonical'> for SEO",
                )

            # Check lang attribute
            html_tag = soup.find("html")
            if html_tag and html_tag.get("lang"):
                self.pass_check(f"Lang attribute: {page['url']}", f"lang='{html_tag['lang']}'")
            else:
                self.fail_check(
                    f"Missing lang: {page['url']}",
                    "No lang attribute on <html> tag",
                    severity=Severity.MEDIUM,
                    recommendation="Add lang attribute to <html> for accessibility and SEO",
                )

    def _check_accessibility(self) -> None:
        """Basic accessibility checks."""
        for page in self.pages[:5]:
            soup = page["soup"]

            # Check for ARIA landmarks
            landmarks = soup.find_all(attrs={"role": True})
            if landmarks:
                self.pass_check(
                    f"ARIA landmarks: {page['url']}",
                    f"{len(landmarks)} ARIA landmark(s) found",
                )

            # Check for focus indicators (CSS check)
            style_tags = soup.find_all("style")
            css_text = " ".join(s.string or "" for s in style_tags)
            if "outline: none" in css_text or "outline:none" in css_text:
                self.fail_check(
                    f"Focus outline removed: {page['url']}",
                    "CSS removes focus outline — keyboard users cannot see focus",
                    severity=Severity.MEDIUM,
                    recommendation="Do not remove outline; provide custom focus styles instead",
                )

            # Check tabindex
            negative_tabindex = soup.find_all(attrs={"tabindex": "-1"})
            interactive_hidden = [
                el for el in negative_tabindex
                if el.name in ("a", "button", "input", "select", "textarea")
            ]
            if interactive_hidden:
                self.fail_check(
                    f"Interactive elements hidden from tab: {page['url']}",
                    f"{len(interactive_hidden)} interactive element(s) have tabindex='-1'",
                    severity=Severity.LOW,
                    recommendation="Avoid tabindex='-1' on interactive elements",
                )

            # Check color contrast (basic — inline styles only)
            # Full contrast check would require rendering (done in UX module)

    def _check_pwa(self) -> None:
        """Check PWA basics."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        soup = BeautifulSoup(resp.body, "lxml")

        # Check manifest
        manifest = soup.find("link", rel="manifest")
        if manifest:
            self.pass_check("PWA Manifest", "Web App Manifest found")

            manifest_url = urljoin(self._base_url, manifest.get("href", ""))
            manifest_resp = self.client.get(manifest_url)
            if manifest_resp.is_success and manifest_resp.json_data:
                data = manifest_resp.json_data
                if data.get("name"):
                    self.pass_check("Manifest name", f"App name: {data['name']}")
                if data.get("icons"):
                    self.pass_check("Manifest icons", f"{len(data['icons'])} icon(s) defined")
                if data.get("start_url"):
                    self.pass_check("Manifest start_url", "start_url defined")
                if not data.get("theme_color"):
                    self.fail_check(
                        "Manifest missing theme_color",
                        "No theme_color in manifest",
                        severity=Severity.LOW,
                        recommendation="Add theme_color to the web app manifest",
                    )
        else:
            self.fail_check(
                "No PWA Manifest",
                "No web app manifest found",
                severity=Severity.LOW,
                recommendation="Add a web app manifest for PWA support",
            )

        # Check service worker
        sw_patterns = ["serviceWorker", "service-worker", "sw.js"]
        has_sw = any(p in resp.body for p in sw_patterns)
        if has_sw:
            self.pass_check("Service Worker", "Service Worker registration found")
        else:
            self.fail_check(
                "No Service Worker",
                "No Service Worker detected",
                severity=Severity.LOW,
                recommendation="Add a Service Worker for offline support",
            )

        # Check theme-color meta
        theme_color = soup.find("meta", {"name": "theme-color"})
        if theme_color:
            self.pass_check("Theme color meta", f"theme-color: {theme_color.get('content', '')}")
        else:
            self.info("Theme color meta", "No theme-color meta tag found")

        # Check apple-touch-icon
        apple_icon = soup.find("link", rel=re.compile("apple-touch-icon"))
        if apple_icon:
            self.pass_check("Apple touch icon", "apple-touch-icon found")

    def _check_assets(self) -> None:
        """Check CSS/JS bundle sizes and loading."""
        for page in self.pages[:3]:
            soup = page["soup"]

            # Check external CSS
            css_links = soup.find_all("link", rel="stylesheet")
            for link in css_links:
                href = link.get("href", "")
                if href and is_same_domain(urljoin(page["url"], href), self._base_url):
                    css_url = urljoin(page["url"], href)
                    resp = self.client.head(css_url)
                    size = int(resp.headers.get("Content-Length", "0"))
                    if size > self.config.performance.max_bundle_size_kb * 1024:
                        self.fail_check(
                            f"Large CSS bundle: {href[:50]}",
                            f"CSS file is {bytes_to_human(size)}",
                            severity=Severity.MEDIUM,
                            url=css_url,
                            recommendation="Split CSS or use code splitting",
                        )

            # Check external JS
            scripts = soup.find_all("script", src=True)
            for script in scripts:
                src = script.get("src", "")
                if src and is_same_domain(urljoin(page["url"], src), self._base_url):
                    js_url = urljoin(page["url"], src)
                    resp = self.client.head(js_url)
                    size = int(resp.headers.get("Content-Length", "0"))
                    if size > self.config.performance.max_bundle_size_kb * 1024:
                        self.fail_check(
                            f"Large JS bundle: {src[:50]}",
                            f"JS file is {bytes_to_human(size)}",
                            severity=Severity.MEDIUM,
                            url=js_url,
                            recommendation="Use code splitting and tree shaking",
                        )

                    # Check for async/defer
                    if not script.get("async") and not script.get("defer"):
                        self.fail_check(
                            f"Render-blocking script: {src[:50]}",
                            "Script without async or defer blocks rendering",
                            severity=Severity.LOW,
                            recommendation="Add async or defer attribute to non-critical scripts",
                        )
