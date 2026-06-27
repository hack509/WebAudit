"""
Backend Auditor — Module 2.

Tests routes, HTTP codes, timeouts, headers, CORS, auth, error handling,
and other backend-related aspects.
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
from utils.constants import SECURITY_HEADERS
from utils.helpers import normalize_url, is_same_domain


class BackendAuditor(BaseAuditor):
    """Audits backend routes, headers, auth, CORS, and error handling."""

    MODULE_NAME = "backend"
    MODULE_DESCRIPTION = "Audit du Backend"

    def __init__(self, config: AuditConfig):
        super().__init__(config)
        self.client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
            jwt_token=config.auth.jwt_token,
        )
        self.discovered_routes: list[str] = []

    async def run(self) -> AuditResult:
        """Run the backend audit."""
        self.logger.info(f"Starting backend audit for {self._base_url}")

        # 1. Crawl and discover routes
        self._discover_routes()

        # 2. Test routes
        self._test_routes()

        # 3. Check headers
        self._check_security_headers()

        # 4. Check CORS
        self._check_cors()

        # 5. Check error handling
        self._check_error_handling()

        # 6. Check rate limiting
        self._check_rate_limiting()

        # 7. Check redirects
        self._check_redirects()

        # 8. Check compression
        self._check_compression()

        return self.build_result()

    def _discover_routes(self) -> None:
        """Crawl the site to discover routes."""
        visited: set[str] = set()
        to_visit: list[str] = [self._base_url]
        max_pages = min(self.config.crawl.max_pages, 50)

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            normalized = normalize_url(url)

            if normalized in visited:
                continue
            visited.add(normalized)

            resp = self.client.get(url)
            if resp.error or resp.status_code >= 400:
                continue

            # Parse links
            try:
                soup = BeautifulSoup(resp.body, "lxml")
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    if href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
                        continue

                    full_url = urljoin(url, href)
                    if is_same_domain(full_url, self._base_url) and normalize_url(full_url) not in visited:
                        to_visit.append(full_url)

                # Also check for form actions
                for form in soup.find_all("form", action=True):
                    action = urljoin(url, form["action"])
                    if is_same_domain(action, self._base_url):
                        visited.add(normalize_url(action))
            except Exception as e:
                self.logger.debug(f"Error parsing {url}: {e}")

        self.discovered_routes = list(visited)
        self.info(
            "Routes discovered",
            f"{len(self.discovered_routes)} route(s) discovered",
        )

    def _test_routes(self) -> None:
        """Test all discovered routes for HTTP status codes and response times."""
        for url in self.discovered_routes[:30]:  # Limit testing
            resp = self.client.get(url)

            if resp.error:
                self.fail_check(
                    f"Route error: {url}",
                    f"Error accessing {url}: {resp.error}",
                    severity=Severity.HIGH,
                    url=url,
                )
                continue

            # Check status code
            if resp.is_success:
                # Check response time
                if resp.elapsed_ms > self.config.performance.max_response_time_ms:
                    self.fail_check(
                        f"Slow response: {url}",
                        f"Response time: {resp.elapsed_ms:.0f}ms (threshold: {self.config.performance.max_response_time_ms}ms)",
                        severity=Severity.MEDIUM,
                        url=url,
                        recommendation="Optimize server response time",
                    )
                else:
                    self.pass_check(
                        f"Route OK: {url}",
                        f"HTTP {resp.status_code} in {resp.elapsed_ms:.0f}ms",
                    )
            elif resp.is_server_error:
                self.fail_check(
                    f"Server error: {url}",
                    f"HTTP {resp.status_code} — server error",
                    severity=Severity.HIGH,
                    url=url,
                    recommendation="Fix the server-side error",
                )
            elif resp.status_code == 404:
                self.fail_check(
                    f"Not found: {url}",
                    f"HTTP 404 — page not found",
                    severity=Severity.LOW,
                    url=url,
                )

            # Check for stack trace exposure
            if resp.body and any(
                pattern in resp.body.lower()
                for pattern in ["traceback", "stack trace", "exception", "error in", "at line"]
            ):
                if resp.status_code >= 400:
                    self.fail_check(
                        f"Stack trace exposed: {url}",
                        "Error page may expose internal stack trace information",
                        severity=Severity.HIGH,
                        url=url,
                        recommendation="Configure custom error pages that don't expose internal details",
                    )

    def _check_security_headers(self) -> None:
        """Check for security-related response headers."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() in headers_lower:
                self.pass_check(
                    f"Security header: {header_name}",
                    f"{header_name}: {headers_lower[header_name.lower()]}",
                )
            else:
                severity_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
                self.fail_check(
                    f"Missing security header: {header_name}",
                    info["description"],
                    severity=severity_map.get(info["severity"], Severity.MEDIUM),
                    recommendation=info["recommendation"],
                )

    def _check_cors(self) -> None:
        """Check CORS configuration."""
        resp = self.client.options(self._base_url, headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
        })

        if resp.error:
            self.info("CORS check", "Could not perform CORS preflight check")
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            self.fail_check(
                "CORS: Wildcard origin",
                "Access-Control-Allow-Origin is set to '*' — allows any origin",
                severity=Severity.HIGH,
                recommendation="Restrict CORS to specific trusted domains",
            )
        elif "evil.com" in acao:
            self.fail_check(
                "CORS: Reflects origin",
                "CORS reflects the attacker's origin — vulnerable to CSRF-like attacks",
                severity=Severity.CRITICAL,
                recommendation="Validate and whitelist allowed origins",
            )
        elif acao:
            self.pass_check("CORS configuration", f"Access-Control-Allow-Origin: {acao}")
        else:
            self.pass_check("CORS configuration", "No CORS headers — same-origin only")

        # Check credentials
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acac.lower() == "true" and acao == "*":
            self.fail_check(
                "CORS: Credentials with wildcard",
                "Allow-Credentials with wildcard origin is a security risk",
                severity=Severity.CRITICAL,
                recommendation="Do not combine Allow-Credentials: true with wildcard origin",
            )

    def _check_error_handling(self) -> None:
        """Test error handling with invalid requests."""
        test_paths = [
            "/nonexistent-page-12345",
            "/%00",
            "/../../etc/passwd",
            "/api/undefined",
        ]

        for path in test_paths:
            url = f"{self._base_url.rstrip('/')}{path}"
            resp = self.client.get(url)

            if resp.status_code == 200 and path == "/../../etc/passwd":
                self.fail_check(
                    "Directory traversal possible",
                    f"Path traversal request returned 200: {path}",
                    severity=Severity.CRITICAL,
                    url=url,
                    recommendation="Sanitize path parameters and block directory traversal",
                )
            elif resp.is_server_error:
                self.fail_check(
                    f"Server error on invalid path: {path}",
                    f"HTTP {resp.status_code} instead of 404 for invalid path",
                    severity=Severity.MEDIUM,
                    url=url,
                    recommendation="Return proper 404 responses for invalid paths",
                )
            else:
                self.pass_check(
                    f"Error handling: {path}",
                    f"Properly handled with HTTP {resp.status_code}",
                )

    def _check_rate_limiting(self) -> None:
        """Test if rate limiting is in place."""
        url = self._base_url
        rate_limited = False

        for i in range(20):
            resp = self.client.get(url)
            if resp.status_code == 429:
                rate_limited = True
                break

        if rate_limited:
            self.pass_check(
                "Rate limiting",
                "Rate limiting is active (HTTP 429 after repeated requests)",
            )
        else:
            self.fail_check(
                "No rate limiting detected",
                "No rate limiting detected after 20 rapid requests",
                severity=Severity.MEDIUM,
                recommendation="Implement rate limiting to prevent abuse and DDoS attacks",
            )

    def _check_redirects(self) -> None:
        """Check HTTP to HTTPS redirect."""
        if self._base_url.startswith("https://"):
            http_url = self._base_url.replace("https://", "http://", 1)
            resp = self.client.get(http_url, allow_redirects=False)

            if resp.is_redirect:
                location = resp.headers.get("Location", "")
                if location.startswith("https://"):
                    self.pass_check("HTTP to HTTPS redirect", "HTTP redirects to HTTPS")
                else:
                    self.fail_check(
                        "HTTP redirect not to HTTPS",
                        f"HTTP redirects to {location} instead of HTTPS",
                        severity=Severity.MEDIUM,
                        recommendation="Redirect HTTP traffic to HTTPS",
                    )

    def _check_compression(self) -> None:
        """Check if response compression is enabled."""
        resp = self.client.get(self._base_url, headers={"Accept-Encoding": "gzip, deflate, br"})

        encoding = resp.headers.get("Content-Encoding", "")
        if encoding:
            self.pass_check("Response compression", f"Compression enabled: {encoding}")
        else:
            self.fail_check(
                "No response compression",
                "Server does not compress responses",
                severity=Severity.LOW,
                recommendation="Enable gzip or brotli compression on the server",
            )
