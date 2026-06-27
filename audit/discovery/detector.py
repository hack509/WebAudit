"""
Discovery Auditor — Module 1.

Automatically detects technologies, frameworks, servers, and versions
used by the target application.
"""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.http_client import HttpClient
from utils.constants import (
    FRONTEND_FRAMEWORKS,
    BACKEND_FRAMEWORKS,
    SENSITIVE_FILES,
)


class DiscoveryAuditor(BaseAuditor):
    """Detects technologies, frameworks, servers, and versions."""

    MODULE_NAME = "discovery"
    MODULE_DESCRIPTION = "Découverte automatique des technologies"

    def __init__(self, config: AuditConfig):
        super().__init__(config)
        self.client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
            jwt_token=config.auth.jwt_token,
        )
        self.technologies: dict[str, Any] = {
            "frontend_framework": None,
            "backend_framework": None,
            "server": None,
            "languages": [],
            "libraries": [],
            "cdn": [],
            "analytics": [],
            "cms": None,
            "headers": {},
            "cookies": [],
            "meta_tags": {},
        }

    async def run(self) -> AuditResult:
        """Run the discovery audit."""
        self.logger.info(f"Scanning {self._base_url} for technologies...")

        response = self.client.get(self._base_url)

        if response.error:
            self.fail_check(
                "Connection to target",
                f"Cannot connect to {self._base_url}: {response.error}",
                severity=Severity.CRITICAL,
            )
            return self.build_result()

        self.pass_check(
            "Connection to target",
            f"Successfully connected to {self._base_url} (HTTP {response.status_code})",
        )

        # Analyze response
        self._detect_server(response.headers)
        self._detect_headers(response.headers)
        self._detect_cookies(response.headers)

        soup = BeautifulSoup(response.body, "lxml")
        self._detect_frontend_framework(response.body, soup, response.headers)
        self._detect_backend_framework(response.headers, response.body)
        self._detect_meta_tags(soup)
        self._detect_scripts(soup)
        self._detect_stylesheets(soup)
        self._check_sensitive_files()
        self._detect_versions(response.body, response.headers)

        # Log summary
        self.info(
            "Technologies Detected Summary",
            self._build_tech_summary(),
        )

        return self.build_result()

    def _detect_server(self, headers: dict[str, str]) -> None:
        """Detect web server from headers."""
        server = headers.get("Server") or headers.get("server", "")
        if server:
            self.technologies["server"] = server
            self.info("Server detected", f"Server: {server}")

            # Check for version exposure
            if re.search(r'\d+\.\d+', server):
                self.fail_check(
                    "Server version exposed",
                    f"Server header exposes version: {server}",
                    severity=Severity.LOW,
                    recommendation="Remove version information from the Server header",
                )
            else:
                self.pass_check("Server version not exposed", "Server header does not expose version")
        else:
            self.info("Server header", "Server header not present")

        # X-Powered-By
        powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by", "")
        if powered_by:
            self.technologies["languages"].append(powered_by)
            self.fail_check(
                "X-Powered-By exposed",
                f"X-Powered-By header exposes: {powered_by}",
                severity=Severity.LOW,
                recommendation="Remove X-Powered-By header to reduce information leakage",
            )

    def _detect_headers(self, headers: dict[str, str]) -> None:
        """Record all response headers."""
        self.technologies["headers"] = dict(headers)

    def _detect_cookies(self, headers: dict[str, str]) -> None:
        """Detect cookies from Set-Cookie headers."""
        cookies = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                cookies.append(value)
        self.technologies["cookies"] = cookies
        if cookies:
            self.info("Cookies detected", f"{len(cookies)} cookie(s) set by the server")

    def _detect_frontend_framework(
        self, body: str, soup: BeautifulSoup, headers: dict[str, str]
    ) -> None:
        """Detect frontend framework from HTML content."""
        detected = []

        for framework, signatures in FRONTEND_FRAMEWORKS.items():
            # Check patterns in body
            for pattern in signatures.get("patterns", []):
                if pattern.lower() in body.lower():
                    detected.append(framework)
                    break

            # Check scripts
            if framework not in detected:
                for script in signatures.get("scripts", []):
                    script_tags = soup.find_all("script", src=True)
                    for tag in script_tags:
                        if script.lower() in tag["src"].lower():
                            detected.append(framework)
                            break

            # Check headers
            if framework not in detected:
                for header_check in signatures.get("headers", []):
                    h_name, h_value = header_check.split(": ", 1)
                    actual = headers.get(h_name) or headers.get(h_name.lower(), "")
                    if h_value.lower() in actual.lower():
                        detected.append(framework)

        if detected:
            self.technologies["frontend_framework"] = detected[0]
            self.pass_check(
                "Frontend framework detected",
                f"Frontend framework(s): {', '.join(detected)}",
            )
        else:
            self.info("Frontend framework", "No known frontend framework detected")

    def _detect_backend_framework(self, headers: dict[str, str], body: str) -> None:
        """Detect backend framework from response."""
        detected = []

        for framework, signatures in BACKEND_FRAMEWORKS.items():
            # Check headers
            for header_check in signatures.get("headers", []):
                parts = header_check.split(": ", 1)
                if len(parts) == 2:
                    h_name, h_value = parts
                    actual = headers.get(h_name) or headers.get(h_name.lower(), "")
                    if h_value.lower() in actual.lower():
                        detected.append(framework)

            # Check cookies
            if framework not in detected:
                all_cookies = " ".join(str(v) for k, v in headers.items() if k.lower() == "set-cookie")
                for cookie_name in signatures.get("cookies", []):
                    if cookie_name.lower() in all_cookies.lower():
                        detected.append(framework)
                        break

            # Check patterns in body
            if framework not in detected:
                for pattern in signatures.get("patterns", []):
                    if pattern.lower() in body.lower():
                        detected.append(framework)
                        break

        if detected:
            self.technologies["backend_framework"] = detected[0]
            self.pass_check(
                "Backend framework detected",
                f"Backend framework(s): {', '.join(detected)}",
            )
        else:
            self.info("Backend framework", "No known backend framework detected")

    def _detect_meta_tags(self, soup: BeautifulSoup) -> None:
        """Extract meta tags for technology detection."""
        meta_tags = {}
        for meta in soup.find_all("meta"):
            name = meta.get("name", meta.get("property", ""))
            content = meta.get("content", "")
            if name and content:
                meta_tags[name] = content

        self.technologies["meta_tags"] = meta_tags

        # Check generator
        generator = meta_tags.get("generator", "")
        if generator:
            self.technologies["cms"] = generator
            self.info("CMS/Generator detected", f"Generator: {generator}")

        # Check viewport (mobile readiness)
        viewport = meta_tags.get("viewport", "")
        if viewport:
            self.pass_check("Viewport meta tag", f"Viewport: {viewport}")
        else:
            self.fail_check(
                "Viewport meta tag missing",
                "No viewport meta tag found — site may not be mobile-friendly",
                severity=Severity.MEDIUM,
                recommendation='Add <meta name="viewport" content="width=device-width, initial-scale=1">',
            )

        # Check description
        description = meta_tags.get("description", "")
        if description:
            self.pass_check("Meta description", f"Description present ({len(description)} chars)")
        else:
            self.fail_check(
                "Meta description missing",
                "No meta description tag found",
                severity=Severity.LOW,
                recommendation="Add a meta description tag for SEO",
            )

        # Check title
        title = soup.find("title")
        if title and title.string:
            self.pass_check("Page title", f"Title: {title.string.strip()}")
        else:
            self.fail_check(
                "Page title missing",
                "No <title> tag found",
                severity=Severity.MEDIUM,
                recommendation="Add a descriptive <title> tag",
            )

    def _detect_scripts(self, soup: BeautifulSoup) -> None:
        """Detect external scripts and libraries."""
        scripts = soup.find_all("script", src=True)
        libraries = []
        cdns = []

        for script in scripts:
            src = script["src"]
            # Detect CDN
            if any(cdn in src for cdn in ["cdnjs", "jsdelivr", "unpkg", "cloudflare"]):
                cdns.append(src)
            libraries.append(src)

            # Detect analytics
            if "google-analytics" in src or "gtag" in src or "gtm" in src:
                self.technologies["analytics"].append("Google Analytics")
            elif "facebook" in src or "fbevents" in src:
                self.technologies["analytics"].append("Facebook Pixel")

        self.technologies["libraries"] = libraries
        self.technologies["cdn"] = cdns

        self.info(
            "External scripts",
            f"{len(scripts)} external script(s) found, {len(cdns)} from CDN",
        )

    def _detect_stylesheets(self, soup: BeautifulSoup) -> None:
        """Detect CSS frameworks and stylesheets."""
        links = soup.find_all("link", rel="stylesheet")

        for link in links:
            href = link.get("href", "")
            if "bootstrap" in href.lower():
                self.technologies["libraries"].append("Bootstrap")
            elif "tailwind" in href.lower():
                self.technologies["libraries"].append("Tailwind CSS")
            elif "bulma" in href.lower():
                self.technologies["libraries"].append("Bulma")
            elif "materialize" in href.lower():
                self.technologies["libraries"].append("Materialize")

        self.info("Stylesheets", f"{len(links)} external stylesheet(s) found")

    def _check_sensitive_files(self) -> None:
        """Check for exposed sensitive files."""
        exposed = []

        for path in SENSITIVE_FILES[:15]:  # Limit to avoid too many requests
            url = f"{self._base_url.rstrip('/')}{path}"
            resp = self.client.get(url)

            if resp.status_code == 200:
                exposed.append(path)
                severity = Severity.CRITICAL if path in ["/.env", "/.git/config", "/.aws/credentials"] else Severity.HIGH
                self.fail_check(
                    f"Sensitive file exposed: {path}",
                    f"The file {path} is publicly accessible",
                    severity=severity,
                    url=url,
                    recommendation=f"Block access to {path} in your server configuration",
                )
            else:
                self.pass_check(
                    f"Sensitive file not exposed: {path}",
                    f"{path} is not publicly accessible (HTTP {resp.status_code})",
                )

    def _detect_versions(self, body: str, headers: dict[str, str]) -> None:
        """Try to detect software versions."""
        # Check for version comments in HTML
        version_patterns = [
            (r'<!-- .*(v\d+\.\d+[\.\d]*).*-->', "HTML Comment Version"),
            (r'version["\s:=]+(\d+\.\d+[\.\d]*)', "Version String"),
        ]

        for pattern, label in version_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches[:3]:  # Limit
                self.info(f"{label} found", f"Version detected: {match}")

    def _build_tech_summary(self) -> str:
        """Build a human-readable technology summary."""
        parts = []
        if self.technologies["server"]:
            parts.append(f"Server: {self.technologies['server']}")
        if self.technologies["frontend_framework"]:
            parts.append(f"Frontend: {self.technologies['frontend_framework']}")
        if self.technologies["backend_framework"]:
            parts.append(f"Backend: {self.technologies['backend_framework']}")
        if self.technologies["cms"]:
            parts.append(f"CMS: {self.technologies['cms']}")
        if self.technologies["analytics"]:
            parts.append(f"Analytics: {', '.join(set(self.technologies['analytics']))}")

        libs = [l for l in self.technologies.get("libraries", []) if isinstance(l, str) and not l.startswith("http")]
        if libs:
            parts.append(f"Libraries: {', '.join(libs)}")

        return " | ".join(parts) if parts else "No technologies detected"

    def get_technologies(self) -> dict[str, Any]:
        """Return the detected technologies dict."""
        return self.technologies
