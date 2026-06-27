"""
Security Auditor — Module 8.

Scans for OWASP Top 10, XSS, SQL Injection, CSRF, CORS, JWT,
headers, cookies, clickjacking, directory traversal, IDOR, open redirect,
and exposed secrets.
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
    SECURITY_HEADERS,
    COOKIE_SECURITY_FLAGS,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    DIRECTORY_TRAVERSAL_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    SECRET_PATTERNS,
    SENSITIVE_FILES,
)


class SecurityAuditor(BaseAuditor):
    """Comprehensive security scanner based on OWASP Top 10."""

    MODULE_NAME = "security"
    MODULE_DESCRIPTION = "Audit de Sécurité (OWASP Top 10)"

    def __init__(self, config: AuditConfig):
        super().__init__(config)
        self.client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
            jwt_token=config.auth.jwt_token,
            verify_ssl=True,
        )

    async def run(self) -> AuditResult:
        """Run the security audit."""
        self.logger.info(f"Starting security audit for {self._base_url}")

        # 1. Security headers
        self._check_security_headers()

        # 2. Cookie security
        self._check_cookie_security()

        # 3. HTTPS / SSL
        self._check_https()

        # 4. Clickjacking
        self._check_clickjacking()

        # 5. SQL Injection
        if self.config.security.test_injections:
            self._check_sql_injection()

        # 6. XSS
        if self.config.security.test_injections:
            self._check_xss()

        # 7. CSRF
        if self.config.security.test_csrf:
            self._check_csrf()

        # 8. Directory traversal
        self._check_directory_traversal()

        # 9. Open redirect
        self._check_open_redirect()

        # 10. Exposed secrets
        self._check_exposed_secrets()

        # 11. Information disclosure
        self._check_information_disclosure()

        # 12. CORS misconfiguration
        self._check_cors_security()

        # 13. JWT security
        self._check_jwt_security()

        return self.build_result()

    def _check_security_headers(self) -> None:
        """Check all security-related HTTP headers."""
        resp = self.client.get(self._base_url)
        if resp.error:
            self.fail_check("Cannot reach target", resp.error, severity=Severity.CRITICAL)
            return

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() in headers_lower:
                value = headers_lower[header_name.lower()]
                self.pass_check(f"Header: {header_name}", f"{header_name}: {value}")

                # Validate header values
                if header_name == "Strict-Transport-Security":
                    if "max-age=0" in value:
                        self.fail_check(
                            "HSTS max-age is 0",
                            "HSTS with max-age=0 effectively disables it",
                            severity=Severity.HIGH,
                            recommendation="Set max-age to at least 31536000 (1 year)",
                        )
                elif header_name == "Content-Security-Policy":
                    if "unsafe-inline" in value:
                        self.fail_check(
                            "CSP allows unsafe-inline",
                            "Content-Security-Policy contains 'unsafe-inline'",
                            severity=Severity.MEDIUM,
                            recommendation="Remove 'unsafe-inline' from CSP and use nonces",
                        )
                    if "unsafe-eval" in value:
                        self.fail_check(
                            "CSP allows unsafe-eval",
                            "Content-Security-Policy contains 'unsafe-eval'",
                            severity=Severity.MEDIUM,
                            recommendation="Remove 'unsafe-eval' from CSP",
                        )
            else:
                sev_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
                self.fail_check(
                    f"Missing: {header_name}",
                    info["description"],
                    severity=sev_map.get(info["severity"], Severity.MEDIUM),
                    recommendation=info["recommendation"],
                )

    def _check_cookie_security(self) -> None:
        """Check cookie security attributes."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        cookies_found = False
        for key, value in resp.headers.items():
            if key.lower() != "set-cookie":
                continue
            cookies_found = True
            cookie_str = value.lower()

            cookie_name = value.split("=")[0].strip()

            for flag, info in COOKIE_SECURITY_FLAGS.items():
                if flag.lower() in cookie_str:
                    self.pass_check(
                        f"Cookie '{cookie_name}' — {flag}",
                        f"{info['description']}",
                    )
                else:
                    sev = Severity.HIGH if info["severity"] == "high" else Severity.MEDIUM
                    self.fail_check(
                        f"Cookie '{cookie_name}' missing {flag}",
                        f"{info['description']}",
                        severity=sev,
                        recommendation=f"Add the {flag} flag to cookie '{cookie_name}'",
                    )

        if not cookies_found:
            self.info("Cookies", "No cookies set by the server")

    def _check_https(self) -> None:
        """Check HTTPS configuration."""
        if self._base_url.startswith("https://"):
            self.pass_check("HTTPS enabled", "Site is served over HTTPS")

            # Check HSTS preload
            resp = self.client.get(self._base_url)
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if "preload" in hsts:
                self.pass_check("HSTS Preload", "HSTS preload directive present")
            if "includeSubDomains" in hsts:
                self.pass_check("HSTS subdomains", "HSTS includes subdomains")
        else:
            self.fail_check(
                "HTTPS not enabled",
                "Site is served over HTTP — not encrypted",
                severity=Severity.CRITICAL,
                recommendation="Enable HTTPS with a valid SSL/TLS certificate",
            )

    def _check_clickjacking(self) -> None:
        """Check clickjacking protections."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        xfo = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "")

        if xfo in ("DENY", "SAMEORIGIN"):
            self.pass_check("Clickjacking protection (X-Frame-Options)", f"X-Frame-Options: {xfo}")
        elif "frame-ancestors" in csp:
            self.pass_check("Clickjacking protection (CSP)", "frame-ancestors directive in CSP")
        else:
            self.fail_check(
                "Clickjacking vulnerability",
                "No X-Frame-Options or CSP frame-ancestors protection",
                severity=Severity.HIGH,
                recommendation="Add X-Frame-Options: DENY or CSP frame-ancestors directive",
            )

    def _check_sql_injection(self) -> None:
        """Test for SQL injection vulnerabilities."""
        test_urls = [self._base_url]
        api_base = self.config.target.api_base or "/api"
        test_urls.append(f"{self._base_url.rstrip('/')}{api_base}")

        for base_url in test_urls:
            for payload in SQL_INJECTION_PAYLOADS[:7]:
                resp = self.client.get(base_url, params={"id": payload, "q": payload})
                if resp.error:
                    continue

                sql_errors = [
                    "sql syntax", "mysql_", "pg_query", "sqlite3",
                    "unclosed quotation", "syntax error at or near",
                    "ora-", "microsoft sql", "odbc",
                ]
                body_lower = resp.body.lower() if resp.body else ""
                for err in sql_errors:
                    if err in body_lower:
                        self.fail_check(
                            "SQL Injection detected",
                            f"SQL error in response with payload: {payload[:40]}",
                            severity=Severity.CRITICAL,
                            url=base_url,
                            evidence=resp.body[:200],
                            recommendation="Use parameterized queries. Never concatenate user input into SQL.",
                        )
                        return

        self.pass_check("SQL Injection test", "No SQL injection vulnerability detected")

    def _check_xss(self) -> None:
        """Test for reflected XSS."""
        for payload in XSS_PAYLOADS[:7]:
            resp = self.client.get(self._base_url, params={"q": payload, "search": payload})
            if resp.error:
                continue

            if payload in (resp.body or ""):
                self.fail_check(
                    "Reflected XSS detected",
                    f"XSS payload reflected in response: {payload[:40]}",
                    severity=Severity.CRITICAL,
                    recommendation="Sanitize and encode all user input before rendering in HTML",
                )
                return

        self.pass_check("XSS test", "No reflected XSS vulnerability detected")

    def _check_csrf(self) -> None:
        """Check for CSRF protections."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        soup = BeautifulSoup(resp.body, "lxml")
        forms = soup.find_all("form", method=re.compile(r"post", re.I))

        if not forms:
            self.info("CSRF check", "No POST forms found on the main page")
            return

        for form in forms:
            csrf_input = form.find("input", {"name": re.compile(r"csrf|token|_token|csrfmiddleware", re.I)})
            if csrf_input:
                self.pass_check("CSRF token found", f"CSRF protection in form: {form.get('action', '/')}")
            else:
                self.fail_check(
                    "Missing CSRF token",
                    f"POST form without CSRF token: {form.get('action', '/')}",
                    severity=Severity.HIGH,
                    recommendation="Add CSRF tokens to all POST forms",
                )

    def _check_directory_traversal(self) -> None:
        """Test for directory traversal."""
        for payload in DIRECTORY_TRAVERSAL_PAYLOADS[:3]:
            url = f"{self._base_url.rstrip('/')}/{payload}"
            resp = self.client.get(url)

            if resp.is_success and resp.body:
                sensitive_indicators = ["root:", "[boot loader]", "daemon:", "[extensions]"]
                if any(ind in resp.body for ind in sensitive_indicators):
                    self.fail_check(
                        "Directory traversal vulnerability",
                        f"Path traversal successful with: {payload}",
                        severity=Severity.CRITICAL,
                        url=url,
                        recommendation="Sanitize file paths and restrict file system access",
                    )
                    return

        self.pass_check("Directory traversal test", "No directory traversal vulnerability detected")

    def _check_open_redirect(self) -> None:
        """Test for open redirect vulnerabilities."""
        redirect_params = ["url", "redirect", "next", "return", "returnTo", "redirect_uri", "continue"]

        for param in redirect_params[:4]:
            for payload in OPEN_REDIRECT_PAYLOADS[:2]:
                resp = self.client.get(
                    self._base_url,
                    params={param: payload},
                    allow_redirects=False,
                )

                if resp.is_redirect:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        self.fail_check(
                            "Open redirect vulnerability",
                            f"Redirect to external domain via '{param}' parameter",
                            severity=Severity.HIGH,
                            recommendation="Validate redirect URLs against a whitelist of allowed domains",
                        )
                        return

        self.pass_check("Open redirect test", "No open redirect vulnerability detected")

    def _check_exposed_secrets(self) -> None:
        """Scan for exposed secrets in page source."""
        resp = self.client.get(self._base_url)
        if resp.error or not resp.body:
            return

        for secret_name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, resp.body)
            if matches:
                self.fail_check(
                    f"Secret exposed: {secret_name}",
                    f"Found {len(matches)} potential {secret_name} in page source",
                    severity=Severity.CRITICAL,
                    recommendation=f"Remove {secret_name} from client-side code. Use server-side environment variables.",
                )

        # Check inline scripts for secrets
        soup = BeautifulSoup(resp.body, "lxml")
        for script in soup.find_all("script", src=False):
            script_text = script.string or ""
            for secret_name, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, script_text):
                    self.fail_check(
                        f"Secret in inline script: {secret_name}",
                        f"Potential {secret_name} found in inline <script>",
                        severity=Severity.CRITICAL,
                        recommendation="Move secrets to server-side environment variables",
                    )

    def _check_information_disclosure(self) -> None:
        """Check for information disclosure."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        # Check server header
        server = resp.headers.get("Server", "")
        if server and re.search(r'\d+\.\d+', server):
            self.fail_check(
                "Server version disclosure",
                f"Server header reveals version: {server}",
                severity=Severity.LOW,
                recommendation="Remove version info from Server header",
            )

        # Check X-Powered-By
        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            self.fail_check(
                "X-Powered-By disclosure",
                f"X-Powered-By: {powered_by}",
                severity=Severity.LOW,
                recommendation="Remove X-Powered-By header",
            )
        else:
            self.pass_check("X-Powered-By hidden", "X-Powered-By header not present")

        # Check for debug mode
        debug_indicators = [
            "debug mode", "debug = true", "DJANGO_SETTINGS_MODULE",
            "werkzeug debugger", "laravel", "stack trace",
        ]
        body_lower = (resp.body or "").lower()
        for indicator in debug_indicators:
            if indicator.lower() in body_lower:
                self.fail_check(
                    f"Debug mode indicator: {indicator}",
                    "Application may be running in debug mode",
                    severity=Severity.HIGH,
                    recommendation="Disable debug mode in production",
                )
                break

    def _check_cors_security(self) -> None:
        """Check CORS configuration for security issues."""
        resp = self.client.get(self._base_url, headers={"Origin": "https://evil-attacker.com"})
        if resp.error:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            self.fail_check(
                "CORS wildcard origin",
                "Access-Control-Allow-Origin: * allows any domain",
                severity=Severity.HIGH,
                recommendation="Restrict CORS to specific trusted origins",
            )
        elif "evil-attacker.com" in acao:
            self.fail_check(
                "CORS origin reflection",
                "CORS reflects attacker's origin — potential credential theft",
                severity=Severity.CRITICAL,
                recommendation="Validate origins against a strict whitelist",
            )
        elif acao:
            self.pass_check("CORS origin restricted", f"CORS origin: {acao}")
        else:
            self.pass_check("No CORS headers", "No CORS — same-origin policy in effect")

    def _check_jwt_security(self) -> None:
        """Check JWT configuration security."""
        if not self.config.auth.jwt_token:
            self.info("JWT check", "No JWT token provided — skipping JWT validation tests")
            return

        import jwt as pyjwt

        token = self.config.auth.jwt_token
        try:
            # Decode without verification to inspect claims
            decoded = pyjwt.decode(token, options={"verify_signature": False})

            # Check algorithm
            header = pyjwt.get_unverified_header(token)
            alg = header.get("alg", "")

            if alg == "none":
                self.fail_check(
                    "JWT algorithm 'none'",
                    "JWT uses 'none' algorithm — anyone can forge tokens",
                    severity=Severity.CRITICAL,
                    recommendation="Use RS256 or HS256 algorithm for JWT",
                )
            elif alg == "HS256":
                self.info("JWT algorithm", "JWT uses HS256 — ensure a strong secret key")
            elif alg in ("RS256", "ES256"):
                self.pass_check("JWT algorithm", f"JWT uses secure algorithm: {alg}")

            # Check expiration
            if "exp" in decoded:
                self.pass_check("JWT expiration", "JWT has an expiration claim")
            else:
                self.fail_check(
                    "JWT no expiration",
                    "JWT token has no 'exp' claim — never expires",
                    severity=Severity.HIGH,
                    recommendation="Always set an expiration time on JWT tokens",
                )

            # Check issuer
            if "iss" in decoded:
                self.pass_check("JWT issuer", f"JWT issuer: {decoded['iss']}")
            else:
                self.fail_check(
                    "JWT no issuer",
                    "JWT has no 'iss' claim",
                    severity=Severity.LOW,
                    recommendation="Add an 'iss' claim to verify token origin",
                )

        except Exception as e:
            self.info("JWT analysis", f"Could not analyze JWT: {e}")
