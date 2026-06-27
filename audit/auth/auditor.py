"""
Auth Auditor — Module 9.

Tests authentication flows: login, logout, registration, password reset,
session management, JWT, OAuth, roles, and permissions.
"""

from __future__ import annotations

from typing import Any, Optional

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.http_client import HttpClient


class AuthAuditor(BaseAuditor):
    """Audits authentication and authorization mechanisms."""

    MODULE_NAME = "auth"
    MODULE_DESCRIPTION = "Audit Authentification & Autorisation"

    def __init__(self, config: AuditConfig):
        super().__init__(config)
        self.client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
        )
        self.auth_client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
            jwt_token=config.auth.jwt_token,
        )

    async def run(self) -> AuditResult:
        """Run the authentication audit."""
        self.logger.info(f"Starting auth audit for {self._base_url}")

        # 1. Discover auth endpoints
        auth_endpoints = self._discover_auth_endpoints()

        # 2. Test login
        self._test_login(auth_endpoints)

        # 3. Test registration
        self._test_registration(auth_endpoints)

        # 4. Test password policy
        self._test_password_policy(auth_endpoints)

        # 5. Test session management
        self._test_session_management()

        # 6. Test brute force protection
        self._test_brute_force_protection(auth_endpoints)

        # 7. Test JWT if token provided
        if self.config.auth.jwt_token:
            self._test_jwt_security()

        # 8. Test OAuth endpoints
        self._test_oauth()

        # 9. Test protected routes
        self._test_protected_routes()

        # 10. Test logout
        self._test_logout(auth_endpoints)

        return self.build_result()

    def _discover_auth_endpoints(self) -> dict[str, Optional[str]]:
        """Discover authentication endpoints."""
        endpoints: dict[str, Optional[str]] = {
            "login": None,
            "register": None,
            "logout": None,
            "password_reset": None,
            "profile": None,
            "refresh_token": None,
        }

        paths_map = {
            "login": ["/login", "/auth/login", "/api/auth/login", "/api/login", "/signin", "/api/signin"],
            "register": ["/register", "/auth/register", "/api/auth/register", "/api/register", "/signup", "/api/signup"],
            "logout": ["/logout", "/auth/logout", "/api/auth/logout", "/api/logout", "/signout"],
            "password_reset": ["/forgot-password", "/auth/forgot-password", "/api/auth/forgot-password", "/password/reset"],
            "profile": ["/profile", "/api/profile", "/api/me", "/api/user", "/me"],
            "refresh_token": ["/auth/refresh", "/api/auth/refresh", "/api/token/refresh"],
        }

        for endpoint_type, paths in paths_map.items():
            for path in paths:
                url = f"{self._base_url.rstrip('/')}{path}"
                resp = self.client.get(url)
                if resp.status_code != 404 and not resp.error:
                    endpoints[endpoint_type] = url
                    self.info(f"Auth endpoint: {endpoint_type}", f"Found at {url}")
                    break

        found = sum(1 for v in endpoints.values() if v)
        self.info("Auth endpoints", f"{found} auth endpoint(s) discovered")

        return endpoints

    def _test_login(self, endpoints: dict) -> None:
        """Test login endpoint security."""
        login_url = endpoints.get("login")
        if not login_url:
            self.info("Login test", "No login endpoint found — skipping")
            return

        # Test empty credentials
        resp = self.client.post(login_url, json_data={"username": "", "password": ""})
        if resp.is_success:
            self.fail_check(
                "Login accepts empty credentials",
                "Login endpoint accepts empty username/password",
                severity=Severity.CRITICAL,
                url=login_url,
                recommendation="Validate all credential fields are non-empty",
            )
        else:
            self.pass_check("Login rejects empty credentials", f"HTTP {resp.status_code}")

        # Test SQL injection in login
        resp = self.client.post(login_url, json_data={
            "username": "admin' OR '1'='1",
            "password": "' OR '1'='1",
        })
        if resp.is_success:
            self.fail_check(
                "Login SQL injection",
                "Login may be vulnerable to SQL injection",
                severity=Severity.CRITICAL,
                url=login_url,
                recommendation="Use parameterized queries for authentication",
            )
        else:
            self.pass_check("Login SQL injection test", "Login rejected SQL injection payload")

        # Test with configured credentials
        if self.config.auth.username and self.config.auth.password:
            resp = self.client.post(login_url, json_data={
                "username": self.config.auth.username,
                "password": self.config.auth.password,
            })
            if resp.is_success:
                self.pass_check("Login with valid credentials", "Authentication successful")
            elif resp.status_code == 401:
                self.info("Login attempt", "Credentials rejected (may need different field names)")
            else:
                self.info("Login attempt", f"Unexpected response: HTTP {resp.status_code}")

    def _test_registration(self, endpoints: dict) -> None:
        """Test registration endpoint."""
        register_url = endpoints.get("register")
        if not register_url:
            self.info("Registration test", "No registration endpoint found — skipping")
            return

        # Test weak password acceptance
        weak_passwords = ["123", "password", "1234", "abc"]
        for pwd in weak_passwords:
            resp = self.client.post(register_url, json_data={
                "username": "testuser_audit",
                "email": "test@audit.test",
                "password": pwd,
            })
            if resp.is_success:
                self.fail_check(
                    f"Weak password accepted: '{pwd}'",
                    f"Registration accepts weak password: '{pwd}'",
                    severity=Severity.HIGH,
                    url=register_url,
                    recommendation="Enforce minimum password complexity (8+ chars, mixed case, symbols)",
                )
                break
        else:
            self.pass_check("Password policy", "Registration rejects weak passwords")

    def _test_password_policy(self, endpoints: dict) -> None:
        """Test password policy enforcement."""
        login_url = endpoints.get("login") or endpoints.get("register")
        if not login_url:
            return

        # Test very long password (DoS via bcrypt)
        long_password = "A" * 10000
        resp = self.client.post(login_url, json_data={
            "username": "testuser",
            "password": long_password,
        })
        if resp.elapsed_ms > 5000:
            self.fail_check(
                "Long password DoS",
                f"Very long password causes slow response ({resp.elapsed_ms:.0f}ms)",
                severity=Severity.HIGH,
                recommendation="Limit password length to prevent bcrypt DoS (max ~72 chars)",
            )
        else:
            self.pass_check("Long password handling", "Server handles very long passwords correctly")

    def _test_session_management(self) -> None:
        """Test session management security."""
        resp = self.client.get(self._base_url)
        if resp.error:
            return

        # Check for session cookie attributes
        for key, value in resp.headers.items():
            if key.lower() == "set-cookie" and ("session" in value.lower() or "sid" in value.lower()):
                cookie_lower = value.lower()

                if "httponly" not in cookie_lower:
                    self.fail_check(
                        "Session cookie not HttpOnly",
                        "Session cookie accessible via JavaScript",
                        severity=Severity.HIGH,
                        recommendation="Set HttpOnly flag on session cookies",
                    )
                else:
                    self.pass_check("Session HttpOnly", "Session cookie has HttpOnly flag")

                if "secure" not in cookie_lower and self._base_url.startswith("https"):
                    self.fail_check(
                        "Session cookie not Secure",
                        "Session cookie sent over HTTP too",
                        severity=Severity.HIGH,
                        recommendation="Set Secure flag on session cookies",
                    )

                if "samesite" not in cookie_lower:
                    self.fail_check(
                        "Session cookie missing SameSite",
                        "Session cookie vulnerable to CSRF",
                        severity=Severity.MEDIUM,
                        recommendation="Set SameSite=Lax or SameSite=Strict on session cookies",
                    )
                else:
                    self.pass_check("Session SameSite", "Session cookie has SameSite attribute")

    def _test_brute_force_protection(self, endpoints: dict) -> None:
        """Test brute force protection on login."""
        login_url = endpoints.get("login")
        if not login_url:
            return

        locked_out = False
        for i in range(10):
            resp = self.client.post(login_url, json_data={
                "username": "admin",
                "password": f"wrong_password_{i}",
            })
            if resp.status_code == 429 or resp.status_code == 423:
                locked_out = True
                break

        if locked_out:
            self.pass_check(
                "Brute force protection",
                "Account lockout or rate limiting detected after repeated failures",
            )
        else:
            self.fail_check(
                "No brute force protection",
                "No rate limiting or account lockout after 10 failed login attempts",
                severity=Severity.HIGH,
                recommendation="Implement rate limiting, CAPTCHA, or account lockout after failed attempts",
            )

    def _test_jwt_security(self) -> None:
        """Test JWT token security."""
        import jwt as pyjwt

        token = self.config.auth.jwt_token
        if not token:
            return

        try:
            header = pyjwt.get_unverified_header(token)
            decoded = pyjwt.decode(token, options={"verify_signature": False})

            # Check algorithm
            alg = header.get("alg", "")
            if alg.lower() == "none":
                self.fail_check("JWT 'none' algorithm", "JWT uses 'none' — forging possible",
                                severity=Severity.CRITICAL)
            else:
                self.pass_check("JWT algorithm", f"JWT algorithm: {alg}")

            # Check claims
            if "exp" in decoded:
                self.pass_check("JWT expiration", "Token has expiration claim")
            else:
                self.fail_check("JWT no expiration", "Token never expires",
                                severity=Severity.HIGH,
                                recommendation="Always set exp claim on JWTs")

            if "iat" in decoded:
                self.pass_check("JWT issued-at", "Token has iat claim")

            # Check if token is accepted when tampered
            parts = token.split(".")
            if len(parts) == 3:
                tampered = parts[0] + "." + parts[1] + ".invalidsignature"
                resp = self.auth_client.get(
                    self._base_url,
                    headers={"Authorization": f"Bearer {tampered}"},
                )
                if resp.is_success:
                    self.fail_check(
                        "JWT signature not verified",
                        "Server accepts JWT with invalid signature",
                        severity=Severity.CRITICAL,
                        recommendation="Always verify JWT signatures on the server",
                    )
                else:
                    self.pass_check("JWT signature verified", "Server rejects tampered JWTs")

        except Exception as e:
            self.info("JWT analysis", f"JWT analysis error: {e}")

    def _test_oauth(self) -> None:
        """Test OAuth configuration."""
        oauth_paths = ["/auth/google", "/auth/github", "/auth/facebook", "/oauth/authorize",
                       "/api/auth/google", "/api/auth/github"]

        for path in oauth_paths:
            url = f"{self._base_url.rstrip('/')}{path}"
            resp = self.client.get(url, allow_redirects=False)

            if resp.status_code != 404 and not resp.error:
                self.info(f"OAuth endpoint: {path}", f"OAuth provider found (HTTP {resp.status_code})")

                if resp.is_redirect:
                    location = resp.headers.get("Location", "")
                    if "client_id" in location:
                        self.info("OAuth redirect", f"Redirects to OAuth provider")

    def _test_protected_routes(self) -> None:
        """Test that protected routes require authentication."""
        protected_paths = ["/admin", "/dashboard", "/settings", "/api/admin",
                           "/profile", "/api/users", "/api/admin/users"]

        unauthenticated = HttpClient(
            timeout=self.config.crawl.timeout_s,
            user_agent=self.config.crawl.user_agent,
        )

        for path in protected_paths:
            url = f"{self._base_url.rstrip('/')}{path}"
            resp = unauthenticated.get(url)

            if resp.status_code == 404:
                continue

            if resp.is_success:
                self.fail_check(
                    f"Unprotected route: {path}",
                    f"Protected resource accessible without auth (HTTP {resp.status_code})",
                    severity=Severity.HIGH,
                    url=url,
                    recommendation=f"Require authentication for {path}",
                )
            elif resp.status_code in (401, 403, 302):
                self.pass_check(
                    f"Protected route: {path}",
                    f"Properly requires auth (HTTP {resp.status_code})",
                )

    def _test_logout(self, endpoints: dict) -> None:
        """Test logout functionality."""
        logout_url = endpoints.get("logout")
        if not logout_url:
            self.info("Logout test", "No logout endpoint found")
            return

        resp = self.client.post(logout_url)
        if resp.is_success or resp.is_redirect:
            self.pass_check("Logout endpoint", f"Logout endpoint responds (HTTP {resp.status_code})")
        else:
            self.info("Logout test", f"Logout returned HTTP {resp.status_code}")
