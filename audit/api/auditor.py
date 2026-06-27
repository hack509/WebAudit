"""
API Auditor — Module 3.

Tests all HTTP methods, payloads, injections, auth, and load.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.http_client import HttpClient, AsyncHttpClient
from utils.constants import (
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    NOSQL_INJECTION_PAYLOADS,
)


class APIAuditor(BaseAuditor):
    """Audits API endpoints for methods, payloads, injections, and load."""

    MODULE_NAME = "api"
    MODULE_DESCRIPTION = "Audit des API"

    def __init__(self, config: AuditConfig):
        super().__init__(config)
        self.client = HttpClient(
            timeout=config.crawl.timeout_s,
            user_agent=config.crawl.user_agent,
            jwt_token=config.auth.jwt_token,
        )
        self.api_base = self._build_api_base()
        self.discovered_endpoints: list[str] = []

    def _build_api_base(self) -> str:
        """Build the API base URL."""
        base = self._base_url.rstrip("/")
        api_path = self.config.target.api_base or "/api"
        return f"{base}{api_path}"

    async def run(self) -> AuditResult:
        """Run the API audit."""
        self.logger.info(f"Starting API audit for {self.api_base}")

        # 1. Discover API endpoints
        self._discover_endpoints()

        # 2. Test HTTP methods
        self._test_http_methods()

        # 3. Test invalid payloads
        self._test_invalid_payloads()

        # 4. Test injections
        if self.config.security.test_injections:
            self._test_sql_injection()
            self._test_xss()
            self._test_nosql_injection()

        # 5. Test auth
        self._test_auth_endpoints()

        # 6. Test response format
        self._test_response_format()

        # 7. Test load
        await self._test_load()

        return self.build_result()

    def _discover_endpoints(self) -> None:
        """Discover API endpoints."""
        common_endpoints = [
            "/", "/health", "/status", "/version",
            "/users", "/auth/login", "/auth/register", "/auth/logout",
            "/products", "/items", "/posts", "/comments",
            "/categories", "/tags", "/search",
            "/docs", "/swagger", "/openapi.json", "/api-docs",
        ]

        for endpoint in common_endpoints:
            url = f"{self.api_base.rstrip('/')}{endpoint}"
            resp = self.client.get(url)

            if resp.status_code != 404 and not resp.error:
                self.discovered_endpoints.append(endpoint)

        self.info(
            "API endpoints discovered",
            f"{len(self.discovered_endpoints)} endpoint(s) found at {self.api_base}",
        )

        # Check for API documentation
        doc_endpoints = ["/docs", "/swagger", "/openapi.json", "/api-docs", "/swagger-ui.html"]
        for ep in doc_endpoints:
            if ep in self.discovered_endpoints:
                self.fail_check(
                    f"API docs exposed: {ep}",
                    "API documentation is publicly accessible",
                    severity=Severity.LOW,
                    recommendation="Restrict API docs access in production",
                    url=f"{self.api_base.rstrip('/')}{ep}",
                )

    def _test_http_methods(self) -> None:
        """Test all HTTP methods on discovered endpoints."""
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

        for endpoint in self.discovered_endpoints[:10]:
            url = f"{self.api_base.rstrip('/')}{endpoint}"

            for method in methods:
                resp = self.client.request(method, url)

                if resp.status_code == 405:
                    # Method not allowed — expected behavior
                    self.pass_check(
                        f"{method} {endpoint} — Not Allowed",
                        f"HTTP 405 — Method properly rejected",
                    )
                elif resp.is_success:
                    self.info(
                        f"{method} {endpoint} — Accepted",
                        f"HTTP {resp.status_code} in {resp.elapsed_ms:.0f}ms",
                    )

                    # Check if dangerous methods are unprotected
                    if method in ["DELETE", "PUT", "PATCH"] and not self.config.auth.jwt_token:
                        self.fail_check(
                            f"{method} {endpoint} — No auth required",
                            f"Dangerous method {method} accepted without authentication",
                            severity=Severity.HIGH,
                            url=url,
                            recommendation=f"Require authentication for {method} requests",
                        )
                elif resp.status_code == 401 or resp.status_code == 403:
                    self.pass_check(
                        f"{method} {endpoint} — Auth required",
                        f"HTTP {resp.status_code} — Properly requires authentication",
                    )

    def _test_invalid_payloads(self) -> None:
        """Test endpoints with invalid payloads."""
        test_cases = [
            ("Empty body", {}),
            ("Null values", {"key": None, "value": None}),
            ("Wrong types", {"id": "not-a-number", "count": "abc"}),
            ("Very long string", {"data": "A" * 10000}),
            ("Special chars", {"data": "!@#$%^&*(){}[]|\\/<>?"}),
            ("Unicode", {"data": "🔥💀👻🎃 тест 测试"}),
            ("Nested deep", {"a": {"b": {"c": {"d": {"e": "deep"}}}}}),
        ]

        for endpoint in self.discovered_endpoints[:5]:
            url = f"{self.api_base.rstrip('/')}{endpoint}"

            for test_name, payload in test_cases:
                resp = self.client.post(url, json_data=payload)

                if resp.is_server_error:
                    self.fail_check(
                        f"Server crash on {test_name}: {endpoint}",
                        f"HTTP {resp.status_code} with payload: {test_name}",
                        severity=Severity.HIGH,
                        url=url,
                        recommendation="Implement proper input validation and error handling",
                    )
                elif resp.status_code in (400, 422):
                    self.pass_check(
                        f"Validation on {test_name}: {endpoint}",
                        f"Properly rejected with HTTP {resp.status_code}",
                    )

    def _test_sql_injection(self) -> None:
        """Test for SQL injection vulnerabilities."""
        max_tests = self.config.security.max_injection_tests

        for endpoint in self.discovered_endpoints[:5]:
            url = f"{self.api_base.rstrip('/')}{endpoint}"

            for i, payload in enumerate(SQL_INJECTION_PAYLOADS):
                if i >= max_tests:
                    break

                # Test in query params
                resp = self.client.get(url, params={"q": payload, "id": payload})

                if resp.is_success and resp.body:
                    # Check for SQL error indicators
                    sql_errors = [
                        "sql syntax", "mysql", "postgresql", "sqlite",
                        "ora-", "sql server", "unclosed quotation",
                        "syntax error", "operand type",
                    ]
                    body_lower = resp.body.lower()
                    if any(err in body_lower for err in sql_errors):
                        self.fail_check(
                            f"SQL Injection: {endpoint}",
                            f"SQL error detected with payload: {payload}",
                            severity=Severity.CRITICAL,
                            url=url,
                            evidence=resp.body[:300],
                            recommendation="Use parameterized queries / prepared statements",
                        )
                        break
                elif resp.is_server_error:
                    self.fail_check(
                        f"Possible SQL Injection: {endpoint}",
                        f"Server error (HTTP {resp.status_code}) with SQL payload",
                        severity=Severity.HIGH,
                        url=url,
                        recommendation="Validate and sanitize all input parameters",
                    )
                    break
            else:
                self.pass_check(
                    f"SQL Injection test: {endpoint}",
                    "No SQL injection vulnerability detected",
                )

    def _test_xss(self) -> None:
        """Test for XSS vulnerabilities."""
        for endpoint in self.discovered_endpoints[:5]:
            url = f"{self.api_base.rstrip('/')}{endpoint}"

            for payload in XSS_PAYLOADS[:5]:
                resp = self.client.get(url, params={"q": payload})

                if resp.is_success and payload in resp.body:
                    self.fail_check(
                        f"XSS Reflected: {endpoint}",
                        f"XSS payload reflected in response: {payload[:50]}",
                        severity=Severity.HIGH,
                        url=url,
                        recommendation="Sanitize and encode all user inputs before rendering",
                    )
                    break
            else:
                self.pass_check(
                    f"XSS test: {endpoint}",
                    "No reflected XSS vulnerability detected",
                )

    def _test_nosql_injection(self) -> None:
        """Test for NoSQL injection."""
        for endpoint in self.discovered_endpoints[:5]:
            url = f"{self.api_base.rstrip('/')}{endpoint}"

            for payload in NOSQL_INJECTION_PAYLOADS[:3]:
                try:
                    json_payload = json.loads(payload) if payload.startswith("{") else {"q": payload}
                except json.JSONDecodeError:
                    json_payload = {"q": payload}

                resp = self.client.post(url, json_data=json_payload)

                if resp.is_success and resp.body:
                    body_lower = resp.body.lower()
                    nosql_errors = ["mongodb", "mongoose", "cast error", "bsontype"]
                    if any(err in body_lower for err in nosql_errors):
                        self.fail_check(
                            f"NoSQL Injection: {endpoint}",
                            f"NoSQL error detected with payload: {payload[:50]}",
                            severity=Severity.CRITICAL,
                            url=url,
                            recommendation="Sanitize NoSQL query inputs",
                        )
                        break
            else:
                self.pass_check(
                    f"NoSQL Injection test: {endpoint}",
                    "No NoSQL injection vulnerability detected",
                )

    def _test_auth_endpoints(self) -> None:
        """Test authentication-related endpoint behavior."""
        auth_endpoints = ["/auth/login", "/auth/register", "/login", "/register"]

        for ep in auth_endpoints:
            url = f"{self.api_base.rstrip('/')}{ep}"
            resp = self.client.post(url, json_data={"username": "", "password": ""})

            if resp.status_code == 404:
                continue

            if resp.is_success:
                self.fail_check(
                    f"Auth accepts empty credentials: {ep}",
                    "Authentication endpoint accepts empty username/password",
                    severity=Severity.CRITICAL,
                    url=url,
                    recommendation="Validate that credentials are not empty",
                )
            elif resp.status_code in (400, 401, 422):
                self.pass_check(
                    f"Auth validates credentials: {ep}",
                    f"Properly rejected empty credentials (HTTP {resp.status_code})",
                )

        # Test expired/invalid JWT
        if self.config.auth.jwt_token:
            resp = self.client.get(
                self.api_base,
                headers={"Authorization": "Bearer invalid-token-12345"},
            )
            if resp.status_code == 401:
                self.pass_check(
                    "Invalid JWT rejected",
                    "Server properly rejects invalid JWT tokens",
                )
            elif resp.is_success:
                self.fail_check(
                    "Invalid JWT accepted",
                    "Server accepts invalid JWT tokens",
                    severity=Severity.CRITICAL,
                    recommendation="Validate JWT tokens on every request",
                )

    def _test_response_format(self) -> None:
        """Test API response format consistency."""
        for endpoint in self.discovered_endpoints[:5]:
            url = f"{self.api_base.rstrip('/')}{endpoint}"
            resp = self.client.get(url)

            if resp.is_success:
                content_type = resp.headers.get("Content-Type", "")

                if "application/json" in content_type:
                    self.pass_check(
                        f"JSON Content-Type: {endpoint}",
                        "Response has proper application/json Content-Type",
                    )

                    # Check JSON structure
                    if resp.json_data is not None:
                        self.pass_check(
                            f"Valid JSON: {endpoint}",
                            "Response body is valid JSON",
                        )
                    else:
                        self.fail_check(
                            f"Invalid JSON body: {endpoint}",
                            "Content-Type is JSON but body is not valid JSON",
                            severity=Severity.MEDIUM,
                            url=url,
                        )

    async def _test_load(self) -> None:
        """Basic load test with concurrent requests."""
        url = self._base_url
        concurrent = 10
        total_requests = 20

        self.logger.info(f"Load test: {total_requests} requests, {concurrent} concurrent")

        async_client = AsyncHttpClient(
            timeout=self.config.crawl.timeout_s,
            max_concurrent=concurrent,
            jwt_token=self.config.auth.jwt_token,
        )

        try:
            start = time.perf_counter()
            tasks = [async_client.get(url) for _ in range(total_requests)]
            results = await asyncio.gather(*tasks)
            total_time = (time.perf_counter() - start) * 1000

            successes = sum(1 for r in results if r.is_success)
            errors = sum(1 for r in results if r.error)
            avg_time = sum(r.elapsed_ms for r in results) / len(results) if results else 0

            self.info(
                "Load test results",
                f"{successes}/{total_requests} successful — "
                f"Avg: {avg_time:.0f}ms — Total: {total_time:.0f}ms — "
                f"Errors: {errors}",
            )

            if errors > total_requests * 0.2:
                self.fail_check(
                    "Load test: High error rate",
                    f"{errors}/{total_requests} requests failed under load",
                    severity=Severity.HIGH,
                    recommendation="Improve server capacity and error handling under load",
                )
            else:
                self.pass_check(
                    "Load test: Stable",
                    f"Server handled {concurrent} concurrent requests with {errors} errors",
                )

            if avg_time > self.config.performance.max_response_time_ms:
                self.fail_check(
                    "Load test: Slow response",
                    f"Average response time {avg_time:.0f}ms exceeds threshold",
                    severity=Severity.MEDIUM,
                    recommendation="Optimize response time under concurrent load",
                )
        finally:
            await async_client.close()
