"""
Integration tests for WebAudit audit modules.

Uses unittest.mock to patch HttpClient so tests run without a live server.
Each test verifies the audit *logic* (finding generation, severity mapping,
scoring) not the network transport.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from audit.result import Severity
from config.settings import AuditConfig, TargetConfig, DatabaseConfig
from utils.http_client import CaseInsensitiveDict, HttpResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_config(**kwargs) -> AuditConfig:
    return AuditConfig(target=TargetConfig(url="http://test.local"), **kwargs)


def ok_response(body: str = "<html><body>OK</body></html>", headers: dict | None = None) -> HttpResponse:
    return HttpResponse(
        status_code=200,
        headers=CaseInsensitiveDict.from_dict(headers or {"content-type": "text/html"}),
        body=body,
        elapsed_ms=50.0,
        url="http://test.local",
        method="GET",
        size_bytes=len(body),
    )


def error_response(status: int = 500, body: str = "Error") -> HttpResponse:
    return HttpResponse(
        status_code=status,
        headers={},
        body=body,
        elapsed_ms=20.0,
        url="http://test.local",
        method="GET",
        size_bytes=len(body),
    )


def timeout_response() -> HttpResponse:
    return HttpResponse(
        status_code=408,
        headers={},
        body="",
        elapsed_ms=30000.0,
        url="http://test.local",
        method="GET",
        error="Request timed out",
    )


# ---------------------------------------------------------------------------
# HttpClient & RateLimiter tests
# ---------------------------------------------------------------------------

class TestHttpResponse:
    def test_is_success(self):
        assert ok_response().is_success
        assert not error_response(404).is_success
        assert not error_response(500).is_success

    def test_is_redirect(self):
        r = HttpResponse(status_code=301, headers={}, body="", url="", method="GET")
        assert r.is_redirect
        assert not r.is_success

    def test_is_server_error(self):
        assert error_response(500).is_server_error
        assert error_response(503).is_server_error
        assert not ok_response().is_server_error

    def test_error_field(self):
        r = timeout_response()
        assert r.error == "Request timed out"
        assert r.status_code == 408


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_acquire_does_not_block_on_first_call(self):
        from utils.http_client import RateLimiter
        rl = RateLimiter(requests_per_second=100.0)
        import time
        start = time.monotonic()
        await rl.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_backoff_resets(self):
        from utils.http_client import RateLimiter
        rl = RateLimiter(requests_per_second=100.0)
        assert rl._backoff == 1.0
        rl.reset_backoff()
        assert rl._backoff == 1.0


class TestAsyncHttpClientCache:
    @pytest.mark.asyncio
    async def test_get_cached(self):
        from utils.http_client import AsyncHttpClient
        client = AsyncHttpClient(cache_ttl_s=60.0)

        mock_resp = ok_response()
        with patch.object(client._client, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = MagicMock(
                status_code=200,
                headers={"content-type": "text/html"},
                text="<html>OK</html>",
                content=b"<html>OK</html>",
                url="http://test.local",
                json=MagicMock(side_effect=ValueError),
            )
            r1 = await client.get("http://test.local/page")
            r2 = await client.get("http://test.local/page")

        # Second call should hit cache — request() called only once
        assert mock_req.call_count == 1
        assert r1.status_code == r2.status_code

        await client.close()

    @pytest.mark.asyncio
    async def test_post_not_cached(self):
        from utils.http_client import AsyncHttpClient
        client = AsyncHttpClient(cache_ttl_s=60.0)

        with patch.object(client._client, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = MagicMock(
                status_code=200, headers={}, text="ok", content=b"ok",
                url="http://test.local", json=MagicMock(side_effect=ValueError),
            )
            await client.post("http://test.local/action")
            await client.post("http://test.local/action")

        # POST must never be cached
        assert mock_req.call_count == 2
        await client.close()


# ---------------------------------------------------------------------------
# BackendAuditor tests
# ---------------------------------------------------------------------------

class TestBackendAuditor:
    def _make_auditor(self, **kwargs):
        from audit.backend.auditor import BackendAuditor
        config = make_config(**kwargs)
        return BackendAuditor(config)

    @pytest.mark.asyncio
    async def test_detects_missing_security_headers(self):
        auditor = self._make_auditor()
        # Response with no security headers
        resp = ok_response(headers={"content-type": "text/html"})

        with patch.object(auditor.client, "get", return_value=resp), \
             patch.object(auditor.client, "options", return_value=resp), \
             patch.object(auditor.client, "head", return_value=resp):
            auditor._check_security_headers()

        missing = [f for f in auditor.findings if "Missing security header" in f.title]
        assert len(missing) > 0

    @pytest.mark.asyncio
    async def test_passes_with_security_headers(self):
        auditor = self._make_auditor()
        resp = ok_response(headers={
            "content-type": "text/html",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        })

        with patch.object(auditor.client, "get", return_value=resp):
            auditor._check_security_headers()

        passed = [f for f in auditor.findings if f.severity == Severity.PASS]
        assert len(passed) > 0

    @pytest.mark.asyncio
    async def test_detects_wildcard_cors(self):
        auditor = self._make_auditor()
        cors_resp = ok_response(headers={
            "content-type": "text/html",
            "access-control-allow-origin": "*",
        })

        with patch.object(auditor.client, "options", return_value=cors_resp):
            auditor._check_cors()

        cors_findings = [f for f in auditor.findings if "CORS" in f.title and f.severity == Severity.HIGH]
        assert len(cors_findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_server_error_on_route(self):
        auditor = self._make_auditor()
        auditor.discovered_routes = ["http://test.local/broken"]

        with patch.object(auditor.client, "get", return_value=error_response(500)):
            auditor._test_routes()

        server_errors = [f for f in auditor.findings if f.severity == Severity.HIGH and "Server error" in f.title]
        assert len(server_errors) >= 1

    @pytest.mark.asyncio
    async def test_detects_no_compression(self):
        auditor = self._make_auditor()
        resp = ok_response(headers={"content-type": "text/html"})

        with patch.object(auditor.client, "get", return_value=resp):
            auditor._check_compression()

        compression_findings = [f for f in auditor.findings if "compression" in f.title.lower()]
        assert len(compression_findings) >= 1


# ---------------------------------------------------------------------------
# DatabaseAuditor tests
# ---------------------------------------------------------------------------

class TestDatabaseAuditorConfig:
    def test_valid_postgresql_connection_string(self):
        config = AuditConfig(
            target=TargetConfig(url="http://test.local"),
            database=DatabaseConfig(connection_string="postgresql://user:pass@localhost/db"),
        )
        assert config.database.connection_string == "postgresql://user:pass@localhost/db"

    def test_valid_sqlite_connection_string(self):
        config = AuditConfig(
            target=TargetConfig(url="http://test.local"),
            database=DatabaseConfig(connection_string="sqlite:///path/to/db.sqlite3"),
        )
        assert config.database.connection_string is not None

    def test_invalid_connection_string_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AuditConfig(
                target=TargetConfig(url="http://test.local"),
                database=DatabaseConfig(connection_string="mongodb://localhost/db"),
            )

    def test_none_connection_string_allowed(self):
        config = AuditConfig(
            target=TargetConfig(url="http://test.local"),
            database=DatabaseConfig(connection_string=None),
        )
        assert config.database.connection_string is None

    @pytest.mark.asyncio
    async def test_skips_when_no_connection_string(self):
        from audit.database.auditor import DatabaseAuditor
        config = make_config()
        auditor = DatabaseAuditor(config)
        result = await auditor.run()
        info_findings = [f for f in result.findings if f.severity == Severity.INFO]
        assert any("skipped" in f.title.lower() or "skipped" in f.description.lower() for f in info_findings)


# ---------------------------------------------------------------------------
# AuditConfig env override tests
# ---------------------------------------------------------------------------

class TestEnvOverrides:
    def test_url_from_env(self, monkeypatch):
        monkeypatch.setenv("WEBAUDIT_URL", "https://env.example.com")
        config = AuditConfig()
        config.apply_env_overrides()
        assert config.target.url == "https://env.example.com"

    def test_verbose_from_env(self, monkeypatch):
        monkeypatch.setenv("WEBAUDIT_VERBOSE", "true")
        config = AuditConfig()
        config.apply_env_overrides()
        assert config.verbose is True

    def test_formats_from_env(self, monkeypatch):
        monkeypatch.setenv("WEBAUDIT_FORMATS", "json,csv")
        config = AuditConfig()
        config.apply_env_overrides()
        assert config.report.formats == ["json", "csv"]

    def test_no_env_vars_leaves_defaults(self, monkeypatch):
        for key in ("WEBAUDIT_URL", "WEBAUDIT_TOKEN", "WEBAUDIT_VERBOSE"):
            monkeypatch.delenv(key, raising=False)
        config = AuditConfig()
        config.apply_env_overrides()
        assert config.target.url == "http://localhost:3000"
        assert config.verbose is False


# ---------------------------------------------------------------------------
# Config profile tests
# ---------------------------------------------------------------------------

class TestConfigProfiles:
    def test_dev_profile_loads(self):
        config = AuditConfig.from_profile("dev")
        assert config.target.url == "http://localhost:3000"
        assert config.verbose is True

    def test_ci_profile_no_screenshots(self):
        config = AuditConfig.from_profile("ci")
        assert config.report.include_screenshots is False
        assert config.report.language == "en"

    def test_prod_profile_no_injections(self):
        config = AuditConfig.from_profile("prod")
        assert config.security.test_injections is False

    def test_unknown_profile_raises(self):
        with pytest.raises(FileNotFoundError):
            AuditConfig.from_profile("nonexistent_profile_xyz")


# ---------------------------------------------------------------------------
# Playwright pool tests
# ---------------------------------------------------------------------------

class TestPlaywrightPool:
    def test_get_pool_returns_none_by_default(self):
        from utils.playwright_pool import get_pool, set_pool
        set_pool(None)
        assert get_pool() is None

    def test_set_and_get_pool(self):
        from utils.playwright_pool import BrowserPool, get_pool, set_pool
        pool = BrowserPool()
        set_pool(pool)
        assert get_pool() is pool
        set_pool(None)

    def test_pool_not_ready_before_start(self):
        from utils.playwright_pool import BrowserPool
        pool = BrowserPool()
        assert not pool.is_ready
