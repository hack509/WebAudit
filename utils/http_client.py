"""
HTTP Client Wrapper for WebAudit — unified sync+async via httpx.

Replaces the previous requests (sync) + aiohttp (async) dual-stack
with a single httpx-based implementation that shares the same interface
for both modes. Adds rate limiting (token-bucket) and GET-response caching.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from utils.logger import get_logger

logger = get_logger("http_client")

_DEFAULT_HEADERS = {
    "User-Agent": "WebAudit/1.0 (Automated Security & Quality Scanner)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
}


# ---------------------------------------------------------------------------
# Rate limiter (async)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Token-bucket rate limiter with exponential back-off on HTTP 429.

    Call `await acquire()` before every async request.
    Call `backoff_on_429()` when the server returns 429.
    Call `reset_backoff()` after any successful response.
    """

    def __init__(self, requests_per_second: float = 10.0, max_backoff_s: float = 60.0):
        self._min_interval = 1.0 / max(requests_per_second, 0.1)
        self._max_backoff = max_backoff_s
        self._last_request: float = 0.0
        self._backoff: float = 1.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def backoff_on_429(self) -> None:
        logger.warning(f"Rate-limited (429) — backing off {self._backoff:.1f}s")
        await asyncio.sleep(self._backoff)
        self._backoff = min(self._backoff * 2, self._max_backoff)

    def reset_backoff(self) -> None:
        self._backoff = 1.0


# ---------------------------------------------------------------------------
# Shared response dataclass (unchanged interface)
# ---------------------------------------------------------------------------

@dataclass
class HttpResponse:
    """Normalised HTTP response shared by both sync and async clients."""

    status_code: int
    headers: dict[str, str]
    body: str
    json_data: Optional[Any] = None
    elapsed_ms: float = 0.0
    url: str = ""
    method: str = ""
    error: Optional[str] = None
    size_bytes: int = 0

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return self.status_code >= 500


class CaseInsensitiveDict(dict):
    """Dict with case-insensitive key lookups — preserves the behaviour of requests.Response.headers."""

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(key.lower())

    def get(self, key: str, default=None):
        return super().get(key.lower(), default)

    def __contains__(self, key: object) -> bool:
        return super().__contains__(str(key).lower())

    @classmethod
    def from_dict(cls, d: dict) -> "CaseInsensitiveDict":
        obj = cls()
        for k, v in d.items():
            obj[k] = v
        return obj


def _to_http_response(resp: httpx.Response, elapsed_ms: float, method: str) -> HttpResponse:
    json_body = None
    try:
        json_body = resp.json()
    except Exception:
        pass
    return HttpResponse(
        status_code=resp.status_code,
        headers=CaseInsensitiveDict.from_dict(dict(resp.headers)),
        body=resp.text,
        json_data=json_body,
        elapsed_ms=elapsed_ms,
        url=str(resp.url),
        method=method.upper(),
        size_bytes=len(resp.content),
    )


def _error_response(url: str, method: str, elapsed_ms: float, error: str) -> HttpResponse:
    return HttpResponse(
        status_code=0, headers={}, body="",
        elapsed_ms=elapsed_ms, url=url, method=method.upper(), error=error,
    )


# ---------------------------------------------------------------------------
# Synchronous client (httpx.Client — replaces requests.Session)
# ---------------------------------------------------------------------------

class HttpClient:
    """Synchronous HTTP client built on httpx.Client.

    Drop-in replacement for the previous requests-based implementation.
    Suitable for use inside async audit methods when called from sync helpers.
    """

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        user_agent: str = "WebAudit/1.0",
        jwt_token: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        headers = {**_DEFAULT_HEADERS, "User-Agent": user_agent}
        if jwt_token:
            headers["Authorization"] = f"Bearer {jwt_token}"

        transport = httpx.HTTPTransport(retries=max_retries)
        self._client = httpx.Client(
            headers=headers,
            timeout=float(timeout),
            verify=verify_ssl,
            transport=transport,
            follow_redirects=True,
        )

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        params: Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        start = time.perf_counter()
        try:
            resp = self._client.request(
                method=method.upper(),
                url=url,
                headers=headers,
                content=data,
                json=json_data,
                params=params,
                follow_redirects=allow_redirects,
            )
            elapsed = (time.perf_counter() - start) * 1000
            return _to_http_response(resp, elapsed, method)

        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - start) * 1000
            logger.warning(f"Timeout on {method.upper()} {url}")
            return HttpResponse(
                status_code=408, headers={}, body="",
                elapsed_ms=elapsed, url=url, method=method.upper(),
                error="Request timed out",
            )
        except httpx.RequestError as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"Request error on {method.upper()} {url}: {e}")
            return _error_response(url, method, elapsed, str(e))
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"Unexpected error on {method.upper()} {url}: {e}")
            return _error_response(url, method, elapsed, str(e))

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HttpResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> HttpResponse:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> HttpResponse:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> HttpResponse:
        return self.request("DELETE", url, **kwargs)

    def options(self, url: str, **kwargs) -> HttpResponse:
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# TTL cache entry
# ---------------------------------------------------------------------------

class _CacheEntry:
    __slots__ = ("response", "expires_at")

    def __init__(self, response: HttpResponse, ttl_s: float):
        self.response = response
        self.expires_at = time.monotonic() + ttl_s


# ---------------------------------------------------------------------------
# Asynchronous client (httpx.AsyncClient — replaces aiohttp)
# ---------------------------------------------------------------------------

class AsyncHttpClient:
    """Asynchronous HTTP client built on httpx.AsyncClient.

    Features:
    - Concurrency cap via asyncio.Semaphore
    - Token-bucket rate limiting with 429 back-off
    - In-memory TTL cache for GET requests (default: 5 min)
    """

    def __init__(
        self,
        timeout: int = 30,
        max_concurrent: int = 10,
        user_agent: str = "WebAudit/1.0",
        jwt_token: Optional[str] = None,
        verify_ssl: bool = True,
        requests_per_second: float = 10.0,
        cache_ttl_s: float = 300.0,
    ):
        headers = {**_DEFAULT_HEADERS, "User-Agent": user_agent, "Accept": "*/*"}
        if jwt_token:
            headers["Authorization"] = f"Bearer {jwt_token}"

        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=float(timeout),
            verify=verify_ssl,
            transport=httpx.AsyncHTTPTransport(retries=2),
            follow_redirects=True,
        )
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._rate_limiter = RateLimiter(requests_per_second=requests_per_second)
        self._cache: dict[str, _CacheEntry] = {}
        self._cache_ttl = cache_ttl_s

    def _cache_get(self, key: str) -> Optional[HttpResponse]:
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            del self._cache[key]
            return None
        return entry.response

    def _cache_set(self, key: str, response: HttpResponse) -> None:
        self._cache[key] = _CacheEntry(response, self._cache_ttl)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
    ) -> HttpResponse:
        method_upper = method.upper()

        # Serve from cache for GET requests
        if method_upper == "GET":
            cached = self._cache_get(url)
            if cached is not None:
                logger.debug(f"Cache hit: {url}")
                return cached

        await self._rate_limiter.acquire()

        async with self._semaphore:
            start = time.perf_counter()
            try:
                resp = await self._client.request(
                    method=method_upper,
                    url=url,
                    headers=headers,
                    content=data,
                    json=json_data,
                )
                elapsed = (time.perf_counter() - start) * 1000

                if resp.status_code == 429:
                    await self._rate_limiter.backoff_on_429()
                else:
                    self._rate_limiter.reset_backoff()

                result = _to_http_response(resp, elapsed, method)

                if method_upper == "GET" and result.is_success:
                    self._cache_set(url, result)

                return result

            except httpx.TimeoutException:
                elapsed = (time.perf_counter() - start) * 1000
                return HttpResponse(
                    status_code=408, headers={}, body="",
                    elapsed_ms=elapsed, url=url, method=method_upper,
                    error="Request timed out",
                )
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000
                return _error_response(url, method, elapsed, str(e))

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncHttpClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
