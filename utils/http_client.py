"""
HTTP Client Wrapper for WebAudit.

Provides synchronous and asynchronous HTTP clients with retry, timeout,
authentication, and error handling.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils.logger import get_logger

logger = get_logger("http_client")


@dataclass
class HttpResponse:
    """Normalized HTTP response."""

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


class HttpClient:
    """Synchronous HTTP client with retry and timeout support."""

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        user_agent: str = "WebAudit/1.0",
        jwt_token: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.jwt_token = jwt_token
        self.verify_ssl = verify_ssl

        self.session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Default headers
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        })

        if self.jwt_token:
            self.session.headers["Authorization"] = f"Bearer {self.jwt_token}"

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
        """Make an HTTP request and return a normalized response."""
        start = time.perf_counter()
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                data=data,
                json=json_data,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
            )
            elapsed = (time.perf_counter() - start) * 1000

            json_body = None
            try:
                json_body = resp.json()
            except (ValueError, TypeError):
                pass

            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                json_data=json_body,
                elapsed_ms=elapsed,
                url=str(resp.url),
                method=method.upper(),
                size_bytes=len(resp.content),
            )

        except requests.exceptions.Timeout:
            elapsed = (time.perf_counter() - start) * 1000
            logger.warning(f"Timeout on {method.upper()} {url}")
            return HttpResponse(
                status_code=408, headers={}, body="",
                elapsed_ms=elapsed, url=url, method=method.upper(),
                error="Request timed out",
            )
        except requests.exceptions.ConnectionError as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"Connection error on {method.upper()} {url}: {e}")
            return HttpResponse(
                status_code=0, headers={}, body="",
                elapsed_ms=elapsed, url=url, method=method.upper(),
                error=f"Connection error: {e}",
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"Request error on {method.upper()} {url}: {e}")
            return HttpResponse(
                status_code=0, headers={}, body="",
                elapsed_ms=elapsed, url=url, method=method.upper(),
                error=str(e),
            )

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
        self.session.close()


class AsyncHttpClient:
    """Asynchronous HTTP client for concurrent requests."""

    def __init__(
        self,
        timeout: int = 30,
        max_concurrent: int = 10,
        user_agent: str = "WebAudit/1.0",
        jwt_token: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self.jwt_token = jwt_token
        self.verify_ssl = verify_ssl
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
            }
            if self.jwt_token:
                headers["Authorization"] = f"Bearer {self.jwt_token}"

            connector = aiohttp.TCPConnector(
                ssl=self.verify_ssl,
                limit=self.max_concurrent,
            )
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers=headers,
                connector=connector,
            )
        return self._session

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
    ) -> HttpResponse:
        """Make an async HTTP request."""
        async with self._semaphore:
            session = await self._get_session()
            start = time.perf_counter()
            try:
                async with session.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    data=data,
                    json=json_data,
                ) as resp:
                    body = await resp.text()
                    elapsed = (time.perf_counter() - start) * 1000

                    json_body = None
                    try:
                        json_body = await resp.json(content_type=None)
                    except (ValueError, TypeError):
                        pass

                    return HttpResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        json_data=json_body,
                        elapsed_ms=elapsed,
                        url=str(resp.url),
                        method=method.upper(),
                        size_bytes=len(body.encode()),
                    )

            except asyncio.TimeoutError:
                elapsed = (time.perf_counter() - start) * 1000
                return HttpResponse(
                    status_code=408, headers={}, body="",
                    elapsed_ms=elapsed, url=url, method=method.upper(),
                    error="Request timed out",
                )
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000
                return HttpResponse(
                    status_code=0, headers={}, body="",
                    elapsed_ms=elapsed, url=url, method=method.upper(),
                    error=str(e),
                )

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
