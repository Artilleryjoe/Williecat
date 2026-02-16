"""Minimal HTTP helper to avoid external dependencies."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Dict, Iterable, Mapping, MutableMapping, Optional


class HttpError(RuntimeError):
    """Exception raised when a non-success HTTP status is encountered."""

    def __init__(self, status_code: int, url: str):
        super().__init__(f"HTTP {status_code} for {url}")
        self.status_code = status_code
        self.url = url


class CaseInsensitiveHeaders(MutableMapping[str, str]):
    """Case-insensitive mapping of HTTP headers."""

    def __init__(self, items: Iterable[tuple[str, str]]):
        self._store: Dict[str, str] = {}
        for key, value in items:
            self._store[key.lower()] = value

    def __getitem__(self, key: str) -> str:
        return self._store[key.lower()]

    def __setitem__(self, key: str, value: str) -> None:
        self._store[key.lower()] = value

    def __delitem__(self, key: str) -> None:
        del self._store[key.lower()]

    def __iter__(self):
        return iter(self._store)

    def __len__(self) -> int:
        return len(self._store)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._store.get(key.lower(), default)

    def items(self):
        return self._store.items()


@dataclass
class Cookie:
    name: str
    value: str


class HttpResponse:
    """Simple HTTP response wrapper."""

    def __init__(self, body: bytes, url: str, status: int, headers: Iterable[tuple[str, str]], cookies: Iterable[Cookie]):
        self._body = body
        self.url = url
        self.status_code = status
        self.headers = CaseInsensitiveHeaders(headers)
        self.cookies = list(cookies)

    def json(self):
        return json.loads(self.text)

    @property
    def text(self) -> str:
        return self._body.decode("utf-8", errors="replace")

    def raise_for_status(self) -> None:
        if not (200 <= self.status_code < 400):
            raise HttpError(self.status_code, self.url)


class HttpSession:
    """Lightweight session supporting HTTP requests via ``urllib``."""

    def __init__(self):
        self.cookie_jar = CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self._headers: Dict[str, str] = {}

    def headers(self) -> Mapping[str, str]:  # pragma: no cover - access helper
        return dict(self._headers)

    def update_headers(self, headers: Mapping[str, str]) -> None:
        for key, value in headers.items():
            self._headers[key] = value

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, str | int | float]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        if params:
            query = urllib.parse.urlencode(params)
            url = _merge_url_params(url, query)
        request = urllib.request.Request(url, method=method.upper())
        for key, value in self._headers.items():
            request.add_header(key, value)
        if headers:
            for key, value in headers.items():
                request.add_header(key, value)
        if not allow_redirects:
            request.redirect = lambda self, req, fp, code, msg, headers: None  # pragma: no cover - rarely used
        try:
            with self._opener.open(request, timeout=timeout) as response:
                data = response.read()
                status = response.getcode()
                response_url = response.geturl()
                response_headers = response.headers.items()
        except urllib.error.HTTPError as exc:
            data = exc.read()
            status = exc.code
            response_url = exc.geturl()
            response_headers = exc.headers.items() if exc.headers is not None else ()

        cookies = [Cookie(cookie.name, cookie.value) for cookie in self.cookie_jar]
        return HttpResponse(data, response_url, status, response_headers, cookies)

    def get(
        self,
        url: str,
        params: Optional[Mapping[str, str | int | float]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )

    def head(
        self,
        url: str,
        params: Optional[Mapping[str, str | int | float]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        return self.request(
            "HEAD",
            url,
            params=params,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )


def _merge_url_params(url: str, query: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        query = f"{parsed.query}&{query}"
    return urllib.parse.urlunparse(parsed._replace(query=query))
