"""Header sniffer and demo consistency tests."""

from __future__ import annotations

from io import BytesIO
from urllib.error import HTTPError
from urllib.request import Request

from williecat.core import ReconContext
from williecat.demo import load_demo_run
from williecat.http import HttpSession
from williecat.modules.header_sniffer import HeaderSnifferModule


class _FakeHeaders:
    def __init__(self, pairs):
        self._pairs = list(pairs)

    def items(self):
        return list(self._pairs)


class _FakeResponse:
    def __init__(self, url: str, status: int, headers: list[tuple[str, str]], body: bytes = b""):
        self._url = url
        self._status = status
        self.headers = _FakeHeaders(headers)
        self._body = body

    def read(self) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeOpener:
    def __init__(self, url: str):
        self.url = url

    def open(self, request: Request, timeout=None):
        method = request.get_method()
        if method == "HEAD":
            raise HTTPError(
                self.url,
                405,
                "Method Not Allowed",
                hdrs=_FakeHeaders([("Allow", "GET")]),
                fp=BytesIO(b""),
            )
        if method == "GET":
            return _FakeResponse(
                self.url,
                200,
                [
                    ("Server", "test-nginx"),
                    ("Strict-Transport-Security", "max-age=31536000"),
                ],
            )
        raise AssertionError(f"Unexpected method: {method}")


def test_header_sniffer_falls_back_to_get_after_head_405():
    url = "https://example.test"
    session = HttpSession()
    session._opener = _FakeOpener(url)
    context = ReconContext(domain="example.test", base_url=url, timeout=2.0, session=session)

    result = HeaderSnifferModule().run(context)

    assert result.outcome == "success"
    assert result.data["method"] == "GET (fallback)"
    assert result.data["status_code"] == 200
    assert result.data["server"] == "test-nginx"
    assert "HEAD not supported" in result.warnings[0]


def test_demo_headers_warning_matches_fallback_method():
    _, results = load_demo_run()
    headers_result = next(result for result in results if result.module == "headers")

    assert headers_result.data["method"] == "GET (fallback)"
    assert any("HEAD not supported" in warning for warning in headers_result.warnings)
