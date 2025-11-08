"""HTTP header collection module."""
from __future__ import annotations

from itertools import cycle
from typing import ClassVar, Dict, List, Optional

from ..core import ModuleResult, ReconContext, ReconModule

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]


USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
    "curl/8.5.0",
)


class HeaderSnifferModule(ReconModule):
    """Fetch HTTP headers and security-relevant metadata."""

    name = "headers"
    description = "Collect HTTP response headers from the target application."
    _ua_cycle: ClassVar[cycle[str]] = cycle(USER_AGENTS)

    def run(self, context: ReconContext) -> ModuleResult:
        url = context.base_url
        if not url:
            if not context.domain:
                return ModuleResult(self.name, None, error="A domain or URL is required for header sniffing.")
            url = f"https://{context.domain}"

        session = context.session
        user_agent = next(self._ua_cycle)
        request_headers = {"User-Agent": user_agent}

        try:
            response = session.head(url, headers=request_headers, timeout=context.timeout, allow_redirects=True)
        except Exception as exc:  # pragma: no cover - defensive
            return ModuleResult(self.name, None, error=f"HEAD request failed: {exc}")

        method_used = "HEAD"
        warnings: List[str] = []
        if response.status_code in {405, 501}:
            try:
                response = session.get(url, headers=request_headers, timeout=context.timeout, allow_redirects=True)
                method_used = "GET (fallback)"
                warnings.append("HEAD not supported – performed safe GET fallback.")
            except Exception as exc:  # pragma: no cover - defensive
                return ModuleResult(self.name, None, error=f"HTTP request failed: {exc}")

        result: Dict[str, Optional[str]] = {}
        for header in SECURITY_HEADERS:
            value = response.headers.get(header)
            if value is None:
                value = response.headers.get(header.title())
            if value is not None:
                result[header] = value

        metadata = {
            "url": str(response.url),
            "method": method_used,
            "status_code": response.status_code,
            "server": response.headers.get("Server"),
            "powered_by": response.headers.get("X-Powered-By"),
            "user_agent": user_agent,
            "cookies": {cookie.name: cookie.value for cookie in response.cookies},
            "security_headers": result,
        }
        if not result:
            warnings.append("No common security headers detected.")

        return ModuleResult(self.name, metadata, warnings=warnings)
