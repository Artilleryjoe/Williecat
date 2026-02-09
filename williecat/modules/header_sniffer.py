"""HTTP header collection module."""
from __future__ import annotations

from typing import Dict, List, Optional

from ..core import ModuleResult, ReconContext, ReconModule
from ..user_agents import random_user_agent

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]


class HeaderSnifferModule(ReconModule):
    """Fetch HTTP headers and security-relevant metadata."""

    name = "headers"
    description = "Collect HTTP response headers from the target application."

    def run(self, context: ReconContext) -> ModuleResult:
        url = context.base_url
        if not url:
            if not context.domain:
                return ModuleResult(self.name, None, error="A domain or URL is required for header sniffing.")
            url = f"https://{context.domain}"

        session = context.session
        user_agent = random_user_agent()
        request_headers = {"User-Agent": user_agent}

        try:
            response = session.head(url, headers=request_headers, timeout=context.timeout, allow_redirects=True)
        except Exception as exc:  # pragma: no cover - defensive
            return ModuleResult.from_exception(self.name, exc)

        method_used = "HEAD"
        warnings: List[str] = []
        if response.status_code in {405, 501}:
            try:
                response = session.get(url, headers=request_headers, timeout=context.timeout, allow_redirects=True)
                method_used = "GET (fallback)"
                warnings.append("HEAD not supported – performed safe GET fallback.")
            except Exception as exc:  # pragma: no cover - defensive
                return ModuleResult.from_exception(self.name, exc)

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
