"""HTTP header collection module."""
from __future__ import annotations

from typing import Dict, List, Optional

from . import ModuleResult, ReconContext, ReconModule

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
        headers = {
            "User-Agent": "Williecat Recon (https://github.com/)"
        }

        try:
            response = session.get(url, headers=headers, timeout=context.timeout, allow_redirects=True)
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
            "status_code": response.status_code,
            "server": response.headers.get("Server"),
            "powered_by": response.headers.get("X-Powered-By"),
            "cookies": {cookie.name: cookie.value for cookie in response.cookies},
            "security_headers": result,
        }
        warnings: List[str] = []
        if not result:
            warnings.append("No common security headers detected.")

        return ModuleResult(self.name, metadata, warnings=warnings)
