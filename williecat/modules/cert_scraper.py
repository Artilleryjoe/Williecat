"""Certificate transparency scraping via crt.sh."""
from __future__ import annotations

from typing import Any, Dict, List

from . import ModuleResult, ReconContext, ReconModule

CRT_ENDPOINT = "https://crt.sh/?q={query}&output=json"


class CertificateScraperModule(ReconModule):
    """Collect certificates from crt.sh for the target domain."""

    name = "certs"
    description = "Certificate Transparency lookup via crt.sh."

    def run(self, context: ReconContext) -> ModuleResult:
        if not context.domain:
            return ModuleResult(self.name, None, error="Domain is required for certificate scraping.")

        session = context.session
        url = CRT_ENDPOINT.format(query=context.domain)
        try:
            response = session.get(url, timeout=context.timeout)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # pragma: no cover - defensive
            return ModuleResult(self.name, None, error=f"crt.sh query failed: {exc}")

        results: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for entry in payload:
            common_name = entry.get("common_name")
            name_value = entry.get("name_value")
            fingerprint = entry.get("sha256") or entry.get("sha1")
            key = fingerprint or f"{common_name}:{name_value}"
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "common_name": common_name,
                    "name_value": name_value,
                    "issuer_name": entry.get("issuer_name"),
                    "not_before": entry.get("not_before"),
                    "not_after": entry.get("not_after"),
                }
            )
            if len(results) >= 25:  # limit output volume
                break

        return ModuleResult(self.name, results)
