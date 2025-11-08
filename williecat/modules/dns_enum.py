"""DNS enumeration using Google's DNS over HTTPS resolver."""
from __future__ import annotations

from typing import Dict, List

from . import ModuleResult, ReconContext, ReconModule

DNS_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "NS": 2,
    "TXT": 16,
}

DNS_RESOLVER_URL = "https://dns.google/resolve"


class DnsEnumModule(ReconModule):
    """Collect passive DNS records using public resolvers."""

    name = "dns"
    description = "Passive DNS record discovery via DNS-over-HTTPS."

    def run(self, context: ReconContext) -> ModuleResult:
        if not context.domain:
            return ModuleResult(self.name, None, error="Domain is required for DNS enumeration.")

        session = context.session
        records: Dict[str, List[str]] = {}
        warnings: List[str] = []

        for record_type, type_id in DNS_TYPES.items():
            try:
                response = session.get(
                    DNS_RESOLVER_URL,
                    params={"name": context.domain, "type": type_id},
                    timeout=context.timeout,
                )
                response.raise_for_status()
                payload = response.json()
            except Exception as exc:  # pragma: no cover - defensive
                warnings.append(f"{record_type} lookup failed: {exc}")
                continue

            status = payload.get("Status")
            if status != 0:
                warnings.append(f"{record_type} lookup returned status {status}")
                continue

            answers = payload.get("Answer", [])
            values: List[str] = []
            for answer in answers:
                data = answer.get("data")
                if data:
                    values.append(str(data))
            if values:
                records[record_type] = values

        return ModuleResult(self.name, records or None, warnings=warnings)
