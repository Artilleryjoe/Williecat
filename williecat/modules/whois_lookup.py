"""WHOIS lookup module using RDAP."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core import ModuleResult, ReconContext, ReconModule

RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"  # passive RDAP API


class WhoisLookupModule(ReconModule):
    """Gather WHOIS and RDAP metadata for a domain."""

    name = "whois"
    description = "Domain registration details via public RDAP."

    def run(self, context: ReconContext) -> ModuleResult:
        if not context.domain:
            return ModuleResult(self.name, None, error="Domain is required for WHOIS lookups.")

        session = context.session
        url = RDAP_ENDPOINT.format(domain=context.domain)
        try:
            response = session.get(url, timeout=context.timeout)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:  # pragma: no cover - defensive
            return ModuleResult(self.name, None, error=f"WHOIS lookup failed: {exc}")

        result = {
            "domain": data.get("ldhName"),
            "status": data.get("status"),
            "registrar": _extract_registrar(data.get("entities", [])),
            "events": _extract_events(data.get("events", [])),
            "nameservers": _extract_nameservers(data.get("nameservers", [])),
        }
        return ModuleResult(self.name, result)


def _extract_events(events: List[Dict[str, Any]]) -> Dict[str, str]:
    mapped: Dict[str, str] = {}
    for event in events:
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            mapped[action] = date
    return mapped


def _extract_nameservers(nameservers: List[Dict[str, Any]]) -> List[str]:
    values: List[str] = []
    for ns in nameservers:
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            values.append(name)
    return values


def _extract_registrar(entities: List[Dict[str, Any]]) -> Optional[str]:
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles or "registrant" in roles:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return str(item[3])
            handle = entity.get("handle")
            if handle:
                return str(handle)
    return None
