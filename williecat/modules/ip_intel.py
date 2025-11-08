"""Passive IP intelligence module."""
from __future__ import annotations

import socket
from typing import Any, Dict, Optional

from . import ModuleResult, ReconContext, ReconModule

IPINFO_ENDPOINT = "https://ipinfo.io/{ip}/json"


class IpIntelModule(ReconModule):
    """Retrieve ASN and geolocation information for an IP."""

    name = "ip"
    description = "Passive IP intelligence using ipinfo.io."

    def run(self, context: ReconContext) -> ModuleResult:
        ip_address = context.ip_address
        if not ip_address and context.domain:
            ip_address = _resolve_domain(context.domain)
        if not ip_address:
            return ModuleResult(self.name, None, error="An IP address or resolvable domain is required.")

        session = context.session
        url = IPINFO_ENDPOINT.format(ip=ip_address)
        try:
            response = session.get(url, timeout=context.timeout)
            response.raise_for_status()
            payload: Dict[str, Any] = response.json()
        except Exception as exc:  # pragma: no cover - defensive
            return ModuleResult(self.name, None, error=f"ipinfo lookup failed: {exc}")

        data = {
            "ip": payload.get("ip", ip_address),
            "hostname": payload.get("hostname"),
            "city": payload.get("city"),
            "region": payload.get("region"),
            "country": payload.get("country"),
            "loc": payload.get("loc"),
            "org": payload.get("org"),
            "asn": payload.get("asn"),
            "bogon": payload.get("bogon"),
        }
        return ModuleResult(self.name, data)


def _resolve_domain(domain: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror:
        return None
    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            return sockaddr[0]
    return None
