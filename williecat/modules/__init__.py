"""Module registry for Williecat."""
from __future__ import annotations

from typing import Dict, Iterable, List

from ..core import ModuleResult, ReconContext, ReconModule


def get_module_registry() -> Dict[str, type[ReconModule]]:
    """Return the mapping of module names to their classes."""

    from .whois_lookup import WhoisLookupModule
    from .dns_enum import DnsEnumModule
    from .cert_scraper import CertificateScraperModule
    from .header_sniffer import HeaderSnifferModule
    from .ip_intel import IpIntelModule
    return {
        WhoisLookupModule.name: WhoisLookupModule,
        DnsEnumModule.name: DnsEnumModule,
        CertificateScraperModule.name: CertificateScraperModule,
        HeaderSnifferModule.name: HeaderSnifferModule,
        IpIntelModule.name: IpIntelModule,
    }


def iter_modules(module_names: Iterable[str]) -> List[str]:
    """Return validated module names preserving order."""

    registry = get_module_registry()
    resolved: List[str] = []
    for name in module_names:
        key = name.strip().lower()
        if key not in registry:
            raise KeyError(f"Unknown module: {name}")
        resolved.append(key)
    return resolved
