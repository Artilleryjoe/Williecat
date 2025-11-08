"""Module registry for Williecat."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional


@dataclass
class ReconContext:
    """Shared context for modules to access target metadata."""

    domain: Optional[str] = None
    ip_address: Optional[str] = None
    base_url: Optional[str] = None
    timeout: float = 10.0
    session: Any = None


@dataclass
class ModuleResult:
    """Structured result from a module run."""

    module: str
    data: Mapping[str, Any] | List[Any] | None
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "data": self.data,
            "warnings": self.warnings,
            "error": self.error,
        }


class ReconModule:
    """Base class for reconnaissance modules."""

    name: str = "module"
    description: str = ""

    def run(self, context: ReconContext) -> ModuleResult:  # pragma: no cover - interface
        raise NotImplementedError


def get_module_registry() -> Dict[str, type[ReconModule]]:
    """Return the mapping of module names to their classes."""

    from .whois_lookup import WhoisLookupModule
    from .dns_enum import DnsEnumModule
    from .cert_scraper import CertificateScraperModule
    from .header_sniffer import HeaderSnifferModule
    from .ip_intel import IpIntelModule
    from .social_trace import SocialTraceModule

    return {
        WhoisLookupModule.name: WhoisLookupModule,
        DnsEnumModule.name: DnsEnumModule,
        CertificateScraperModule.name: CertificateScraperModule,
        HeaderSnifferModule.name: HeaderSnifferModule,
        IpIntelModule.name: IpIntelModule,
        SocialTraceModule.name: SocialTraceModule,
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
