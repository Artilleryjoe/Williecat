"""Core data structures for Williecat reconnaissance modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


@dataclass
class ReconContext:
    """Shared execution context provided to every module."""

    domain: Optional[str] = None
    ip_address: Optional[str] = None
    base_url: Optional[str] = None
    timeout: float = 10.0
    session: Any = None


@dataclass
class ModuleResult:
    """Structured result returned from a module run."""

    module: str
    data: Mapping[str, Any] | List[Any] | None
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation of the result."""

        return {
            "module": self.module,
            "data": self.data,
            "warnings": list(self.warnings),
            "error": self.error,
        }


class ReconModule:
    """Base class for reconnaissance modules."""

    name: str = "module"
    description: str = ""

    def run(self, context: ReconContext) -> ModuleResult:  # pragma: no cover - interface
        raise NotImplementedError

