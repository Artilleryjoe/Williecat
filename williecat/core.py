"""Core data structures for Williecat reconnaissance modules."""
from __future__ import annotations

import socket
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


OUTCOME_BLOCKED = "blocked"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_NO_DATA = "no_data"
OUTCOME_SUCCESS = "success"


def classify_exception(exc: Exception) -> str:
    """Classify an exception into a stable outcome."""

    if isinstance(exc, (TimeoutError, socket.timeout)):
        return OUTCOME_TIMEOUT
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return OUTCOME_TIMEOUT
        if "timed out" in str(reason).lower():
            return OUTCOME_TIMEOUT
    if "timed out" in str(exc).lower():
        return OUTCOME_TIMEOUT
    return OUTCOME_BLOCKED


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
    outcome: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.outcome is None:
            if self.error:
                self.outcome = OUTCOME_BLOCKED
            elif self.data is None:
                self.outcome = OUTCOME_NO_DATA
            else:
                self.outcome = OUTCOME_SUCCESS

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation of the result."""

        return {
            "module": self.module,
            "outcome": self.outcome,
            "data": self.data,
            "warnings": list(self.warnings),
            "error": self.error,
        }

    @classmethod
    def failure(
        cls,
        module: str,
        message: str,
        *,
        outcome: str = OUTCOME_BLOCKED,
        warnings: Optional[List[str]] = None,
    ) -> "ModuleResult":
        return cls(module, None, warnings=warnings or [], error=message, outcome=outcome)

    @classmethod
    def from_exception(
        cls,
        module: str,
        exc: Exception,
        *,
        warnings: Optional[List[str]] = None,
    ) -> "ModuleResult":
        outcome = classify_exception(exc)
        return cls(module, None, warnings=warnings or [], error=str(exc), outcome=outcome)


class ReconModule:
    """Base class for reconnaissance modules."""

    name: str = "module"
    description: str = ""

    def run(self, context: ReconContext) -> ModuleResult:  # pragma: no cover - interface
        raise NotImplementedError
