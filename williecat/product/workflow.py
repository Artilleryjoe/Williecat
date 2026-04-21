"""Product workflow orchestration for Williecat runs."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from ..core import ModuleResult, ReconContext, ReconModule
from ..demo import load_demo_run
from ..http import HttpSession
from ..modules import get_module_registry, iter_modules
from ..modules import reporter as reporter_utils

DEFAULT_MODULES = ["whois", "headers", "dns", "certs", "ip", "social"]
PAWPRINTS_ENV_VAR = "WILLIECAT_PAWPRINTS"


@dataclass
class RunRequest:
    """Inputs needed to run a reconnaissance workflow."""

    domain: str | None = None
    ip: str | None = None
    url: str | None = None
    modules: str | None = None
    output_path: Path | None = None
    json_path: Path | None = None
    timeout: float = 10.0
    quiet: bool = False
    demo: bool = False


@dataclass
class RunResponse:
    """Outputs returned from the reconnaissance workflow."""

    context: ReconContext
    modules: List[str]
    results: List[ModuleResult]


def resolve_modules(raw_modules: str | None) -> List[str]:
    """Resolve user supplied module text into canonical module names."""

    if not raw_modules:
        return list(DEFAULT_MODULES)
    return iter_modules(raw_modules.split(","))


def run_recon(request: RunRequest) -> RunResponse:
    """Execute a full reconnaissance run from a single request object."""

    if request.demo:
        context, results = load_demo_run()
        modules = [result.module for result in results]
    else:
        modules = resolve_modules(request.modules)

        context = ReconContext(
            domain=request.domain,
            ip_address=request.ip,
            base_url=request.url,
            timeout=request.timeout,
            session=HttpSession(),
        )
        results = _execute_modules(context, modules, quiet=request.quiet)

    _emit_reports(
        context,
        modules,
        results,
        output_path=request.output_path,
        json_path=request.json_path,
        quiet=request.quiet,
    )

    return RunResponse(context=context, modules=modules, results=results)


def _execute_modules(context: ReconContext, modules: Iterable[str], *, quiet: bool) -> List[ModuleResult]:
    registry = get_module_registry()
    results: List[ModuleResult] = []
    for name in modules:
        module_cls = registry[name]
        module: ReconModule = module_cls()
        result = module.run(context)
        results.append(result)
        if not quiet:
            print(f"[{result.module.upper()}]")
            print(f"  Outcome: {result.outcome}")
            if result.outcome == "success":
                if isinstance(result.data, dict):
                    for key, value in result.data.items():
                        print(f"  {key}: {value}")
                elif isinstance(result.data, list):
                    for item in result.data:
                        print(f"  - {item}")
            elif result.outcome == "no_data":
                print("  No data collected.")
            if result.warnings:
                for warning in result.warnings:
                    print(f"  ! {warning}")
            print("soft paws only.")
    return results


def _emit_reports(
    context: ReconContext,
    modules: Iterable[str],
    results: List[ModuleResult],
    *,
    output_path: Path | None,
    json_path: Path | None,
    quiet: bool,
) -> None:
    if output_path:
        markdown = reporter_utils.render_markdown(context, results)
        reporter_utils.write_markdown(output_path, markdown)
        if not quiet:
            print(f"[+] Markdown report written to {output_path}")

    if json_path:
        reporter_utils.write_json(json_path, results)
        if not quiet:
            print(f"[+] JSON report written to {json_path}")

    _log_run(context, modules, results, output_path, json_path, quiet=quiet)


def _log_run(
    context: ReconContext,
    modules: Iterable[str],
    results: Iterable[ModuleResult],
    output_path: Path | None,
    json_path: Path | None,
    *,
    quiet: bool,
) -> None:
    pawprints_path = _resolve_pawprints_path()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": context.domain,
        "ip_address": context.ip_address,
        "base_url": context.base_url,
        "modules": list(modules),
        "output": str(output_path) if output_path else None,
        "json_output": str(json_path) if json_path else None,
        "results": [result.as_dict() for result in results],
    }

    try:
        with pawprints_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:  # pragma: no cover - best effort logging
        if not quiet:
            print(f"[!] Failed to write pawprints log: {exc}", file=sys.stderr)


def _resolve_pawprints_path() -> Path:
    """Return the path where pawprints logs should be written."""

    override = os.environ.get(PAWPRINTS_ENV_VAR)
    return Path(override) if override else Path("pawprints.log")
