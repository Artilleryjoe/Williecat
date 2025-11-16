"""Command line interface for Williecat."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from .core import ModuleResult, ReconContext, ReconModule
from .demo import load_demo_run
from .http import HttpSession
from .modules import get_module_registry, iter_modules
from .modules import reporter as reporter_utils

BANNER = r"""/\_/\  Williecat v0.1
( o.o ) Reconnaissance with Instinct
^ <"""

DEFAULT_MODULES = ["whois", "headers", "dns", "certs", "ip", "social"]
PAWPRINTS_PATH = Path("pawprints.log")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="williecat",
        description="Williecat – Reconnaissance with Instinct",
    )
    parser.add_argument("--domain", help="Target domain for reconnaissance.")
    parser.add_argument("--ip", help="Target IP address (optional).")
    parser.add_argument("--url", help="Full URL for HTTP header collection.")
    parser.add_argument(
        "--modules",
        help="Comma separated list of modules to run (default: all).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write Markdown report to the specified file.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Write JSON output to the specified file.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List available modules and exit.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress banner and inline module output.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate canned output without performing network requests.",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list_modules:
        for name, module in get_module_registry().items():
            print(f"{name}: {module.description}")
        return 0

    if args.demo:
        context, results = load_demo_run()
        modules = [result.module for result in results]
        if not args.quiet:
            print(BANNER)
            print("[demo] Using built-in sample data – no network requests performed.")
            for result in results:
                _display_result(result)
    else:
        modules: List[str]
        if args.modules:
            try:
                modules = iter_modules(args.modules.split(","))
            except KeyError as exc:
                parser.error(str(exc))
        else:
            modules = list(DEFAULT_MODULES)

        if not args.domain and not args.ip and not args.url:
            parser.error("At least one of --domain, --ip, or --url must be provided.")

        session = HttpSession()
        session.update_headers({"User-Agent": "Williecat/1.0"})

        context = ReconContext(
            domain=args.domain,
            ip_address=args.ip,
            base_url=args.url,
            timeout=args.timeout,
            session=session,
        )

        if not args.quiet:
            print(BANNER)
        results = _execute_modules(context, modules, quiet=args.quiet)

    _emit_reports(
        context,
        modules,
        results,
        output_path=args.output,
        json_path=args.json_output,
        quiet=args.quiet,
    )

    return 0


def _execute_modules(context: ReconContext, modules: Iterable[str], *, quiet: bool) -> List[ModuleResult]:
    registry = get_module_registry()
    results: List[ModuleResult] = []
    for name in modules:
        module_cls = registry[name]
        module: ReconModule = module_cls()
        result = module.run(context)
        results.append(result)
        _display_result(result, quiet=quiet)
    return results


def _print_inline(result: ModuleResult) -> None:
    header = f"[{result.module.upper()}]"
    if result.error:
        print(f"{header} Error: {result.error}")
        return
    print(header)
    if result.data is None:
        print("  No data collected.")
    elif isinstance(result.data, dict):
        for key, value in result.data.items():
            print(f"  {key}: {value}")
    else:
        for item in result.data:
            print(f"  - {item}")
    if result.warnings:
        for warning in result.warnings:
            print(f"  ! {warning}")


def _display_result(result: ModuleResult, *, quiet: bool = False) -> None:
    if quiet:
        return
    _print_inline(result)
    print("soft paws only.")


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
        with PAWPRINTS_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:  # pragma: no cover - best effort logging
        if not quiet:
            print(f"[!] Failed to write pawprints log: {exc}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
