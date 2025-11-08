"""Command line interface for Williecat."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, List

from .http import HttpSession
from .modules import ModuleResult, ReconContext, ReconModule, get_module_registry, iter_modules
from .modules import reporter as reporter_utils

DEFAULT_MODULES = ["whois", "dns", "certs", "headers", "ip", "social"]


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
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list_modules:
        for name, module in get_module_registry().items():
            print(f"{name}: {module.description}")
        return 0

    modules = DEFAULT_MODULES
    if args.modules:
        modules = iter_modules(args.modules.split(","))

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

    results: List[ModuleResult] = []
    registry = get_module_registry()

    for name in modules:
        module_cls = registry[name]
        module: ReconModule = module_cls()
        result = module.run(context)
        results.append(result)
        _print_inline(result)

    if args.output:
        markdown = reporter_utils.render_markdown(context, results)
        reporter_utils.write_markdown(args.output, markdown)
        print(f"[+] Markdown report written to {args.output}")

    if args.json_output:
        reporter_utils.write_json(args.json_output, results)
        print(f"[+] JSON report written to {args.json_output}")

    return 0


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


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
