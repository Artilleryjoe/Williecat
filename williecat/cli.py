"""Command line interface for Williecat."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

from .modules import get_module_registry
from .product.workflow import PAWPRINTS_ENV_VAR, RunRequest, _resolve_pawprints_path, run_recon

BANNER = r"""/\_/\  Williecat v0.1
( o.o ) Reconnaissance with Instinct
^ <"""


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
        help="Comma-separated list of modules to run (default: all).",
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

    if not args.demo and not args.domain and not args.ip and not args.url:
        parser.error("At least one of --domain, --ip, or --url must be provided.")

    request = RunRequest(
        domain=args.domain,
        ip=args.ip,
        url=args.url,
        modules=args.modules,
        output_path=args.output,
        json_path=args.json_output,
        timeout=args.timeout,
        quiet=args.quiet,
        demo=args.demo,
    )

    if not args.quiet:
        print(BANNER)
        if args.demo:
            print("[demo] Using built-in sample data – no network requests performed.")

    try:
        response = run_recon(request)
    except KeyError as exc:
        parser.error(str(exc))

    if not args.quiet:
        _print_summary(response.results)

    return 0


def _print_summary(results: Iterable[object]) -> None:
    outcomes = {"success": 0, "blocked": 0, "no_data": 0, "timeout": 0}
    total = 0
    for result in results:
        total += 1
        if getattr(result, "outcome", None) in outcomes:
            outcomes[result.outcome] += 1

    print("Modules run:", total)
    print("Success:", outcomes["success"])
    print("Blocked:", outcomes["blocked"])
    print("No data:", outcomes["no_data"])
    print("Timeout:", outcomes["timeout"])


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
