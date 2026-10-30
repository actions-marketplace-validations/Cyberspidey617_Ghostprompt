"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .report import pretty, to_json, to_sarif
from .rules import ALL_RULES, SEVERITY_ORDER
from .scanner import ScanResult, scan_paths, scan_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghostprompt",
        description="Find hidden prompt injections, ASCII smuggling and Trojan Source characters "
                    "in repos, docs, MCP configs and AI agent rules files.",
    )
    p.add_argument("paths", nargs="*", default=["."], help="files or directories to scan ('-' for stdin)")
    p.add_argument("-f", "--format", choices=["pretty", "json", "sarif"], default="pretty")
    p.add_argument("-o", "--output", help="write report to a file instead of stdout")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "none"], default="high",
                   help="exit 1 if a finding at or above this severity exists (default: high)")
    p.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low",
                   help="hide findings below this severity")
    p.add_argument("-e", "--exclude", action="append", default=[], help="glob to exclude (repeatable)")
    p.add_argument("--max-size", type=int, default=2_000_000, help="skip files larger than N bytes")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--list-rules", action="store_true", help="print all rules and exit")
    p.add_argument("-V", "--version", action="version", version=f"ghostprompt {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        for r in ALL_RULES:
            print(f"{r.id}  {r.severity:<8}  {r.name:<30} {r.description}")
        return 0

    if args.paths == ["-"]:
        result = ScanResult(findings=scan_text(sys.stdin.read(), "<stdin>"), files_scanned=1)
    else:
        missing = [p for p in args.paths if not os.path.exists(p)]
        if missing:
            print(f"ghostprompt: path not found: {', '.join(missing)}", file=sys.stderr)
            return 2
        result = scan_paths(args.paths, excludes=args.exclude, max_size=args.max_size)

    floor = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in result.findings if SEVERITY_ORDER[f.severity] >= floor]

    if args.format == "json":
        report = to_json(result, findings)
    elif args.format == "sarif":
        report = to_sarif(result, findings)
    else:
        use_color = not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        report = pretty(result, findings, color=use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        try:
            print(report)
        except UnicodeEncodeError:  # e.g. legacy Windows consoles
            sys.stdout.buffer.write((report + "\n").encode("utf-8", errors="replace"))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
