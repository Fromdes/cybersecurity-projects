"""CLI for the File Integrity Verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from project_03.core import (
    BASELINE_FILENAME,
    IntegrityReport,
    check_integrity,
    create_baseline,
    load_baseline,
    save_baseline,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor — detect unauthorized file modifications.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    init = sub.add_parser("init", help="Create a new integrity baseline")
    init.add_argument("directory", type=Path, help="Directory to baseline")
    init.add_argument(
        "--output", "-o", type=Path, help="Baseline output path (default: <dir>/.integrity_baseline.json)"
    )
    init.add_argument("--exclude", nargs="*", default=[], help="Filenames to exclude")

    # check
    check = sub.add_parser("check", help="Check directory against existing baseline")
    check.add_argument("directory", type=Path)
    check.add_argument(
        "--baseline", "-b", type=Path, help="Baseline file (default: <dir>/.integrity_baseline.json)"
    )
    check.add_argument("--json", action="store_true", dest="as_json")
    check.add_argument("--exclude", nargs="*", default=[])

    return parser


def _cmd_init(args: argparse.Namespace) -> int:
    if not args.directory.is_dir():
        print(f"Error: not a directory: {args.directory}", file=sys.stderr)
        return 1
    output = args.output or (args.directory / BASELINE_FILENAME)
    exclude = set(args.exclude) if args.exclude else None
    baseline = create_baseline(args.directory, exclude=exclude)
    save_baseline(baseline, output)
    print(f"Baseline created: {output} ({len(baseline)} files)")
    return 0


def _format_report(report: IntegrityReport, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps({
            "clean": report.is_clean,
            "checked_at": report.checked_at,
            "new": report.new_files,
            "deleted": report.deleted_files,
            "modified": report.modified_files,
        }, indent=2))
        return
    print(report.summary())
    for f in report.new_files:
        print(f"  [NEW]      {f}")
    for f in report.deleted_files:
        print(f"  [DELETED]  {f}")
    for f in report.modified_files:
        print(f"  [MODIFIED] {f}")


def _cmd_check(args: argparse.Namespace) -> int:
    if not args.directory.is_dir():
        print(f"Error: not a directory: {args.directory}", file=sys.stderr)
        return 1
    baseline_path = args.baseline or (args.directory / BASELINE_FILENAME)
    try:
        baseline = load_baseline(baseline_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    exclude = set(args.exclude) if args.exclude else None
    report = check_integrity(args.directory, baseline, exclude=exclude)
    _format_report(report, as_json=args.as_json)
    return 0 if report.is_clean else 2


def main() -> None:
    """Entry point for the fim CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    dispatch = {"init": _cmd_init, "check": _cmd_check}
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(handler(args))
