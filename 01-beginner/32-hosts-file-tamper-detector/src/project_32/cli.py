"""CLI for the Hosts File Tamper Detector."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from project_32.core import (
    DEFAULT_HOSTS_PATH,
    TamperResult,
    detect_tampering,
    load_baseline,
    parse_hosts,
    save_baseline,
)

DEFAULT_BASELINE: Path = Path("hosts_baseline.json")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hosts-tamper-detect",
        description="Detect unauthorised changes to /etc/hosts",
    )
    parser.add_argument(
        "--hosts", type=Path, default=DEFAULT_HOSTS_PATH,
        help=f"Path to hosts file (default: {DEFAULT_HOSTS_PATH})",
    )
    parser.add_argument(
        "--baseline", type=Path, default=DEFAULT_BASELINE,
        help="Path to baseline JSON file (default: hosts_baseline.json)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("baseline", help="Save current hosts file as baseline")
    sub.add_parser("check", help="Check hosts file against baseline")
    sub.add_parser("show", help="Display current hosts file entries")
    return parser


def _print_result(result: TamperResult) -> None:
    status = "TAMPERED" if result.is_tampered else "OK"
    print(f"Status       : {status}")
    print(f"Hash changed : {'YES' if result.hash_changed else 'no'}")
    if result.added:
        print("Added entries:")
        for line in result.added:
            print(f"  + {line}")
    if result.removed:
        print("Removed entries:")
        for line in result.removed:
            print(f"  - {line}")
    if result.suspicious:
        print("SUSPICIOUS redirects detected:")
        for line in result.suspicious:
            print(f"  ! {line}")


def main() -> None:
    """Entry point for the Hosts File Tamper Detector CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    hosts_path: Path = args.hosts
    baseline_path: Path = args.baseline

    try:
        if args.command == "baseline":
            b = save_baseline(hosts_path, baseline_path)
            entries = b["entries"]
            assert isinstance(entries, list)
            print(f"Baseline saved: {len(entries)} entries, SHA-256={b['hash']}")

        elif args.command == "check":
            baseline = load_baseline(baseline_path)
            result = detect_tampering(baseline, hosts_path)
            _print_result(result)
            if result.is_tampered:
                sys.exit(2)

        elif args.command == "show":
            entries = parse_hosts(hosts_path)
            for e in entries:
                aliases = " ".join(e.aliases)
                print(f"{e.ip:<20} {e.hostname}  {aliases}")

    except FileNotFoundError as exc:
        print(f"File not found: {exc}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as exc:
        print(f"Permission denied (try sudo): {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
