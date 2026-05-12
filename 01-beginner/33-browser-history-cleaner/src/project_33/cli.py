"""CLI for the Browser History Privacy Cleaner."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from project_33.core import (
    TRACKER_PATTERNS,
    delete_entries,
    find_profiles,
    scan_profile,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="history-cleaner",
        description="Scan and selectively remove browser history entries matching privacy patterns",
    )
    parser.add_argument(
        "--browser", choices=["chrome", "chromium", "firefox", "all"], default="all",
        help="Browser to target (default: all)",
    )
    parser.add_argument(
        "--pattern", action="append", dest="patterns", metavar="REGEX",
        help="Additional URL regex pattern to match (can repeat)",
    )
    parser.add_argument(
        "--profile", type=Path, metavar="PATH",
        help="Specific profile directory to target instead of auto-discovery",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scan", help="Show matching history entries without deleting")
    sub.add_parser("clean", help="Delete matching history entries (close browser first)")
    return parser


def _resolve_patterns(args: argparse.Namespace) -> tuple[str, ...]:
    extra = tuple(args.patterns or [])
    return TRACKER_PATTERNS + extra


def main() -> None:
    """Entry point for the Browser History Privacy Cleaner CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    patterns = _resolve_patterns(args)

    if args.profile:
        profiles_map: dict[str, list[Path]] = {
            args.browser if args.browser != "all" else "chrome": [args.profile]
        }
    else:
        profiles_map = find_profiles()
        if not profiles_map:
            print("No browser profiles found.", file=sys.stderr)
            sys.exit(1)

    target_browsers = (
        list(profiles_map.keys())
        if args.browser == "all"
        else [args.browser]
    )

    total_matched = 0
    total_deleted = 0

    for browser in target_browsers:
        if browser not in profiles_map:
            continue
        for profile_path in profiles_map[browser]:
            try:
                if args.command == "scan":
                    result = scan_profile(profile_path, browser, patterns)
                    total_matched += result.matched_entries
                    print(f"\n[{browser}] {profile_path}")
                    print(f"  Total entries : {result.total_entries}")
                    print(f"  Matched       : {result.matched_entries}")
                    for entry in result.entries[:20]:
                        print(f"    {entry.visit_time.date()} {entry.url[:80]}")
                    if result.matched_entries > 20:
                        print(f"    ... and {result.matched_entries - 20} more")

                elif args.command == "clean":
                    count = delete_entries(profile_path, browser, patterns)
                    total_deleted += count
                    print(f"[{browser}] {profile_path}: deleted {count} entries")

            except FileNotFoundError as exc:
                print(f"  Warning: {exc}", file=sys.stderr)
            except Exception as exc:
                print(f"  Error ({browser}/{profile_path}): {exc}", file=sys.stderr)

    if args.command == "scan":
        print(f"\nTotal matched entries: {total_matched}")
    else:
        print(f"\nTotal deleted entries: {total_deleted}")
