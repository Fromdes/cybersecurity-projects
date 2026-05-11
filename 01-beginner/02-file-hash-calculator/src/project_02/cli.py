"""CLI for the File Hash Calculator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from project_02.core import (
    SUPPORTED_ALGORITHMS,
    hash_file,
    hash_file_all,
    hash_text,
    verify_hash,
)

_DEFAULT_ALGORITHM = "sha256"


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="file-hash",
        description="Compute and verify cryptographic file/text hashes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # hash subcommand
    h = sub.add_parser("hash", help="Hash a file or text string")
    src = h.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", "-f", type=Path, help="File to hash")
    src.add_argument("--text", "-t", help="Text string to hash")
    h.add_argument(
        "--algorithm", "-a",
        default=_DEFAULT_ALGORITHM,
        choices=sorted(SUPPORTED_ALGORITHMS),
        help=f"Hash algorithm (default: {_DEFAULT_ALGORITHM})",
    )
    h.add_argument("--all", action="store_true", dest="all_algos", help="Hash with all algorithms")
    h.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")

    # verify subcommand
    v = sub.add_parser("verify", help="Verify a file hash against an expected value")
    v.add_argument("file", type=Path, help="File to verify")
    v.add_argument("expected", help="Expected hex digest")
    v.add_argument(
        "--algorithm", "-a",
        default=_DEFAULT_ALGORITHM,
        choices=sorted(SUPPORTED_ALGORITHMS),
    )

    return parser


def _cmd_hash(args: argparse.Namespace) -> int:
    """Handle the hash subcommand."""
    if args.file and not args.file.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 1

    if args.all_algos:
        if args.text:
            print("Error: --all requires --file, not --text", file=sys.stderr)
            return 1
        results = hash_file_all(args.file)
        if args.as_json:
            print(json.dumps(results, indent=2))
        else:
            for alg, digest in results.items():
                print(f"{alg:<12} {digest}")
        return 0

    if args.file:
        digest = hash_file(args.file, args.algorithm)
    else:
        digest = hash_text(args.text, args.algorithm)

    if args.as_json:
        print(json.dumps({"algorithm": args.algorithm, "digest": digest}))
    else:
        print(f"{args.algorithm}  {digest}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Handle the verify subcommand."""
    if not args.file.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 1
    match = verify_hash(args.file, args.algorithm, args.expected)
    status = "OK" if match else "MISMATCH"
    print(f"{status}  {args.file}")
    return 0 if match else 2


def main() -> None:
    """Entry point for the file-hash CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    dispatch = {"hash": _cmd_hash, "verify": _cmd_verify}
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(handler(args))
