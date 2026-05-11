"""CLI for the Have-I-Been-Pwned Client."""

from __future__ import annotations

import argparse
import getpass
import sys

import requests

from project_07.core import check_hash, check_password


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hibp-check",
        description=(
            "Check if a password or SHA-1 hash appears in known data breaches "
            "via the HIBP k-anonymity API. The full password/hash is NEVER sent."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    pw = sub.add_parser("password", help="Check a password (hashed locally before query)")
    src = pw.add_mutually_exclusive_group()
    src.add_argument("password", nargs="?", help="Password to check (omit for prompt)")
    src.add_argument("--stdin", action="store_true", help="Read password from stdin")

    hsh = sub.add_parser("hash", help="Check a pre-computed SHA-1 hash")
    hsh.add_argument("sha1_hash", help="40-character SHA-1 hex digest")

    return parser


def _get_password(args: argparse.Namespace) -> str:
    if getattr(args, "password", None):
        return args.password
    if getattr(args, "stdin", False):
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Password to check: ")


def main() -> None:
    """Entry point for the hibp-check CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        if args.command == "password":
            password = _get_password(args)
            count = check_password(password)
        else:
            count = check_hash(args.sha1_hash)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except requests.Timeout:
        print("Error: HIBP API timed out. Try again later.", file=sys.stderr)
        sys.exit(2)
    except requests.ConnectionError:
        print("Error: Cannot reach HIBP API. Check your network connection.", file=sys.stderr)
        sys.exit(2)
    except requests.HTTPError as exc:
        print(f"Error: HIBP API returned {exc.response.status_code}", file=sys.stderr)
        sys.exit(2)

    if count == 0:
        print("SAFE — not found in any known breaches.")
        sys.exit(0)
    else:
        print(f"PWNED — found {count:,} times in known data breaches!")
        print("Change this password immediately.")
        sys.exit(1)
