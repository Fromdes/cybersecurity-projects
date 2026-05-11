"""CLI for the Argon2id/PBKDF2 Password Hasher."""

from __future__ import annotations

import argparse
import getpass
import sys

from project_14.core import HashAlgorithm, hash_password, needs_rehash, verify_password


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passwd-hash",
        description="Hash and verify passwords with Argon2id or PBKDF2-SHA256.",
    )
    parser.add_argument(
        "--algorithm", "-a",
        choices=["argon2id", "pbkdf2"],
        default="argon2id",
        help="Hashing algorithm (default: argon2id)",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="Read password from stdin instead of interactive prompt",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("hash", help="Hash a password")

    v = sub.add_parser("verify", help="Verify a password against a stored hash")
    v.add_argument("encoded", help="Stored hash string")

    rh = sub.add_parser("check-rehash", help="Check if an Argon2id hash needs upgrading")
    rh.add_argument("encoded", help="Stored Argon2id PHC string")

    return parser


def _read_password(use_stdin: bool) -> str:
    if use_stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Password: ")


def main() -> None:
    """Entry point for the passwd-hash CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    algorithm = HashAlgorithm(args.algorithm)

    if args.command == "check-rehash":
        stale = needs_rehash(args.encoded)
        print("NEEDS_REHASH" if stale else "OK")
        sys.exit(0)

    password = _read_password(args.stdin)
    if not password:
        print("Error: password must not be empty", file=sys.stderr)
        sys.exit(1)

    if args.command == "hash":
        result = hash_password(password, algorithm=algorithm)
        print(result.encoded)
        sys.exit(0)

    # verify
    ok = verify_password(password, args.encoded, algorithm=algorithm)
    if ok:
        print("VALID")
        sys.exit(0)
    print("INVALID", file=sys.stderr)
    sys.exit(1)
