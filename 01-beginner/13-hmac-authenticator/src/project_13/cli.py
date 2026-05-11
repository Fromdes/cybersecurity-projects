"""CLI for the HMAC Message Authenticator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from project_13.core import (
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    compute_hmac,
    derive_key_from_passphrase,
    sign_file,
    verify_file,
    verify_hmac,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hmac-auth",
        description="Compute and verify HMAC-SHA256/512 message authentication codes.",
    )
    parser.add_argument(
        "--algorithm", "-a",
        choices=sorted(SUPPORTED_ALGORITHMS),
        default=DEFAULT_ALGORITHM,
    )
    parser.add_argument("--key", "-k", required=True, help="Secret key (passphrase)")

    sub = parser.add_subparsers(dest="command", required=True)

    # sign message
    sm = sub.add_parser("sign", help="Compute HMAC of a message string")
    sm.add_argument("message", help="Message to authenticate")

    # verify message
    vm = sub.add_parser("verify", help="Verify HMAC of a message string")
    vm.add_argument("message", help="Original message")
    vm.add_argument("digest", help="Expected hex HMAC digest")

    # sign file
    sf = sub.add_parser("sign-file", help="Compute HMAC of a file")
    sf.add_argument("file", type=Path)

    # verify file
    vf = sub.add_parser("verify-file", help="Verify HMAC of a file")
    vf.add_argument("file", type=Path)
    vf.add_argument("digest", help="Expected hex HMAC digest")

    return parser


def main() -> None:
    """Entry point for the hmac-auth CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    key = derive_key_from_passphrase(args.key, algorithm=args.algorithm)

    try:
        if args.command == "sign":
            result = compute_hmac(args.message.encode(), key, algorithm=args.algorithm)
            print(result.digest)
            sys.exit(0)

        if args.command == "verify":
            ok = verify_hmac(args.message.encode(), key, args.digest, algorithm=args.algorithm)
            if ok:
                print("VALID")
                sys.exit(0)
            print("INVALID", file=sys.stderr)
            sys.exit(1)

        if args.command == "sign-file":
            result = sign_file(args.file, key, algorithm=args.algorithm)
            print(result.digest)
            sys.exit(0)

        if args.command == "verify-file":
            ok = verify_file(args.file, key, args.digest, algorithm=args.algorithm)
            if ok:
                print("VALID")
                sys.exit(0)
            print("INVALID", file=sys.stderr)
            sys.exit(1)

    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
