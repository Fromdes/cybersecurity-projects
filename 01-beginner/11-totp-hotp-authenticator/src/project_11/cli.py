"""CLI for the TOTP/HOTP Authenticator."""

from __future__ import annotations

import argparse
import sys

from project_11.core import (
    TOTPConfig,
    generate_hotp,
    generate_secret,
    generate_totp,
    provisioning_uri,
    verify_hotp,
    verify_totp,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="otp",
        description="TOTP/HOTP two-factor authentication tool (RFC 6238/4226).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate-secret
    sub.add_parser("generate-secret", help="Generate a new base32 shared secret")

    # totp subcommand
    t = sub.add_parser("totp", help="Generate or verify a TOTP code")
    t.add_argument("--secret", required=True, help="Base32 shared secret")
    tmode = t.add_mutually_exclusive_group(required=True)
    tmode.add_argument("--generate", action="store_true")
    tmode.add_argument("--verify", metavar="CODE", help="OTP code to verify")
    t.add_argument("--issuer", default="DefensivePortfolio")
    t.add_argument("--account", default="user@example.com")
    t.add_argument("--interval", type=int, default=30)
    t.add_argument("--uri", action="store_true", help="Print provisioning URI")

    # hotp subcommand
    h = sub.add_parser("hotp", help="Generate or verify an HOTP code")
    h.add_argument("--secret", required=True)
    h.add_argument("--counter", type=int, required=True)
    hmode = h.add_mutually_exclusive_group(required=True)
    hmode.add_argument("--generate", action="store_true")
    hmode.add_argument("--verify", metavar="CODE")

    return parser


def _cmd_totp(args: argparse.Namespace) -> int:
    config = TOTPConfig(
        secret=args.secret,
        issuer=args.issuer,
        account=args.account,
        interval=args.interval,
    )
    if args.uri:
        print(provisioning_uri(config))
    if args.generate:
        print(generate_totp(config))
        return 0
    # verify mode
    valid = verify_totp(args.verify, config)
    if valid:
        print("VALID")
        return 0
    print("INVALID", file=sys.stderr)
    return 1


def _cmd_hotp(args: argparse.Namespace) -> int:
    if args.generate:
        print(generate_hotp(args.secret, args.counter))
        return 0
    next_counter = verify_hotp(args.verify, args.secret, args.counter)
    if next_counter is not None:
        print(f"VALID  (next counter: {next_counter})")
        return 0
    print("INVALID", file=sys.stderr)
    return 1


def main() -> None:
    """Entry point for the otp CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "generate-secret":
        print(generate_secret())
        sys.exit(0)
    dispatch = {"totp": _cmd_totp, "hotp": _cmd_hotp}
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(handler(args))
