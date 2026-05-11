"""CLI for the QR Code TOTP Provisioner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from project_12.core import (
    DEFAULT_ACCOUNT,
    DEFAULT_DIGITS,
    DEFAULT_INTERVAL,
    DEFAULT_ISSUER,
    TOTPParams,
    generate_uri,
    render_png,
    render_terminal,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="totp-qr",
        description="Generate QR codes for TOTP authenticator app provisioning.",
    )
    parser.add_argument("--secret", required=True, help="Base32 shared secret")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help="Service name")
    parser.add_argument("--account", default=DEFAULT_ACCOUNT, help="User account label")
    parser.add_argument("--digits", type=int, default=DEFAULT_DIGITS)
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)

    out = parser.add_mutually_exclusive_group(required=True)
    out.add_argument("--png", metavar="FILE", type=Path, help="Save QR code as PNG")
    out.add_argument("--terminal", action="store_true", help="Print QR code to terminal")
    out.add_argument("--uri", action="store_true", help="Print otpauth:// URI only")

    return parser


def main() -> None:
    """Entry point for the totp-qr CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    params = TOTPParams(
        secret=args.secret,
        issuer=args.issuer,
        account=args.account,
        digits=args.digits,
        interval=args.interval,
    )
    uri = generate_uri(params)

    if args.uri:
        print(uri)
        sys.exit(0)

    if args.terminal:
        print(render_terminal(uri))
        sys.exit(0)

    # PNG output
    try:
        render_png(uri, args.png)
        print(f"QR code saved to {args.png}")
        sys.exit(0)
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
