"""CLI for the Secure Token Generator."""
from __future__ import annotations

import argparse
import sys

from project_15.core import TokenFormat, estimate_entropy, generate_token


def _add_generate_cmd(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("generate", help="Generate a secure token")
    p.add_argument(
        "--format", "-f",
        choices=[f.value for f in TokenFormat],
        default=TokenFormat.HEX.value,
        help="Token format (default: hex)",
    )
    p.add_argument(
        "--bytes", "-b",
        type=int, default=32, dest="byte_length", metavar="N",
        help="Random bytes to use (default: 32, range: 16–512)",
    )
    p.add_argument(
        "--count", "-n",
        type=int, default=1, metavar="COUNT",
        help="Number of tokens to generate (default: 1)",
    )
    p.add_argument("--quiet", "-q", action="store_true", help="Token only, no metadata")


def _add_entropy_cmd(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("entropy", help="Estimate entropy of a token format")
    p.add_argument("length", type=int, help="Token character length")
    p.add_argument(
        "--charset", type=int, default=16, metavar="SIZE",
        help="Charset size (default: 16 for hex)",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sectoken",
        description="Generate cryptographically secure tokens (CSPRNG-backed)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_generate_cmd(sub)
    _add_entropy_cmd(sub)
    return parser


def _cmd_generate(args: argparse.Namespace) -> None:
    fmt = TokenFormat(args.format)
    for _ in range(args.count):
        result = generate_token(fmt=fmt, byte_length=args.byte_length)
        if args.quiet:
            print(result.token)
        else:
            print(
                f"{result.token}  "
                f"[{result.format.value}, {result.entropy_bits:.1f} bits]"
            )


def _cmd_entropy(args: argparse.Namespace) -> None:
    try:
        bits = estimate_entropy(args.length, args.charset)
        print(f"Estimated entropy: {bits:.1f} bits")
        strength = "STRONG" if bits >= 128 else ("ADEQUATE" if bits >= 80 else "WEAK")
        print(f"Strength: {strength}")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Entry point for the secure token generator CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if args.command == "generate":
            _cmd_generate(args)
        elif args.command == "entropy":
            _cmd_entropy(args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
