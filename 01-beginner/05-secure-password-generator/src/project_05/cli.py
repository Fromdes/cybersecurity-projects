"""CLI for the Secure Password Generator."""

from __future__ import annotations

import argparse
import sys

from project_05.core import DEFAULT_LENGTH, PasswordConfig, generate_multiple


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-gen",
        description="Generate cryptographically secure passwords using the OS CSPRNG.",
    )
    parser.add_argument(
        "--length", "-l", type=int, default=DEFAULT_LENGTH,
        help=f"Password length (default: {DEFAULT_LENGTH})",
    )
    parser.add_argument(
        "--count", "-n", type=int, default=1,
        help="Number of passwords to generate (default: 1)",
    )
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-special", action="store_true", help="Exclude special characters")
    parser.add_argument(
        "--no-ambiguous", action="store_true",
        help="Exclude visually ambiguous characters (0, O, 1, l, I)",
    )
    parser.add_argument(
        "--no-require-each", action="store_true",
        help="Do not require at least one character from each enabled class",
    )
    parser.add_argument(
        "--entropy", action="store_true",
        help="Print entropy estimate alongside each password",
    )
    return parser


def main() -> None:
    """Entry point for the password-gen CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        config = PasswordConfig(
            length=args.length,
            use_lower=not args.no_lower,
            use_upper=not args.no_upper,
            use_digits=not args.no_digits,
            use_special=not args.no_special,
            exclude_ambiguous=args.no_ambiguous,
            require_each_class=not args.no_require_each,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    passwords = generate_multiple(args.count, config)

    if args.entropy:
        bits = config.entropy_bits()
        for pw in passwords:
            print(f"{pw}  [{bits:.1f} bits]")
    else:
        for pw in passwords:
            print(pw)
    sys.exit(0)
