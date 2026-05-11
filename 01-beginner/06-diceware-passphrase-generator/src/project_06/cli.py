"""CLI for the Diceware Passphrase Generator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from project_06.core import (
    DEFAULT_SEPARATOR,
    DEFAULT_WORD_COUNT,
    entropy_warning,
    generate_passphrase,
    load_wordlist,
    passphrase_entropy,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="diceware",
        description="Generate cryptographically secure Diceware passphrases.",
    )
    parser.add_argument(
        "--words", "-w", type=int, default=DEFAULT_WORD_COUNT,
        help=f"Number of words (default: {DEFAULT_WORD_COUNT})",
    )
    parser.add_argument(
        "--count", "-n", type=int, default=1,
        help="Number of passphrases to generate (default: 1)",
    )
    parser.add_argument(
        "--separator", "-s", default=DEFAULT_SEPARATOR,
        help=f"Word separator (default: '{DEFAULT_SEPARATOR}')",
    )
    parser.add_argument(
        "--wordlist", "-W", type=Path, default=None,
        help="Path to a custom wordlist file (EFF format or one word per line)",
    )
    parser.add_argument(
        "--entropy", action="store_true",
        help="Show entropy estimate alongside each passphrase",
    )
    return parser


def main() -> None:
    """Entry point for the diceware CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        wordlist = load_wordlist(args.wordlist)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    entropy = passphrase_entropy(args.words, len(wordlist))
    warning = entropy_warning(entropy)
    if warning:
        print(f"WARNING: {warning}", file=sys.stderr)

    for _ in range(args.count):
        passphrase = generate_passphrase(
            word_count=args.words,
            wordlist=wordlist,
            separator=args.separator,
        )
        if args.entropy:
            print(f"{passphrase}  [{entropy:.1f} bits]")
        else:
            print(passphrase)
    sys.exit(0)
