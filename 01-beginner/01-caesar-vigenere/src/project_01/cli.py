"""CLI for the Caesar & Vigenere Cipher Toolkit."""

from __future__ import annotations

import argparse
import json
import sys

from project_01.core import (
    CaesarCipher,
    VigenereCipher,
    caesar_crack,
    frequency_analysis,
    vigenere_key_length_hint,
)

_TOP_CRACK_RESULTS = 5


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cipher-toolkit",
        description="Classical cipher toolkit — understand why Caesar & Vigenere are insecure.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # caesar subcommand
    caesar = sub.add_parser("caesar", help="Caesar cipher encrypt / decrypt / crack")
    caesar.add_argument("text", help="Input text")
    caesar.add_argument("--shift", type=int, default=13, help="Shift value 0-25 (default: 13)")
    mode = caesar.add_mutually_exclusive_group(required=True)
    mode.add_argument("--encrypt", action="store_true")
    mode.add_argument("--decrypt", action="store_true")
    mode.add_argument("--crack", action="store_true", help="Brute-force all shifts")

    # vigenere subcommand
    vigenere = sub.add_parser("vigenere", help="Vigenere cipher encrypt / decrypt / hint")
    vigenere.add_argument("text", help="Input text")
    vigenere.add_argument("--key", help="Cipher key (letters only)")
    vmode = vigenere.add_mutually_exclusive_group(required=True)
    vmode.add_argument("--encrypt", action="store_true")
    vmode.add_argument("--decrypt", action="store_true")
    vmode.add_argument("--hint", action="store_true", help="Key-length hint via IoC")

    # freq subcommand
    freq = sub.add_parser("freq", help="Letter frequency analysis")
    freq.add_argument("text", help="Input text")
    freq.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")

    return parser


def _cmd_caesar(args: argparse.Namespace) -> int:
    """Handle the caesar subcommand."""
    if args.crack:
        results = caesar_crack(args.text)[:_TOP_CRACK_RESULTS]
        print("Top crack candidates (best English-frequency match first):")
        for shift, plaintext in results:
            print(f"  shift={shift:>2}: {plaintext}")
        return 0
    cipher = CaesarCipher(args.shift)
    result = cipher.encrypt(args.text) if args.encrypt else cipher.decrypt(args.text)
    print(result)
    return 0


def _cmd_vigenere(args: argparse.Namespace) -> int:
    """Handle the vigenere subcommand."""
    if args.hint:
        hints = vigenere_key_length_hint(args.text)
        print("Key-length hints (closest to English IoC 0.065 first):")
        for length, ioc in hints[:_TOP_CRACK_RESULTS]:
            print(f"  length={length}: IoC={ioc}")
        return 0
    if not args.key:
        print("Error: --key is required for --encrypt / --decrypt", file=sys.stderr)
        return 1
    cipher = VigenereCipher(args.key)
    result = cipher.encrypt(args.text) if args.encrypt else cipher.decrypt(args.text)
    print(result)
    return 0


def _cmd_freq(args: argparse.Namespace) -> int:
    """Handle the freq subcommand."""
    freq = frequency_analysis(args.text)
    if args.as_json:
        print(json.dumps(freq, indent=2))
    else:
        for letter, pct in sorted(freq.items(), key=lambda x: -x[1]):
            if pct > 0:
                bar = "#" * int(pct)
                print(f"  {letter}: {pct:>6.3f}%  {bar}")
    return 0


def main() -> None:
    """Entry point for the cipher toolkit CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    dispatch = {
        "caesar": _cmd_caesar,
        "vigenere": _cmd_vigenere,
        "freq": _cmd_freq,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(handler(args))
