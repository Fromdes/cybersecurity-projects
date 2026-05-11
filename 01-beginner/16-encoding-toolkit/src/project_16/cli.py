"""CLI for the Encoding Toolkit."""
from __future__ import annotations

import argparse
import sys

from project_16.core import Encoding, decode, detect_encodings, encode


def _add_encode_cmd(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("encode", help="Encode data using a specified scheme")
    p.add_argument("data", help="Input string to encode")
    p.add_argument(
        "--encoding", "-e",
        choices=[e.value for e in Encoding],
        default=Encoding.BASE64.value,
        help="Encoding scheme (default: base64)",
    )


def _add_decode_cmd(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("decode", help="Decode data from a specified scheme")
    p.add_argument("data", help="Input string to decode")
    p.add_argument(
        "--encoding", "-e",
        choices=[e.value for e in Encoding],
        required=True,
        help="Encoding scheme to decode from",
    )


def _add_detect_cmd(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("detect", help="Detect possible encoding of a string")
    p.add_argument("data", help="Input string to analyse")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="encode-toolkit",
        description="Encode, decode, and detect data encoding schemes",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_encode_cmd(sub)
    _add_decode_cmd(sub)
    _add_detect_cmd(sub)
    return parser


def _cmd_encode(args: argparse.Namespace) -> None:
    result = encode(args.data, Encoding(args.encoding))
    print(result.output)


def _cmd_decode(args: argparse.Namespace) -> None:
    try:
        result = decode(args.data, Encoding(args.encoding))
        print(result.output)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def _cmd_detect(args: argparse.Namespace) -> None:
    candidates = detect_encodings(args.data)
    if candidates:
        print("Possible encodings:")
        for enc in candidates:
            print(f"  - {enc.value}")
    else:
        print("No common encoding pattern detected.")


def main() -> None:
    """Entry point for the encoding toolkit CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if args.command == "encode":
            _cmd_encode(args)
        elif args.command == "decode":
            _cmd_decode(args)
        elif args.command == "detect":
            _cmd_detect(args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
