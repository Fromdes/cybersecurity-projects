"""CLI for the AES-256-GCM File Encryptor."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from project_08.core import ENCRYPTED_EXTENSION, DecryptionError, decrypt_file, encrypt_file


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aes-crypt",
        description="Encrypt or decrypt files with AES-256-GCM + Scrypt key derivation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", type=Path, help="Plaintext file to encrypt")
    enc.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output path (default: <input>.enc)",
    )

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", type=Path, help="Encrypted file to decrypt")
    dec.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output path (default: strip .enc suffix or add .dec)",
    )

    return parser


def _get_password(*, confirm: bool) -> str:
    """Prompt for password; if *confirm*, ask twice and verify they match."""
    password = getpass.getpass("Password: ")
    if confirm:
        confirm_pw = getpass.getpass("Confirm password: ")
        if password != confirm_pw:
            raise ValueError("Passwords do not match")
    return password


def _default_decrypt_output(path: Path) -> Path:
    """Derive default output path for decryption."""
    if path.suffix == ENCRYPTED_EXTENSION:
        return path.with_suffix("")
    return path.with_suffix(".dec")


def _cmd_encrypt(args: argparse.Namespace) -> int:
    output = args.output or args.input.with_suffix(
        args.input.suffix + ENCRYPTED_EXTENSION
    )
    try:
        password = _get_password(confirm=True)
        encrypt_file(args.input, output, password)
        print(f"Encrypted: {output}")
        return 0
    except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_decrypt(args: argparse.Namespace) -> int:
    output = args.output or _default_decrypt_output(args.input)
    try:
        password = _get_password(confirm=False)
        decrypt_file(args.input, output, password)
        print(f"Decrypted: {output}")
        return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except DecryptionError as exc:
        print(f"Decryption failed: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    """Entry point for the aes-crypt CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    dispatch = {"encrypt": _cmd_encrypt, "decrypt": _cmd_decrypt}
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(handler(args))
