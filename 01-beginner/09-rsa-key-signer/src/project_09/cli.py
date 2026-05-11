"""CLI for the RSA Key Pair Generator & File Signer."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from project_09.core import (
    SIGNATURE_EXTENSION,
    SignatureVerificationError,
    generate_key_pair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sign_file,
    verify_file,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rsa-sign",
        description="Generate RSA-4096 key pairs and sign/verify files with PSS-SHA-256.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate-key
    gk = sub.add_parser("generate-key", help="Generate RSA-4096 key pair")
    gk.add_argument("--private", type=Path, default=Path("private_key.pem"))
    gk.add_argument("--public", type=Path, default=Path("public_key.pem"))

    # sign
    s = sub.add_parser("sign", help="Sign a file with the private key")
    s.add_argument("file", type=Path)
    s.add_argument("--key", type=Path, default=Path("private_key.pem"))
    s.add_argument("--output", "-o", type=Path, default=None)

    # verify
    v = sub.add_parser("verify", help="Verify a file's signature with the public key")
    v.add_argument("file", type=Path)
    v.add_argument("--key", type=Path, default=Path("public_key.pem"))
    v.add_argument("--signature", type=Path, default=None)

    return parser


def _cmd_generate_key(args: argparse.Namespace) -> int:
    password = getpass.getpass("Private key password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Error: passwords do not match", file=sys.stderr)
        return 1
    private_key, public_key = generate_key_pair()
    save_private_key(private_key, args.private, password)
    save_public_key(public_key, args.public)
    print(f"Private key: {args.private}")
    print(f"Public key:  {args.public}")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    output = args.output or args.file.with_suffix(args.file.suffix + SIGNATURE_EXTENSION)
    password = getpass.getpass("Private key password: ")
    try:
        private_key = load_private_key(args.key, password)
        signature = sign_file(args.file, private_key)
        output.write_bytes(signature)
        print(f"Signature written: {output}")
        return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_verify(args: argparse.Namespace) -> int:
    sig_path = args.signature or args.file.with_suffix(
        args.file.suffix + SIGNATURE_EXTENSION
    )
    try:
        public_key = load_public_key(args.key)
        signature = sig_path.read_bytes()
        verify_file(args.file, signature, public_key)
        print(f"VALID — signature verified for {args.file}")
        return 0
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except SignatureVerificationError as exc:
        print(f"INVALID — {exc}", file=sys.stderr)
        return 2


def main() -> None:
    """Entry point for the rsa-sign CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    dispatch = {
        "generate-key": _cmd_generate_key,
        "sign": _cmd_sign,
        "verify": _cmd_verify,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(handler(args))
