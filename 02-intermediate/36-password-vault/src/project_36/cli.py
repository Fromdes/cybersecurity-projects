"""CLI for the Personal Password Vault."""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from project_36.core import DEFAULT_PASSWORD_LEN, Vault, VaultEntry, generate_password

DEFAULT_VAULT: Path = Path.home() / ".local" / "share" / "password-vault" / "vault.enc"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        description="AES-256-GCM encrypted local password manager",
    )
    parser.add_argument(
        "--vault", type=Path, default=DEFAULT_VAULT,
        help=f"Vault file path (default: {DEFAULT_VAULT})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    add_p = sub.add_parser("add", help="Add a credential entry")
    add_p.add_argument("site", help="Website or service name")
    add_p.add_argument("username", help="Username or email")
    add_p.add_argument("--password", help="Password (prompted if omitted)")
    add_p.add_argument("--generate", action="store_true", help="Generate a random password")
    add_p.add_argument("--length", type=int, default=DEFAULT_PASSWORD_LEN,
                       help=f"Generated password length (default: {DEFAULT_PASSWORD_LEN})")
    add_p.add_argument("--notes", default="", help="Optional notes")

    list_p = sub.add_parser("list", help="List all entries")
    list_p.add_argument("--search", help="Filter by site or username")

    get_p = sub.add_parser("get", help="Show an entry including password")
    get_p.add_argument("id", help="Entry UUID")

    del_p = sub.add_parser("delete", help="Delete an entry")
    del_p.add_argument("id", help="Entry UUID")

    gen_p = sub.add_parser("generate", help="Generate a random password")
    gen_p.add_argument("--length", type=int, default=DEFAULT_PASSWORD_LEN)

    return parser


def _open_vault(path: Path) -> Vault:
    path.parent.mkdir(parents=True, exist_ok=True)
    password = getpass.getpass("Master password: ")
    return Vault(path, password)


def _print_entry(entry: VaultEntry, show_password: bool = False) -> None:
    print(f"ID       : {entry.id}")
    print(f"Site     : {entry.site}")
    print(f"Username : {entry.username}")
    if show_password:
        print(f"Password : {entry.password}")
    print(f"Notes    : {entry.notes or '-'}")
    print(f"Modified : {entry.modified_at}")


def main() -> None:
    """Entry point for the Password Vault CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "generate":
        try:
            print(generate_password(args.length))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    try:
        vault = _open_vault(args.vault)
    except InvalidTag:
        print("Error: wrong master password or vault corrupted.", file=sys.stderr)
        sys.exit(1)

    try:
        if args.command == "add":
            if args.generate:
                pwd = generate_password(args.length)
                print(f"Generated password: {pwd}")
            elif args.password:
                pwd = args.password
            else:
                pwd = getpass.getpass("Entry password: ")
            entry = vault.add(args.site, args.username, pwd, args.notes)
            print(f"Entry added: {entry.id}")

        elif args.command == "list":
            entries = vault.search(args.search) if args.search else vault.list_all()
            if not entries:
                print("No entries found.")
            else:
                print(f"{'ID':<38} {'SITE':<25} USERNAME")
                print("-" * 80)
                for e in entries:
                    print(f"{e.id}  {e.site[:24]:<25} {e.username}")

        elif args.command == "get":
            entry = vault.get(args.id)
            _print_entry(entry, show_password=True)

        elif args.command == "delete":
            vault.delete(args.id)
            print(f"Entry deleted: {args.id}")

    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
