"""CLI for the Encrypted Notes tool."""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from project_34.core import NotesStore

DEFAULT_STORE: Path = Path.home() / ".local" / "share" / "enc-notes" / "notes.enc"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enc-notes",
        description="Manage AES-256-GCM encrypted notes",
    )
    parser.add_argument(
        "--store", type=Path, default=DEFAULT_STORE,
        help=f"Notes file path (default: {DEFAULT_STORE})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    add_p = sub.add_parser("add", help="Add a new note")
    add_p.add_argument("title", help="Note title")
    add_p.add_argument("body", nargs="?", default="", help="Note body (optional)")

    sub.add_parser("list", help="List all note titles and IDs")

    get_p = sub.add_parser("get", help="Display a note by ID")
    get_p.add_argument("id", help="Note UUID")

    del_p = sub.add_parser("delete", help="Delete a note by ID")
    del_p.add_argument("id", help="Note UUID")

    upd_p = sub.add_parser("update", help="Update an existing note")
    upd_p.add_argument("id", help="Note UUID")
    upd_p.add_argument("--title", help="New title")
    upd_p.add_argument("--body", help="New body")

    return parser


def _open_store(path: Path, prompt: str = "Master password: ") -> NotesStore:
    path.parent.mkdir(parents=True, exist_ok=True)
    password = getpass.getpass(prompt)
    return NotesStore(path, password)


def main() -> None:
    """Entry point for the Encrypted Notes CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        store = _open_store(args.store)
    except InvalidTag:
        print("Error: wrong password or corrupted store.", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.command == "add":
            note = store.add_note(args.title, args.body)
            print(f"Note added: {note.id}")

        elif args.command == "list":
            notes = store.list_notes()
            if not notes:
                print("No notes stored.")
            else:
                print(f"{'ID':<38} {'TITLE'}")
                print("-" * 70)
                for n in notes:
                    print(f"{n.id}  {n.title}")

        elif args.command == "get":
            note = store.get_note(args.id)
            print(f"ID      : {note.id}")
            print(f"Title   : {note.title}")
            print(f"Created : {note.created_at}")
            print(f"Updated : {note.updated_at}")
            print()
            print(note.body)

        elif args.command == "delete":
            store.delete_note(args.id)
            print(f"Note deleted: {args.id}")

        elif args.command == "update":
            note = store.update_note(args.id, title=args.title, body=args.body)
            print(f"Note updated: {note.id}")

    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
