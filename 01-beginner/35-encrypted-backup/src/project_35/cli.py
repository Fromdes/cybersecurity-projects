"""CLI for the Encrypted Backup Tool."""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from project_35.core import BackupManifest, create_backup, restore_backup, verify_backup


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enc-backup",
        description="Create and restore AES-256-GCM encrypted compressed backups",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    bk_p = sub.add_parser("create", help="Create an encrypted backup")
    bk_p.add_argument("source", type=Path, help="File or directory to backup")
    bk_p.add_argument("output", type=Path, help="Output .encbak file path")

    rs_p = sub.add_parser("restore", help="Decrypt and restore a backup")
    rs_p.add_argument("backup", type=Path, help=".encbak file to restore")
    rs_p.add_argument("output_dir", type=Path, help="Directory to restore files into")

    vf_p = sub.add_parser("verify", help="Verify backup integrity")
    vf_p.add_argument("backup", type=Path, help=".encbak file to verify")

    return parser


def _print_manifest(manifest: BackupManifest) -> None:
    print(f"Source      : {manifest.source_path}")
    print(f"Created     : {manifest.created_at}")
    print(f"Files       : {manifest.file_count}")
    print(f"Original    : {manifest.uncompressed_size:,} bytes")
    print(f"Compressed  : {manifest.compressed_size:,} bytes")
    ratio = (1 - manifest.compressed_size / max(manifest.uncompressed_size, 1)) * 100
    print(f"Ratio       : {ratio:.1f}% compression")
    print(f"SHA-256     : {manifest.content_hash}")


def main() -> None:
    """Entry point for the Encrypted Backup Tool CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        if args.command == "create":
            password = getpass.getpass("Backup password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match.", file=sys.stderr)
                sys.exit(1)
            manifest = create_backup(args.source, args.output, password)
            print("Backup created successfully.")
            _print_manifest(manifest)

        elif args.command == "restore":
            password = getpass.getpass("Backup password: ")
            count = restore_backup(args.backup, args.output_dir, password)
            print(f"Restored {count} files to {args.output_dir}")

        elif args.command == "verify":
            password = getpass.getpass("Backup password: ")
            ok = verify_backup(args.backup, password)
            if ok:
                print("Backup integrity: OK")
            else:
                print("Backup integrity: FAILED (hash mismatch)", file=sys.stderr)
                sys.exit(2)

    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except InvalidTag:
        print("Error: wrong password or backup file corrupted.", file=sys.stderr)
        sys.exit(1)
