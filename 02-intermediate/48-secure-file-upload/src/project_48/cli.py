"""CLI for Secure File Upload Service."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import click

from .core import UploadStorage, UploadValidator


@click.group()
def cli() -> None:
    """Secure File Upload Service — validate and store files safely."""


@click.command("upload")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--storage-dir", default=None, help="Directory to store files (default: temp).")
@click.option("--max-mb", default=10, show_default=True, help="Max file size in MiB.")
def upload_cmd(file_path: str, storage_dir: str | None, max_mb: int) -> None:
    """Validate and store FILE_PATH securely."""
    src = Path(file_path)
    data = src.read_bytes()
    storage_path = Path(storage_dir) if storage_dir else Path(tempfile.mkdtemp())

    validator = UploadValidator(max_bytes=max_mb * 1024 * 1024)
    storage = UploadStorage(storage_root=storage_path, validator=validator)
    try:
        result = storage.store(src.name, data)
        click.echo(f"[ok] Stored as : {result.stored_name}")
        click.echo(f"     MIME type : {result.mime_type}")
        click.echo(f"     Size      : {result.size_bytes} bytes")
        click.echo(f"     SHA-256   : {result.sha256}")
        click.echo(f"     Path      : {result.storage_path}")
    except Exception as exc:  # noqa: BLE001
        click.echo(f"[error] {exc}", err=True)
        sys.exit(1)


@click.command("validate")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
def validate_cmd(file_path: str) -> None:
    """Validate FILE_PATH without storing."""
    src = Path(file_path)
    data = src.read_bytes()
    validator = UploadValidator()
    try:
        mime = validator.validate(src.name, data)
        click.echo(f"[ok] Valid — MIME: {mime}, size: {len(data)} bytes")
    except Exception as exc:  # noqa: BLE001
        click.echo(f"[fail] {exc}", err=True)
        sys.exit(1)


cli.add_command(upload_cmd, "upload")
cli.add_command(validate_cmd, "validate")
