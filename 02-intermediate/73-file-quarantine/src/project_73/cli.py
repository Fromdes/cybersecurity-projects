"""CLI for File Quarantine Service."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from project_73.core import QuarantineStore


@click.group()
@click.option("--store", "-s", default="./quarantine", show_default=True,
              help="Path to quarantine directory")
@click.pass_context
def cli(ctx: click.Context, store: str) -> None:
    """File Quarantine Service — isolate and track suspicious files."""
    ctx.ensure_object(dict)
    ctx.obj["store"] = QuarantineStore(Path(store))


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--reason", "-r", default="manual quarantine", help="Reason for quarantine")
@click.pass_context
def add(ctx: click.Context, file_path: str, reason: str) -> None:
    """Quarantine FILE_PATH."""
    store: QuarantineStore = ctx.obj["store"]
    result = store.quarantine(file_path, reason)
    if result.success and result.entry:
        click.echo(f"Quarantined: {result.entry.sha256[:12]}… → {result.entry.quarantine_name}")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@cli.command("list")
@click.option("--all", "show_all", is_flag=True, help="Include released files")
@click.pass_context
def list_cmd(ctx: click.Context, show_all: bool) -> None:
    """List quarantined files."""
    store: QuarantineStore = ctx.obj["store"]
    entries = store.list_entries(include_released=show_all)
    if not entries:
        click.echo("No quarantined files.")
        return
    for e in entries:
        status = "RELEASED" if e.released else "QUARANTINED"
        click.echo(f"  [{status}] {e.sha256[:12]}… {e.original_path} ({e.reason})")


@cli.command()
@click.argument("file_hash")
@click.argument("destination")
@click.pass_context
def release(ctx: click.Context, file_hash: str, destination: str) -> None:
    """Release FILE_HASH to DESTINATION path."""
    store: QuarantineStore = ctx.obj["store"]
    result = store.release(file_hash, destination)
    if result.success:
        click.echo(f"Released to {destination}")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("file_hash")
@click.confirmation_option(prompt="Permanently delete quarantined file?")
@click.pass_context
def delete(ctx: click.Context, file_hash: str) -> None:
    """Permanently wipe FILE_HASH from quarantine."""
    store: QuarantineStore = ctx.obj["store"]
    result = store.delete(file_hash)
    if result.success:
        click.echo("File deleted.")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def verify(ctx: click.Context) -> None:
    """Verify integrity of all quarantined files."""
    store: QuarantineStore = ctx.obj["store"]
    errors = store.verify_integrity()
    if not errors:
        click.echo("All quarantined files pass integrity check.")
    else:
        for err in errors:
            click.echo(f"  [FAIL] {err}", err=True)
        sys.exit(1)
