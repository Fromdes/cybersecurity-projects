"""Disk Image Hash & Chain-of-Custody — CLI interface."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from project_83.core import (
    CustodyRecord,
    create_custody_record,
    hash_image,
    verify_image,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Disk Image Hash & Chain-of-Custody — forensic hashing and custody management."""


@cli.command("hash")
@click.argument("image_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write JSON hash report to file.")
def hash_cmd(image_file: Path, output: Path | None) -> None:
    """Compute MD5/SHA1/SHA256/SHA512 of a disk image."""
    click.echo(f"Hashing {image_file.name} ({image_file.stat().st_size:,} bytes) …")
    result = hash_image(image_file)
    click.echo(f"\nMD5:    {result.md5}")
    click.echo(f"SHA1:   {result.sha1}")
    click.echo(f"SHA256: {result.sha256}")
    click.echo(f"SHA512: {result.sha512}")
    click.echo(f"Size:   {result.file_size:,} bytes")
    click.echo(f"At:     {result.computed_at}")
    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2))
        click.echo(f"\nHash report saved to {output}")


@cli.command("verify")
@click.argument("image_file", type=click.Path(exists=True, path_type=Path))
@click.argument("expected_sha256")
def verify_cmd(image_file: Path, expected_sha256: str) -> None:
    """Verify a disk image against an expected SHA-256 hash."""
    click.echo(f"Verifying {image_file.name} …")
    matches, actual = verify_image(image_file, expected_sha256)
    if matches:
        click.echo(click.style("PASS", fg="green") + f" SHA-256 matches: {actual}")
    else:
        click.echo(click.style("FAIL", fg="red") + " Hash mismatch!")
        click.echo(f"  Expected: {expected_sha256}")
        click.echo(f"  Actual:   {actual}")
        sys.exit(1)


@cli.command("acquire")
@click.argument("image_file", type=click.Path(exists=True, path_type=Path))
@click.option("--custody-file", "-c", required=True, type=click.Path(path_type=Path),
              help="Output chain-of-custody JSON file.")
@click.option("--notes", "-n", default="", help="Acquisition notes.")
def acquire_cmd(image_file: Path, custody_file: Path, notes: str) -> None:
    """Hash image and create an initial chain-of-custody record."""
    click.echo(f"Acquiring {image_file.name} …")
    record = create_custody_record(image_file, notes=notes)
    record.save(custody_file)
    click.echo(f"SHA256: {record.hash_result.sha256}")
    click.echo(f"Chain-of-custody record saved to {custody_file}")


@cli.command("transfer")
@click.argument("custody_file", type=click.Path(exists=True, path_type=Path))
@click.argument("image_file", type=click.Path(exists=True, path_type=Path))
@click.option("--notes", "-n", default="", help="Transfer notes.")
def transfer_cmd(custody_file: Path, image_file: Path, notes: str) -> None:
    """Record a custody transfer event (re-verifies hash integrity)."""
    record = CustodyRecord.load(custody_file)
    click.echo("Verifying image before transfer …")
    matches, actual = verify_image(image_file, record.hash_result.sha256)
    if not matches:
        click.echo(click.style("INTEGRITY CHECK FAILED", fg="red"), err=True)
        click.echo(f"  Expected: {record.hash_result.sha256}")
        click.echo(f"  Actual:   {actual}")
        sys.exit(1)
    entry = record.add_entry("TRANSFERRED", notes=notes, current_sha256=actual)
    record.save(custody_file)
    click.echo(click.style("PASS", fg="green") + f" Integrity verified. Transfer recorded by {entry.actor}.")


@cli.command("log")
@click.argument("custody_file", type=click.Path(exists=True, path_type=Path))
def log_cmd(custody_file: Path) -> None:
    """Display the full chain-of-custody log."""
    record = CustodyRecord.load(custody_file)
    click.echo(f"File:   {record.hash_result.file_path}")
    click.echo(f"Size:   {record.hash_result.file_size:,} bytes")
    click.echo(f"SHA256: {record.hash_result.sha256}")
    click.echo(f"\nChain of Custody ({len(record.chain)} event(s)):")
    click.echo("─" * 70)
    for i, entry in enumerate(record.chain, 1):
        click.echo(f"{i}. [{entry.timestamp}] {entry.action}")
        click.echo(f"   Actor:    {entry.actor}")
        click.echo(f"   Location: {entry.location}")
        if entry.notes:
            click.echo(f"   Notes:    {entry.notes}")
