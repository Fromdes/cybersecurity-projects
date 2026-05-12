"""CLI for STIX/TAXII Feed Parser."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .core import STIXBundle, TAXIIClient


@click.group()
def cli() -> None:
    """STIX/TAXII Feed Parser — parse bundles and query TAXII servers."""


@cli.command("parse")
@click.argument("bundle_file", type=click.Path(exists=True))
@click.option("--indicators-only", is_flag=True)
@click.option("--json-output", is_flag=True)
def parse_cmd(bundle_file: str, indicators_only: bool, json_output: bool) -> None:
    """Parse a STIX 2.x JSON bundle file."""
    bundle = STIXBundle.from_file(Path(bundle_file))
    click.echo(f"Bundle: {bundle.bundle_id}  ({len(bundle.objects)} objects)")

    objects = bundle.indicators() if indicators_only else bundle.objects
    for obj in objects:
        if json_output:
            click.echo(json.dumps({"id": obj.stix_id, "type": obj.stix_type,
                                   "name": obj.name, "created": obj.created}))
        else:
            click.echo(f"  [{obj.stix_type}] {obj.name} ({obj.stix_id[:40]})")

    click.echo(f"\nSummary: {bundle.summary()}")


@cli.command("discover")
@click.argument("server_url")
@click.option("--user", default="", help="HTTP Basic auth username.")
@click.option("--password", default="", help="HTTP Basic auth password.")
@click.option("--no-verify-ssl", is_flag=True)
def discover_cmd(server_url: str, user: str, password: str, no_verify_ssl: bool) -> None:
    """Query TAXII server discovery endpoint."""
    client = TAXIIClient(
        server_url=server_url, username=user, password=password,
        verify_ssl=not no_verify_ssl,
    )
    try:
        info = client.discover()
        click.echo(json.dumps(info, indent=2))
    except Exception as exc:
        click.echo(f"[error] {exc}", err=True)
        sys.exit(1)
