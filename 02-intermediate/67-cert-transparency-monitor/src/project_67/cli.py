"""CLI for Certificate Transparency Monitor."""

from __future__ import annotations

import json
import sys

import click

from project_67.core import monitor


@click.group()
def cli() -> None:
    """Certificate Transparency Monitor — watch CT logs for your domains."""


@cli.command()
@click.argument("domain")
@click.option("--issuers", "-i", multiple=True, help="Trusted issuer substrings (repeatable)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def watch(domain: str, issuers: tuple[str, ...], output_json: bool) -> None:
    """Query CT logs for DOMAIN and report anomalies."""
    try:
        result = monitor(domain, watched_issuers=list(issuers) or None)
    except (OSError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if output_json:
        out = {
            "domain": result.domain,
            "total": result.total,
            "wildcards": result.wildcard_count,
            "anomalies": result.anomalies,
            "entries": [
                {
                    "id": e.id,
                    "common_name": e.common_name,
                    "logged_at": e.logged_at.isoformat(),
                    "not_after": e.not_after.isoformat(),
                    "issuer": e.issuer_name,
                }
                for e in result.entries
            ],
        }
        click.echo(json.dumps(out, indent=2))
        return

    click.echo(f"\nCT Monitor: {domain}")
    click.echo(f"  Total certs : {result.total}")
    click.echo(f"  Wildcards   : {result.wildcard_count}")
    click.echo(f"  Expired     : {result.expired_count}")
    if result.anomalies:
        click.echo("\nAnomalies:")
        for a in result.anomalies:
            click.echo(f"  [!] {a}")
    else:
        click.echo("  No anomalies detected.")
