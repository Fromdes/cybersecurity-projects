"""CLI for TLS Configuration Auditor."""

from __future__ import annotations

import json
import sys

import click

from project_66.core import analyse_result, audit_tls


@click.group()
def cli() -> None:
    """TLS Configuration Auditor — check cipher suites, protocols, and cert validity."""


@cli.command()
@click.argument("host")
@click.option("--port", "-p", default=443, show_default=True, help="TCP port")
@click.option("--timeout", "-t", default=10, show_default=True, help="Connection timeout (seconds)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def audit(host: str, port: int, timeout: int, output_json: bool) -> None:
    """Audit TLS configuration of HOST."""
    result = audit_tls(host, port, timeout=timeout)
    summary = analyse_result(result)

    if output_json:
        click.echo(json.dumps(summary, indent=2))
        return

    click.echo(f"\nTLS Audit: {host}:{port}")
    click.echo(f"  Grade  : {summary['grade']}  (score: {summary['score']}/100)")
    click.echo(f"  Protocol: {summary.get('protocol', 'N/A')}")
    if "cipher" in summary:
        c = summary["cipher"]
        click.echo(f"  Cipher : {c['name']} ({c['bits']} bits)")  # type: ignore[index]

    if summary["findings"]:
        click.echo("\nFindings:")
        for finding in summary["findings"]:  # type: ignore[union-attr]
            click.echo(f"  {finding}")
    else:
        click.echo("\n  No findings — configuration looks strong.")

    if not result.connected:
        sys.exit(1)
