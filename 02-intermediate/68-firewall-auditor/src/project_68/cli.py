"""CLI for Firewall Rule Auditor."""

from __future__ import annotations

import sys

import click

from project_68.core import audit_rules, get_live_rules, parse_iptables_output


@click.group()
def cli() -> None:
    """Firewall Rule Auditor — analyse iptables rules for misconfigurations."""


@cli.command()
@click.option("--table", default="filter", show_default=True, help="iptables table")
def live(table: str) -> None:
    """Audit live iptables rules (requires root)."""
    output, err = get_live_rules(table)
    if not output:
        click.echo(f"Error: {err or 'No output from iptables'}", err=True)
        sys.exit(1)
    _run_audit(output)


@cli.command("file")
@click.argument("path", type=click.Path(exists=True))
def from_file(path: str) -> None:
    """Audit iptables rules from FILE (iptables -L -n -v output)."""
    with open(path) as fh:
        output = fh.read()
    _run_audit(output)


def _run_audit(output: str) -> None:
    rules, policies = parse_iptables_output(output)
    result = audit_rules(rules, policies)

    click.echo(f"\nFirewall Audit — {len(rules)} rules parsed")
    click.echo(f"  Critical: {result.critical_count}  High: {result.high_count}  "
               f"Total findings: {len(result.findings)}")

    if not result.findings:
        click.echo("  No issues found.")
        return

    click.echo("\nFindings:")
    for f in result.findings:
        click.echo(f"  [{f.severity.upper():8s}] {f.message}")
        if f.raw_rule:
            click.echo(f"             Rule: {f.raw_rule[:80]}")
