"""CLI for Nmap Result Parser & Diff."""

from __future__ import annotations

from pathlib import Path

import click

from .core import diff_scans, parse_nmap_xml


@click.group()
def cli() -> None:
    """Nmap Result Parser & Diff — parse and compare Nmap XML scans."""


@cli.command("parse")
@click.argument("xml_file", type=click.Path(exists=True))
@click.option("--open-only", is_flag=True, default=False,
              help="Only show open ports.")
def parse_cmd(xml_file: str, open_only: bool) -> None:
    """Parse an Nmap XML file and display host/port information."""
    xml = Path(xml_file).read_text(encoding="utf-8")
    result = parse_nmap_xml(xml)
    click.echo(f"Scan: {result.args}")
    for addr, host in result.hosts.items():
        click.echo(f"\nHost: {addr} ({host.hostname}) — {host.status}")
        ports = host.open_ports() if open_only else host.ports
        for p in ports:
            click.echo(
                f"  {p.port}/{p.protocol}  {p.state:<8}  {p.service}  {p.product} {p.version}"
            )
        if host.os_guesses:
            click.echo(f"  OS: {', '.join(host.os_guesses[:2])}")


@cli.command("diff")
@click.argument("baseline_xml", type=click.Path(exists=True))
@click.argument("current_xml", type=click.Path(exists=True))
def diff_cmd(baseline_xml: str, current_xml: str) -> None:
    """Diff two Nmap XML scans and report changes."""
    baseline = parse_nmap_xml(Path(baseline_xml).read_text(encoding="utf-8"))
    current = parse_nmap_xml(Path(current_xml).read_text(encoding="utf-8"))
    diff = diff_scans(baseline, current)

    if not diff.has_changes:
        click.echo("[ok] No changes detected.")
        return

    for addr in diff.new_hosts:
        click.echo(f"[NEW HOST] {addr}")
    for addr in diff.removed_hosts:
        click.echo(f"[GONE HOST] {addr}")
    for change in diff.port_changes:
        click.echo(
            f"[{change.change.upper()}] {change.address}:{change.port}/{change.protocol}"
        )
