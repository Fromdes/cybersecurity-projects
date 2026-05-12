"""CLI for Rogue DHCP Detector."""

from __future__ import annotations

import sys

import click

from project_71.core import analyse_pcap


@click.group()
def cli() -> None:
    """Rogue DHCP Detector — find unauthorised DHCP servers."""


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--authorised", "-a", multiple=True, required=True,
              help="Authorised DHCP server IP (repeatable)")
def analyse(pcap_file: str, authorised: tuple[str, ...]) -> None:
    """Analyse PCAP_FILE for rogue DHCP servers."""
    with open(pcap_file, "rb") as fh:
        data = fh.read()

    state = analyse_pcap(data, list(authorised))

    click.echo(f"\nRogue DHCP Analysis: {pcap_file}")
    click.echo(f"  DHCP server packets seen : {len(state.packets)}")
    click.echo(f"  Rogue server alerts      : {len(state.alerts)}")

    if not state.alerts:
        click.echo("  No rogue DHCP servers detected.")
        return

    click.echo("\nAlerts:")
    for alert in state.alerts:
        click.echo(
            f"  [{alert.severity.upper():8s}] {alert.server_ip} ({alert.server_mac})"
            f" offered {alert.offered_ip}"
        )
        click.echo(f"             {alert.reason}")
