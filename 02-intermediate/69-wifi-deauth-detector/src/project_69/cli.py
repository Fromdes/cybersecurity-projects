"""CLI for WiFi Deauth Detector."""

from __future__ import annotations

import click

from project_69.core import analyse_pcap


@click.group()
def cli() -> None:
    """WiFi Deauth Detector — detect deauthentication attack frames in PCAP files."""


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--threshold", "-t", default=10, show_default=True,
              help="Deauth count threshold per source to trigger alarm")
def analyse(pcap_file: str, threshold: int) -> None:
    """Analyse PCAP_FILE for deauth attacks."""
    with open(pcap_file, "rb") as fh:
        data = fh.read()

    state = analyse_pcap(data, threshold=threshold)

    click.echo(f"\nDeauth Analysis: {pcap_file}")
    click.echo(f"  Total deauth/disassoc frames : {len(state.events)}")
    click.echo(f"  Alarms triggered             : {len(state.alarms)}")

    if not state.alarms:
        click.echo("  No attacks detected above threshold.")
        return

    click.echo("\nAlarms:")
    for alarm in state.alarms:
        click.echo(
            f"  [{alarm.severity.upper():6s}] {alarm.src_mac} → BSSID {alarm.bssid} "
            f"| {alarm.count} frames | broadcast={alarm.broadcast_ratio:.0%}"
        )
