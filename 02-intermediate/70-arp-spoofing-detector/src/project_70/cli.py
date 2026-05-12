"""CLI for ARP Spoofing Detector."""

from __future__ import annotations

import click

from project_70.core import analyse_arp_log, analyse_pcap


@click.group()
def cli() -> None:
    """ARP Spoofing Detector — detect IP-to-MAC binding conflicts."""


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
def pcap(pcap_file: str) -> None:
    """Analyse PCAP_FILE for ARP spoofing."""
    with open(pcap_file, "rb") as fh:
        data = fh.read()

    table = analyse_pcap(data)
    _print_results(table)


@cli.command()
@click.argument("log_file", type=click.Path(exists=True))
def neigh(log_file: str) -> None:
    """Analyse ip-neigh LOG_FILE output for ARP conflicts."""
    with open(log_file) as fh:
        lines = fh.readlines()

    table = analyse_arp_log(lines)
    _print_results(table)


def _print_results(table: project_70.core.ARPTable) -> None:  # type: ignore[name-defined]  # noqa: F821
    click.echo("\nARP Spoofing Analysis")
    click.echo(f"  Conflicts detected: {len(table.conflicts)}")
    susp = table.suspicious_macs()
    click.echo(f"  Suspicious MACs  : {len(susp)}")

    if table.conflicts:
        click.echo("\nConflicts:")
        for c in table.conflicts:
            click.echo(f"  [{c.severity.upper():8s}] {c.ip_address}: {c.old_mac} → {c.new_mac}")

    if susp:
        click.echo("\nSuspicious (high-gratuitous-ARP) MACs:")
        for mac in susp:
            click.echo(f"  {mac} ({table.gratuitous_counts[mac]} gratuitous ARPs)")
