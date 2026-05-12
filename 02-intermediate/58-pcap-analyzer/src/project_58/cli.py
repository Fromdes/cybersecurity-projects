"""CLI for PCAP Analyzer."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .core import PCAPAnalyser, PCAPReader


@click.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--top-n", default=5, show_default=True, help="Top talkers to show.")
@click.option("--flows", is_flag=True, help="Print flow table.")
@click.option("--anomalies-only", is_flag=True, help="Only print anomalies.")
def cli(pcap_file: str, top_n: int, flows: bool, anomalies_only: bool) -> None:
    """Analyse a PCAP file for traffic patterns and anomalies."""
    try:
        reader = PCAPReader(Path(pcap_file))
        packets = reader.packets()
    except ValueError as exc:
        click.echo(f"[error] {exc}", err=True)
        sys.exit(1)

    analyser = PCAPAnalyser()
    stats = analyser.analyse(packets)

    if not anomalies_only:
        click.echo(f"Packets      : {stats.total_packets}")
        click.echo(f"Total bytes  : {stats.total_bytes}")
        click.echo(f"Duration     : {stats.duration_seconds:.1f}s")
        click.echo(f"Protocols    : {stats.protocol_counts}")

        click.echo(f"\nTop {top_n} talkers (by bytes):")
        for ip, b in stats.top_talkers[:top_n]:
            click.echo(f"  {ip:<18} {b:>10} bytes")

        if flows:
            click.echo(f"\nFlows ({len(stats.flows)}):")
            for fl in sorted(stats.flows, key=lambda f: f.byte_count, reverse=True)[:20]:
                click.echo(
                    f"  {fl.src_ip}:{fl.src_port} → {fl.dst_ip}:{fl.dst_port} "
                    f"proto={fl.protocol} pkts={fl.packet_count} bytes={fl.byte_count}"
                )

    if stats.anomalies:
        click.echo("\n[!] Anomalies detected:")
        for a in stats.anomalies:
            click.echo(f"  {a}")
        sys.exit(2)
    else:
        if not anomalies_only:
            click.echo("\n[ok] No anomalies detected.")
