"""CLI for NetFlow/IPFIX Analyzer."""

from __future__ import annotations

import socket
import sys

import click

from .core import NetFlowRecord, analyse_records, parse_netflow_v5


@click.group()
def cli() -> None:
    """NetFlow/IPFIX Analyzer — collect and analyse NetFlow v5 traffic data."""


@cli.command("collect")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=2055, show_default=True)
@click.option("--packets", default=10, show_default=True, help="Stop after N datagrams.")
@click.option("--timeout", default=30, show_default=True)
def collect_cmd(host: str, port: int, packets: int, timeout: int) -> None:
    """Listen for NetFlow v5 datagrams and print flow records."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(timeout)
    click.echo(f"Listening for NetFlow v5 on {host}:{port}")

    collected = 0
    try:
        while collected < packets:
            try:
                data, addr = sock.recvfrom(65535)
            except TimeoutError:
                break
            packet = parse_netflow_v5(data)
            if not packet:
                continue
            click.echo(f"[{addr[0]}] {packet.count} flows (seq={packet.flow_sequence})")
            for r in packet.records:
                click.echo(
                    f"  {r.src_ip}:{r.src_port} → {r.dst_ip}:{r.dst_port} "
                    f"proto={r.protocol_name} pkts={r.packets} bytes={r.bytes_count}"
                )
            collected += 1
    finally:
        sock.close()


@cli.command("analyse")
@click.argument("records_file", type=click.Path(exists=True))
def analyse_cmd(records_file: str) -> None:
    """Analyse a CSV file of flow records (src_ip,dst_ip,src_port,dst_port,proto,pkts,bytes)."""
    import csv
    records: list[NetFlowRecord] = []
    with open(records_file, encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                records.append(NetFlowRecord(
                    src_ip=row["src_ip"], dst_ip=row["dst_ip"],
                    src_port=int(row["src_port"]), dst_port=int(row["dst_port"]),
                    protocol=int(row["proto"]), packets=int(row["pkts"]),
                    bytes_count=int(row["bytes"]),
                    first_ms=0, last_ms=0, tcp_flags=0, tos=0,
                ))
            except (KeyError, ValueError):
                continue

    stats = analyse_records(records)
    click.echo(f"Flows   : {stats.total_flows}")
    click.echo(f"Packets : {stats.total_packets}")
    click.echo(f"Bytes   : {stats.total_bytes}")
    click.echo(f"Protocols: {stats.protocol_dist}")
    click.echo("\nTop talkers:")
    for ip, b in stats.top_talkers[:5]:
        click.echo(f"  {ip:<18} {b:>12} bytes")
    if stats.anomalies:
        click.echo("\n[!] Anomalies:")
        for a in stats.anomalies:
            click.echo(f"  {a}")
        sys.exit(2)
