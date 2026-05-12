"""CLI for Port Scan Detection from Logs."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .core import analyse_log_file


@click.command()
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--threshold", default=15, show_default=True,
              help="Distinct ports to trigger alert.")
@click.option("--window", default=60.0, show_default=True,
              help="Time window in seconds.")
@click.option("--verbose", is_flag=True)
def cli(log_file: str, threshold: int, window: float, verbose: bool) -> None:
    """Detect port scan activity from firewall/access log files."""
    lines = Path(log_file).read_text(encoding="utf-8").splitlines()
    alerts = analyse_log_file(lines, port_threshold=threshold, window_seconds=window)

    if not alerts:
        click.echo("[ok] No port scan activity detected.")
        return

    click.echo(f"[!] Detected {len(alerts)} scan(s):\n")
    for alert in alerts:
        click.echo(
            f"  [{alert.severity.upper()}] {alert.source_ip} — "
            f"{alert.scan_type} scan — {alert.distinct_ports} ports"
        )
        if verbose:
            click.echo(f"        ports: {list(alert.port_list[:20])}{'...' if len(alert.port_list) > 20 else ''}")

    sys.exit(2)  # non-zero exit when scans detected
