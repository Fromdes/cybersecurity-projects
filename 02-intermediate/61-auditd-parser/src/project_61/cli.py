"""CLI for auditd Log Parser."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .core import detect_anomalies, parse_log_file


@click.group()
def cli() -> None:
    """auditd Log Parser — parse and analyse Linux auditd logs."""


@cli.command("parse")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--limit", default=50, show_default=True)
@click.option("--syscall", default=None, help="Filter by syscall name.")
def parse_cmd(log_file: str, limit: int, syscall: str | None) -> None:
    """Parse an auditd log file and print correlated events."""
    events = parse_log_file(Path(log_file))
    for event in events[:limit]:
        if syscall and event.syscall_record:
            if event.syscall_record.syscall_name != syscall:
                continue
        click.echo(event.summary())
    click.echo(f"\nTotal events: {len(events)}")


@cli.command("detect")
@click.argument("log_file", type=click.Path(exists=True))
def detect_cmd(log_file: str) -> None:
    """Detect anomalies in an auditd log file."""
    events = parse_log_file(Path(log_file))
    alerts = detect_anomalies(events)
    if not alerts:
        click.echo("[ok] No anomalies detected.")
        return
    click.echo(f"[!] {len(alerts)} alert(s):\n")
    for a in alerts:
        click.echo(f"  [{a.severity.upper()}] {a.reason}: {a.detail}")
    sys.exit(2)
