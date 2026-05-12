"""CLI for Login Anomaly Detector."""

from __future__ import annotations

import sys

import click

from project_75.core import analyse_log_file


@click.group()
def cli() -> None:
    """Login Anomaly Detector — detect suspicious patterns in authentication logs."""


@cli.command()
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--threshold", "-t", default=5, show_default=True,
              help="Consecutive failure threshold for brute-force detection")
@click.option("--baseline", "-b", type=click.Path(exists=True),
              help="Historical log file to build baseline profiles")
def analyse(log_file: str, threshold: int, baseline: str | None) -> None:
    """Analyse LOG_FILE for login anomalies."""
    with open(log_file) as fh:
        lines = fh.readlines()

    baseline_events = None
    if baseline:
        from project_75.core import parse_log_file
        with open(baseline) as fh:
            baseline_events = parse_log_file(fh.readlines())

    state = analyse_log_file(lines, brute_force_threshold=threshold,
                              baseline_events=baseline_events)

    click.echo(f"\nLogin Anomaly Analysis: {log_file}")
    click.echo(f"  Users tracked : {len(state.profiles)}")
    click.echo(f"  Anomalies     : {len(state.anomalies)}")

    if not state.anomalies:
        click.echo("  No anomalies detected.")
        return

    click.echo("\nAnomalies:")
    for a in sorted(state.anomalies, key=lambda x: x.timestamp):
        click.echo(
            f"  [{a.severity.upper():8s}] [{a.anomaly_type:25s}] {a.username}: {a.description}"
        )
