"""Mini SIEM Platform — CLI interface."""

from __future__ import annotations

import json
import logging
import sys
import threading
from pathlib import Path

import click

from project_76.core import (
    AlertStore,
    BUILTIN_RULES,
    SIEMEngine,
    Severity,
    get_parser,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Mini SIEM Platform — log ingestion, detection, and alerting."""


@cli.command("ingest")
@click.argument("log_file", type=click.Path(exists=True, path_type=Path))
@click.option("--parser", default="syslog", show_default=True,
              type=click.Choice(["syslog", "apache", "generic"]),
              help="Log format parser to use.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="JSONL file to write alerts to.")
@click.option("--min-severity", default="LOW", show_default=True,
              type=click.Choice([s.value for s in Severity]),
              help="Minimum severity to display.")
def ingest_cmd(log_file: Path, parser: str, output: Path | None, min_severity: str) -> None:
    """Ingest a log file and display alerts."""
    store = AlertStore(output_path=output)
    engine = SIEMEngine(alert_store=store)
    p = get_parser(parser)
    lines, alert_count = engine.ingest_file(log_file, p)
    click.echo(f"\nProcessed {lines} lines → {alert_count} alert(s) fired.")
    threshold = Severity(min_severity)
    _order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_idx = _order.index(threshold)
    alerts = [a for a in store.get_all() if _order.index(a.severity) >= min_idx]
    if alerts:
        click.echo(f"\n{'─'*70}")
        for a in alerts:
            color = {"LOW": "white", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}[a.severity.value]
            click.echo(click.style(f"[{a.severity.value}] {a.rule_name}", fg=color) + f" — {a.event.message[:80]}")
        click.echo(f"{'─'*70}")
    if output:
        click.echo(f"Alerts written to {output}")


@cli.command("tail")
@click.argument("log_file", type=click.Path(exists=True, path_type=Path))
@click.option("--parser", default="syslog", show_default=True,
              type=click.Choice(["syslog", "apache", "generic"]))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def tail_cmd(log_file: Path, parser: str, output: Path | None) -> None:
    """Tail a log file in real-time and emit alerts as they occur."""
    store = AlertStore(output_path=output)
    engine = SIEMEngine(alert_store=store)
    p = get_parser(parser)
    stop_event = threading.Event()
    click.echo(f"Tailing {log_file} — press Ctrl+C to stop …")
    try:
        engine.tail_file(log_file, p, stop_event)
    except KeyboardInterrupt:
        stop_event.set()
        click.echo("\nStopped.")


@cli.command("rules")
def rules_cmd() -> None:
    """List all built-in detection rules."""
    click.echo(f"{'Name':<35} {'Severity':<10} Description")
    click.echo("─" * 90)
    for r in BUILTIN_RULES:
        color = {"LOW": "white", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}[r.severity.value]
        click.echo(
            click.style(f"{r.name:<35}", fg=color)
            + f" {r.severity.value:<10} {r.description}"
        )


@cli.command("summary")
@click.argument("alerts_file", type=click.Path(exists=True, path_type=Path))
def summary_cmd(alerts_file: Path) -> None:
    """Summarize a JSONL alerts file."""
    counts: dict[str, int] = {}
    total = 0
    with alerts_file.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                sev = obj.get("severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
                total += 1
            except json.JSONDecodeError:
                continue
    click.echo(f"Total alerts: {total}")
    for sev, cnt in sorted(counts.items()):
        click.echo(f"  {sev}: {cnt}")
