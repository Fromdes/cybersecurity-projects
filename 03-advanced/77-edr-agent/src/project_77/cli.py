"""Lightweight EDR Agent — CLI interface."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

import click

from project_77.core import EDRAgent, ThreatLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Lightweight EDR Agent — endpoint detection and response."""


@cli.command("scan")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="JSONL file to write findings to.")
@click.option("--min-level", default="LOW", show_default=True,
              type=click.Choice([l.value for l in ThreatLevel]),
              help="Minimum threat level to display.")
def scan_cmd(output: Path | None, min_level: str) -> None:
    """Run a single EDR scan of the current system."""
    agent = EDRAgent(output_path=output)
    click.echo("Running EDR scan …")
    findings = agent.scan_once()
    _order = [ThreatLevel.INFO, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
    threshold_idx = _order.index(ThreatLevel(min_level))
    visible = [f for f in findings if _order.index(f.threat_level) >= threshold_idx]
    click.echo(f"Scan complete: {len(findings)} finding(s) total, {len(visible)} at or above {min_level}.")
    if visible:
        click.echo(f"\n{'─'*70}")
        for f in visible:
            color = {"INFO": "white", "LOW": "cyan", "MEDIUM": "yellow",
                     "HIGH": "red", "CRITICAL": "bright_red"}[f.threat_level.value]
            click.echo(
                click.style(f"[{f.threat_level.value}] {f.category}", fg=color)
                + f" — {f.description}"
            )
        click.echo(f"{'─'*70}")
    if output:
        click.echo(f"Findings written to {output}")


@cli.command("monitor")
@click.option("--interval", default=30.0, show_default=True, help="Scan interval in seconds.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def monitor_cmd(interval: float, output: Path | None) -> None:
    """Run continuous EDR monitoring. Press Ctrl+C to stop."""
    agent = EDRAgent(output_path=output)
    stop_event = threading.Event()
    click.echo(f"EDR monitoring started (interval={interval}s). Ctrl+C to stop …")
    try:
        agent.run_continuous(interval, stop_event)
    except KeyboardInterrupt:
        stop_event.set()
        summary = agent.summary()
        click.echo("\nMonitoring stopped.")
        click.echo("Summary: " + json.dumps(summary))


@cli.command("report")
@click.argument("findings_file", type=click.Path(exists=True, path_type=Path))
def report_cmd(findings_file: Path) -> None:
    """Summarize a JSONL findings file."""
    counts: dict[str, int] = {}
    total = 0
    with findings_file.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                lvl = obj.get("threat_level", "UNKNOWN")
                counts[lvl] = counts.get(lvl, 0) + 1
                total += 1
            except json.JSONDecodeError:
                continue
    click.echo(f"Total findings: {total}")
    for lvl, cnt in sorted(counts.items()):
        click.echo(f"  {lvl}: {cnt}")
