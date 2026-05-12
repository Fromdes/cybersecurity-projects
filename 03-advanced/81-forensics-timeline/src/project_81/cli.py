"""Forensics Timeline Builder — CLI interface."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import click

from project_81.core import (
    ForensicsTimeline,
    collect_filesystem_events,
    collect_generic_log_events,
    collect_syslog_events,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Forensics Timeline Builder — unified timeline from multiple artifact sources."""


@cli.command("build")
@click.option("--fs", "fs_paths", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="File/directory path to collect filesystem timestamps from.")
@click.option("--syslog", "syslog_files", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Syslog-format log files to parse.")
@click.option("--log", "log_files", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Generic log files with ISO8601 timestamps.")
@click.option("--output", "-o", required=True, type=click.Path(path_type=Path))
@click.option("--format", "fmt", default="jsonl", show_default=True,
              type=click.Choice(["jsonl", "csv"]), help="Output format.")
@click.option("--start", default=None, help="Filter start (ISO8601 datetime).")
@click.option("--end", default=None, help="Filter end (ISO8601 datetime).")
@click.option("--no-recursive", is_flag=True, default=False)
def build_cmd(
    fs_paths: tuple[Path, ...],
    syslog_files: tuple[Path, ...],
    log_files: tuple[Path, ...],
    output: Path,
    fmt: str,
    start: str | None,
    end: str | None,
    no_recursive: bool,
) -> None:
    """Build a forensic timeline from specified artifact sources."""
    timeline = ForensicsTimeline()
    total = 0

    for path in fs_paths:
        count = timeline.add_events(collect_filesystem_events(path, recursive=not no_recursive))
        click.echo(f"  filesystem {path}: {count} events")
        total += count

    for log_path in syslog_files:
        count = timeline.add_events(collect_syslog_events(log_path))
        click.echo(f"  syslog {log_path.name}: {count} events")
        total += count

    for log_path in log_files:
        count = timeline.add_events(collect_generic_log_events(log_path))
        click.echo(f"  generic log {log_path.name}: {count} events")
        total += count

    start_dt = datetime.fromisoformat(start).replace(tzinfo=UTC) if start else None
    end_dt = datetime.fromisoformat(end).replace(tzinfo=UTC) if end else None

    if fmt == "jsonl":
        written = timeline.to_jsonl(output)
    else:
        written = timeline.to_csv(output)

    summary = timeline.summary()
    click.echo(f"\nTimeline built: {total} events collected, {written} written to {output}")
    if summary.get("earliest"):
        click.echo(f"  Earliest: {summary['earliest']}")
        click.echo(f"  Latest:   {summary['latest']}")
    for src, cnt in summary.get("by_source", {}).items():
        click.echo(f"  {src}: {cnt}")


@cli.command("summary")
@click.argument("timeline_file", type=click.Path(exists=True, path_type=Path))
def summary_cmd(timeline_file: Path) -> None:
    """Print summary statistics for a JSONL timeline file."""
    timeline = ForensicsTimeline()
    with timeline_file.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                from project_81.core import TimelineEvent
                event = TimelineEvent.from_dict(json.loads(line))
                timeline._events.append(event)
            except (json.JSONDecodeError, KeyError):
                continue
    summary = timeline.summary()
    click.echo(json.dumps(summary, indent=2))
