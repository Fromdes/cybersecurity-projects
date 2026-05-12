"""Real-Time FIM — CLI interface."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from project_78.core import WATCHDOG_AVAILABLE, Baseline, FIMEventLog, FIMWatcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Real-Time File Integrity Monitor (inotify/watchdog)."""


@cli.command("baseline")
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", required=True, type=click.Path(path_type=Path),
              help="Baseline output JSON file.")
@click.option("--no-recursive", is_flag=True, default=False, help="Do not recurse into subdirectories.")
def baseline_cmd(paths: tuple[Path, ...], output: Path, no_recursive: bool) -> None:
    """Build a file integrity baseline for given paths."""
    b = Baseline()
    count = b.build(list(paths), recursive=not no_recursive)
    b.save(output)
    click.echo(f"Baseline built: {count} file(s) → {output}")


@cli.command("verify")
@click.argument("baseline_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="JSONL file to write deviations to.")
def verify_cmd(baseline_file: Path, output: Path | None) -> None:
    """Verify current filesystem state against a saved baseline."""
    b = Baseline.load(baseline_file)
    events = b.verify()
    if not events:
        click.echo("All files match baseline. No deviations found.")
        return
    click.echo(f"{len(events)} deviation(s) found:")
    event_log = FIMEventLog(output_path=output)
    for ev in events:
        event_log.record(ev)
        color = {"MODIFIED": "yellow", "DELETED": "red", "CREATED": "green", "MOVED": "cyan"}.get(
            ev.event_type.value, "white"
        )
        click.echo(
            click.style(f"[{ev.event_type.value}]", fg=color) + f" {ev.path}"
        )
    if output:
        click.echo(f"Deviations written to {output}")


@cli.command("watch")
@click.argument("baseline_file", type=click.Path(exists=True, path_type=Path))
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-recursive", is_flag=True, default=False)
def watch_cmd(baseline_file: Path, paths: tuple[Path, ...], output: Path | None, no_recursive: bool) -> None:
    """Watch paths in real-time against a baseline. Requires watchdog."""
    if not WATCHDOG_AVAILABLE:
        click.echo("ERROR: watchdog not installed. Run: pip install watchdog", err=True)
        sys.exit(1)
    b = Baseline.load(baseline_file)
    event_log = FIMEventLog(output_path=output)

    def on_event(event: object) -> None:
        from project_78.core import FIMEvent
        if isinstance(event, FIMEvent):
            event_log.record(event)
            color = {"MODIFIED": "yellow", "DELETED": "red", "CREATED": "green", "MOVED": "cyan"}.get(
                event.event_type.value, "white"
            )
            click.echo(click.style(f"[{event.event_type.value}]", fg=color) + f" {event.path}")

    watcher = FIMWatcher(b, list(paths), on_event, recursive=not no_recursive)
    watcher.start()
    click.echo(f"Watching {list(paths)} … Ctrl+C to stop.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watcher.stop()
        click.echo("\nStopped.")
