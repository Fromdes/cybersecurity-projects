"""CLI for SSH Brute-Force Detection Daemon."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from .core import BruteForceDetector, analyse_auth_log, parse_line


@click.group()
def cli() -> None:
    """SSH Brute-Force Detector — analyse auth.log for attack patterns."""


@cli.command("analyse")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--threshold", default=5, show_default=True)
@click.option("--window", default=60, show_default=True, help="Window in seconds.")
def analyse_cmd(log_file: str, threshold: int, window: int) -> None:
    """Analyse an auth.log file for brute-force attacks."""
    lines = Path(log_file).read_text(encoding="utf-8", errors="replace").splitlines()
    alerts = analyse_auth_log(lines, threshold=threshold, window=window)

    if not alerts:
        click.echo("[ok] No brute-force activity detected.")
        return

    click.echo(f"[!] {len(alerts)} brute-force alert(s):\n")
    for a in alerts:
        click.echo(
            f"  [{a.severity.upper()}] {a.src_ip} — {a.attempt_count} attempts — "
            f"users: {', '.join(a.usernames[:5])}"
        )
    sys.exit(2)


@cli.command("tail")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--threshold", default=5, show_default=True)
@click.option("--window", default=60, show_default=True)
@click.option("--interval", default=5.0, show_default=True)
def tail_cmd(log_file: str, threshold: int, window: int, interval: float) -> None:
    """Tail-follow auth.log and alert on brute-force in real time."""
    detector = BruteForceDetector(threshold=threshold, window=window)
    click.echo(f"Watching {log_file} (Ctrl+C to stop)")
    seen_lines = 0
    try:
        while True:
            lines = Path(log_file).read_text(encoding="utf-8", errors="replace").splitlines()
            new_lines = lines[seen_lines:]
            seen_lines = len(lines)
            base = time.time()
            for i, line in enumerate(new_lines):
                attempt = parse_line(line, base_timestamp=base + i * 0.001)
                if attempt:
                    detector.record(attempt)
            alerts = detector.analyse()
            for a in alerts:
                click.echo(
                    f"[ALERT] {a.src_ip}: {a.attempt_count} attempts "
                    f"({a.severity})"
                )
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
