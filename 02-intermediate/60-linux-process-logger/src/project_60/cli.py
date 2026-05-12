"""CLI for Linux Process Tree Logger."""

from __future__ import annotations

import json
import sys
import time

import click

from .core import build_process_tree, collect_processes, detect_anomalies


@click.group()
def cli() -> None:
    """Linux Process Tree Logger — snapshot, display, and monitor processes."""


@cli.command("snapshot")
@click.option("--tree", is_flag=True, help="Display as process tree.")
@click.option("--anomalies-only", is_flag=True)
@click.option("--json-output", is_flag=True)
def snapshot_cmd(tree: bool, anomalies_only: bool, json_output: bool) -> None:
    """Take a process snapshot and print results."""
    try:
        procs = collect_processes()
    except ImportError as exc:
        click.echo(f"[error] {exc}", err=True)
        sys.exit(1)

    alerts = detect_anomalies(procs)

    if not anomalies_only:
        if tree:
            roots = build_process_tree(procs)
            for root in roots[:5]:  # limit to top 5 root processes
                for line in root.render():
                    click.echo(line)
        else:
            for p in sorted(procs, key=lambda x: x.pid)[:50]:
                if json_output:
                    click.echo(json.dumps({
                        "pid": p.pid, "ppid": p.ppid, "name": p.name,
                        "user": p.username, "status": p.status,
                    }))
                else:
                    click.echo(f"[{p.pid:6}] {p.name:<25} {p.username:<15} {p.status}")

    if alerts:
        click.echo(f"\n[!] {len(alerts)} anomaly alert(s):")
        for a in alerts:
            click.echo(f"  [{a.severity.upper()}] PID={a.pid} {a.name}: {a.reason}")
        sys.exit(2)


@cli.command("monitor")
@click.option("--interval", default=5.0, show_default=True, help="Poll interval in seconds.")
@click.option("--log-file", default=None, type=click.Path())
def monitor_cmd(interval: float, log_file: str | None) -> None:
    """Continuously monitor processes and log anomalies."""
    click.echo(f"Monitoring (interval={interval}s) — Ctrl+C to stop")
    out = open(log_file, "a", encoding="utf-8") if log_file else None
    try:
        while True:
            procs = collect_processes()
            alerts = detect_anomalies(procs)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            for a in alerts:
                line = f"[{ts}] [{a.severity.upper()}] PID={a.pid} {a.name}: {a.reason}"
                click.echo(line)
                if out:
                    out.write(line + "\n")
                    out.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        if out:
            out.close()
