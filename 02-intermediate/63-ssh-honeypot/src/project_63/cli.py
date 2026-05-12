"""CLI for SSH Honeypot Logger."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .core import HoneypotLogger, SSHHoneypotServer


@click.group()
def cli() -> None:
    """SSH Honeypot Logger — capture attacker credentials and banners."""


@cli.command("serve")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=2222, show_default=True)
@click.option("--log-file", default="honeypot-ssh.jsonl", show_default=True)
def serve_cmd(host: str, port: int, log_file: str) -> None:
    """Start the SSH honeypot server."""
    hp_logger = HoneypotLogger(log_path=Path(log_file))
    server = SSHHoneypotServer(host=host, port=port, honeypot_logger=hp_logger)
    click.echo(f"SSH honeypot listening on {host}:{port} — logging to {log_file}")
    click.echo("Press Ctrl+C to stop.")
    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        server.stop()
        click.echo("\nStopped.")


@cli.command("report")
@click.argument("log_file", type=click.Path(exists=True))
def report_cmd(log_file: str) -> None:
    """Summarise a honeypot JSONL log file."""
    lines = Path(log_file).read_text(encoding="utf-8").splitlines()
    events = [json.loads(l) for l in lines if l.strip()]

    connects = [e for e in events if e["event_type"] == "connect"]
    auth_attempts = [e for e in events if e["event_type"] == "auth_attempt"]

    click.echo(f"Total connections  : {len(connects)}")
    click.echo(f"Auth attempts      : {len(auth_attempts)}")

    creds: dict[str, int] = {}
    for e in auth_attempts:
        key = f"{e.get('username','?')}:{e.get('password','?')}"
        creds[key] = creds.get(key, 0) + 1

    if creds:
        click.echo("\nTop credentials:")
        for cred, cnt in sorted(creds.items(), key=lambda x: x[1], reverse=True)[:10]:
            click.echo(f"  {cred:<40} {cnt}")
