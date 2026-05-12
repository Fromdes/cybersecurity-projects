"""CLI for HTTP Honeypot Logger."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click


@click.group()
def cli() -> None:
    """HTTP Honeypot Logger — capture and analyse HTTP attack traffic."""


@cli.command("serve")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8080, show_default=True)
@click.option("--log-file", default="honeypot-http.jsonl", show_default=True)
def serve_cmd(host: str, port: int, log_file: str) -> None:
    """Start the HTTP honeypot server."""
    try:
        import logging
        from pathlib import Path as P

        from flask import Flask

        from .app import _honeypot_logger, app
        from .core import HTTPHoneypotLogger
        _honeypot_logger.log_path = P(log_file)
    except ImportError as exc:
        click.echo(f"[error] Install flask: pip install flask — {exc}", err=True)
        sys.exit(1)

    click.echo(f"HTTP honeypot on {host}:{port} → {log_file}")
    app.run(host=host, port=port, debug=False)


@cli.command("report")
@click.argument("log_file", type=click.Path(exists=True))
def report_cmd(log_file: str) -> None:
    """Summarise a honeypot JSONL log file."""
    lines = Path(log_file).read_text(encoding="utf-8").splitlines()
    events = [json.loads(l) for l in lines if l.strip()]
    threats = [e for e in events if e.get("is_threat")]
    click.echo(f"Total requests : {len(events)}")
    click.echo(f"Threat requests: {len(threats)}")

    type_counts: dict[str, int] = {}
    for e in threats:
        for t in e.get("threat_types", []):
            type_counts[t] = type_counts.get(t, 0) + 1

    if type_counts:
        click.echo("\nThreat types:")
        for t, c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            click.echo(f"  {t:<30} {c}")
