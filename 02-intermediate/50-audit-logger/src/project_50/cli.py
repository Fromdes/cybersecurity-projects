"""CLI for Audit Log System."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import click

from .core import AuditLog, Severity

DEFAULT_LOG = "audit.jsonl"


@click.group()
def cli() -> None:
    """Audit Log System — append and query tamper-evident audit events."""


@cli.command("log")
@click.option("--log-file", default=DEFAULT_LOG, show_default=True)
@click.option("--actor", required=True, help="Who performed the action.")
@click.option("--action", required=True, help="Action name (e.g. LOGIN).")
@click.option("--resource", required=True, help="Resource acted on.")
@click.option("--outcome", default="success", show_default=True,
              type=click.Choice(["success", "failure", "error"]))
@click.option("--severity", default="INFO", show_default=True,
              type=click.Choice(["INFO", "WARNING", "ERROR", "CRITICAL"]))
@click.option("--ip", default="", help="Source IP address.")
@click.option("--session", default="", help="Session ID.")
def log_cmd(
    log_file: str, actor: str, action: str, resource: str,
    outcome: str, severity: str, ip: str, session: str,
) -> None:
    """Append a new audit event to the log."""
    audit = AuditLog(log_path=Path(log_file))
    event = audit.append(
        actor=actor, action=action, resource=resource,
        outcome=outcome, severity=Severity(severity),
        ip_address=ip, session_id=session,
    )
    click.echo(f"[ok] Event logged: {event.event_id}")


@cli.command("query")
@click.option("--log-file", default=DEFAULT_LOG, show_default=True)
@click.option("--actor", default=None)
@click.option("--action", default=None)
@click.option("--outcome", default=None)
@click.option("--severity", default=None)
@click.option("--last-hours", default=None, type=float,
              help="Only show events from the last N hours.")
@click.option("--json-output", is_flag=True)
def query_cmd(
    log_file: str, actor: str | None, action: str | None,
    outcome: str | None, severity: str | None,
    last_hours: float | None, json_output: bool,
) -> None:
    """Query audit events."""
    audit = AuditLog(log_path=Path(log_file))
    since = time.time() - last_hours * 3600 if last_hours else None
    events = audit.query(actor=actor, action=action, outcome=outcome,
                         severity=severity, since=since)
    if not events:
        click.echo("No matching events.")
        return
    for e in events:
        if json_output:
            click.echo(e.to_json())
        else:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.timestamp))
            click.echo(
                f"[{ts}] [{e.severity}] {e.actor} {e.action} {e.resource} → {e.outcome}"
            )


@cli.command("verify")
@click.option("--log-file", default=DEFAULT_LOG, show_default=True)
def verify_cmd(log_file: str) -> None:
    """Verify hash-chain integrity of the log."""
    audit = AuditLog(log_path=Path(log_file))
    ok, msg = audit.verify_chain()
    if ok:
        click.echo(f"[ok] {msg}")
    else:
        click.echo(f"[TAMPERED] {msg}", err=True)
        sys.exit(1)
