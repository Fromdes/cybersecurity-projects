"""CLI for CSRF Token Service."""

from __future__ import annotations

import os
import sys

import click

from .core import CSRFService


def _get_service() -> CSRFService:
    secret_str = os.environ.get("CSRF_SECRET", "changeme-in-production-32-bytes!!")
    return CSRFService(secret=secret_str.encode())


@click.group()
def cli() -> None:
    """CSRF Token Service — generate and validate CSRF tokens."""


@cli.command("generate")
@click.argument("session_id")
def generate_cmd(session_id: str) -> None:
    """Generate a CSRF token for SESSION_ID."""
    svc = _get_service()
    token = svc.generate_token(session_id)
    click.echo(token)


@cli.command("validate")
@click.argument("session_id")
@click.argument("token")
def validate_cmd(session_id: str, token: str) -> None:
    """Validate TOKEN for SESSION_ID (uses in-memory store, demo only)."""
    svc = _get_service()
    svc.generate_token(session_id)
    try:
        svc.validate_token(session_id, token)
        click.echo("[ok] Token valid.")
    except Exception as exc:
        click.echo(f"[fail] {exc}", err=True)
        sys.exit(1)


@cli.command("demo")
def demo_cmd() -> None:
    """Run a short end-to-end demo."""
    svc = _get_service()
    sid = "user-session-abc123"
    token = svc.generate_token(sid)
    click.echo(f"Generated : {token}")
    svc.validate_token(sid, token)
    click.echo("Validation: PASS")
    rotated = svc.rotate_token(sid)
    click.echo(f"Rotated   : {rotated}")
    click.echo("Demo complete.")
