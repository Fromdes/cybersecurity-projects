"""CLI for Centralized Structured Logger."""

from __future__ import annotations

import json
import sys

import click

from .core import get_structured_logger, redact_dict


@click.group()
def cli() -> None:
    """Structured Logger — emit JSON logs and redact sensitive data."""


@cli.command("emit")
@click.option("--service", default="demo-service", show_default=True)
@click.option("--level", default="INFO", show_default=True,
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]))
@click.argument("message")
def emit_cmd(service: str, level: str, message: str) -> None:
    """Emit a structured log line."""
    import logging
    log = get_structured_logger("cli", service_name=service)
    getattr(log, level.lower())(message)


@cli.command("redact")
@click.argument("json_input")
def redact_cmd(json_input: str) -> None:
    """Redact sensitive fields from a JSON string."""
    try:
        data = json.loads(json_input)
    except json.JSONDecodeError as exc:
        click.echo(f"[error] Invalid JSON: {exc}", err=True)
        sys.exit(1)
    if not isinstance(data, dict):
        click.echo("[error] Input must be a JSON object", err=True)
        sys.exit(1)
    click.echo(json.dumps(redact_dict(data), indent=2))


@cli.command("demo")
def demo_cmd() -> None:
    """Run a structured logging demo."""
    log = get_structured_logger("demo", service_name="my-app", environment="staging")
    log.info("Application started")
    log.warning("High memory usage", extra={"memory_mb": 512})
    try:
        raise ValueError("Something went wrong")
    except ValueError:
        log.exception("Caught an error")
