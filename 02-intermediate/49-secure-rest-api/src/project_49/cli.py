"""CLI entry point for Secure REST API Template."""

from __future__ import annotations

import click


@click.group()
def cli() -> None:
    """Secure REST API Template — run the API server or sign requests."""


@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True)
@click.option("--reload", is_flag=True)
def serve_cmd(host: str, port: int, reload: bool) -> None:
    """Start the FastAPI development server."""
    try:
        import uvicorn
    except ImportError as exc:
        raise click.ClickException("Install uvicorn: pip install uvicorn") from exc
    uvicorn.run("project_49.app:app", host=host, port=port, reload=reload)
