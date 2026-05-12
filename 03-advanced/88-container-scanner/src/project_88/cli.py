"""Container Image Scanner — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_88.core import scan_image_tarball


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Container Image Scanner — scan Docker image tarballs for security issues."""


@cli.command("scan")
@click.argument("image_tar", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="INFO", show_default=True,
              type=click.Choice(["INFO", "WARN", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False)
def scan_cmd(image_tar: Path, output: Path | None, min_severity: str, exit_code: bool) -> None:
    """Scan a Docker image tarball for security misconfigurations."""
    click.echo(f"Scanning {image_tar.name} …")
    result = scan_image_tarball(image_tar)

    click.echo(f"SHA256: {result.sha256}")
    click.echo(f"Layers: {len(result.layers)}  Packages: {len(result.packages)}")
    click.echo(f"Findings: {len(result.findings)}")

    _order = ["INFO", "WARN", "HIGH", "CRITICAL"]
    threshold = _order.index(min_severity)
    for f in result.findings:
        if f.severity not in _order or _order.index(f.severity) >= threshold:
            color = {"INFO": "cyan", "WARN": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}.get(
                f.severity, "white"
            )
            click.echo(
                click.style(f"  [{f.severity}]", fg=color) + f" {f.rule_id} — {f.title}"
            )
            if f.file_path:
                click.echo(f"    File: {f.file_path}")

    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(f.severity == "CRITICAL" for f in result.findings):
        sys.exit(1)
