"""Dockerfile Linter & CIS Checker — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_87.core import lint_dockerfile


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Dockerfile Linter — CIS Docker Benchmark static analysis."""


@cli.command("lint")
@click.argument("dockerfile", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="INFO", show_default=True,
              type=click.Choice(["INFO", "WARN", "ERROR", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False,
              help="Exit 1 if CRITICAL or ERROR findings exist.")
def lint_cmd(dockerfile: Path, output: Path | None, min_severity: str, exit_code: bool) -> None:
    """Lint a Dockerfile against CIS benchmarks."""
    result = lint_dockerfile(dockerfile)
    _order = ["INFO", "WARN", "ERROR", "CRITICAL"]
    threshold = _order.index(min_severity)

    click.echo(f"Linting {dockerfile.name} ({result.instructions_count} instructions) …")
    visible = [f for f in result.findings if _order.index(f.severity) >= threshold]

    if not visible:
        click.echo(click.style("No findings above threshold.", fg="green"))
    else:
        for f in visible:
            color = {"INFO": "cyan", "WARN": "yellow", "ERROR": "red", "CRITICAL": "bright_red"}[f.severity]
            line = click.style(f"[{f.severity}]", fg=color) + f" {f.rule_id} — {f.title}"
            if f.line_number:
                line += f" (line {f.line_number})"
            click.echo(line)
            click.echo(f"  {f.description}")

    click.echo(f"\nTotal: {len(result.findings)} finding(s) in {dockerfile.name}")
    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2))
        click.echo(f"Report saved to {output}")

    has_critical = any(f.severity in ("CRITICAL", "ERROR") for f in result.findings)
    if exit_code and has_critical:
        sys.exit(1)


@cli.command("batch")
@click.argument("directory", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def batch_cmd(directory: Path, output: Path | None) -> None:
    """Lint all Dockerfiles in a directory."""
    dockerfiles = list(directory.rglob("Dockerfile*"))
    if not dockerfiles:
        click.echo("No Dockerfiles found.")
        return
    results = []
    for df in dockerfiles:
        r = lint_dockerfile(df)
        results.append(r.to_dict())
        critical = sum(1 for f in r.findings if f.severity in ("CRITICAL", "ERROR"))
        click.echo(f"  {df.name}: {len(r.findings)} findings ({critical} critical/error)")
    if output:
        output.write_text(json.dumps(results, indent=2))
        click.echo(f"Batch report saved to {output}")
