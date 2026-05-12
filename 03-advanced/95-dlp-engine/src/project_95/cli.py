"""DLP Engine — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_95.core import (
    DEFAULT_RULES,
    DLPReport,
    redact_text,
    scan_directory,
    scan_file,
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """DLP Engine — detect and redact sensitive data in files."""


def _print_report(report: DLPReport, min_severity: str) -> None:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = order.index(min_severity)
    colors = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}
    for f in report.findings:
        if f.severity in order and order.index(f.severity) >= threshold:
            click.echo(
                click.style(f"  [{f.severity}]", fg=colors[f.severity])
                + f" {f.rule_id} {f.rule_name} ({f.category})"
            )
            click.echo(f"    {f.file_path}:{f.line_number}:{f.column}")
            click.echo(f"    Match: {f.matched_text[:60]!r}")


@cli.command("scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="MEDIUM", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False)
@click.option("--category", "-c", multiple=True, help="Filter by category (repeatable)")
def scan_cmd(
    path: Path,
    output: Path | None,
    min_severity: str,
    exit_code: bool,
    category: tuple[str, ...],
) -> None:
    """Scan files for sensitive data."""
    rules = DEFAULT_RULES
    if category:
        rules = tuple(r for r in rules if r.category.lower() in {c.lower() for c in category})

    if path.is_dir():
        report = scan_directory(path, rules=rules)
        click.echo(f"Scanned {report.files_scanned} file(s) in {path}")
    else:
        findings = scan_file(path, rules=rules)
        report = DLPReport(findings=findings, files_scanned=1, source=str(path))
        click.echo(f"Scanned {path.name}")

    click.echo(f"Findings: {len(report.findings)}")
    _print_report(report, min_severity)

    if output:
        output.write_text(json.dumps(report.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(f.severity in ("CRITICAL", "HIGH") for f in report.findings):
        sys.exit(1)


@cli.command("redact")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output file (default: stdout)")
def redact_cmd(input_file: Path, output: Path | None) -> None:
    """Redact sensitive data from a file."""
    text = input_file.read_text(encoding="utf-8", errors="replace")
    redacted = redact_text(text)
    if output:
        output.write_text(redacted)
        click.echo(f"Redacted output saved to {output}")
    else:
        click.echo(redacted, nl=False)
