"""Terraform Security Scanner — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_90.core import ScanReport, scan_directory, scan_file


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Terraform Security Scanner — static analysis for Terraform HCL files."""


def _print_report(report: ScanReport, min_severity: str) -> None:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = order.index(min_severity)
    colors = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}
    for f in report.findings:
        if f.severity in order and order.index(f.severity) >= threshold:
            click.echo(
                click.style(f"  [{f.severity}]", fg=colors[f.severity])
                + f" {f.check_id} — {f.title}"
            )
            click.echo(f"    {f.resource_type}.{f.resource_name}  ({f.file_path}:{f.line_number})")
            click.echo(f"    {f.detail}")


@cli.command("scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="MEDIUM", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False)
def scan_cmd(path: Path, output: Path | None, min_severity: str, exit_code: bool) -> None:
    """Scan Terraform files for security misconfigurations."""
    if path.is_dir():
        report = scan_directory(path)
        click.echo(f"Scanned {report.files_scanned} .tf file(s) in {path}")
    else:
        findings = scan_file(path)
        report = ScanReport(findings=findings, files_scanned=1, source=str(path))
        click.echo(f"Scanned {path.name}")

    click.echo(f"Findings: {len(report.findings)}")
    _print_report(report, min_severity)

    if output:
        output.write_text(json.dumps(report.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(f.severity in ("CRITICAL", "HIGH") for f in report.findings):
        sys.exit(1)
