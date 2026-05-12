"""Kubernetes RBAC Auditor — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_89.core import audit_file


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Kubernetes RBAC Auditor — detect privilege escalation in Role/ClusterRole YAML."""


@cli.command("audit")
@click.argument("yaml_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="MEDIUM", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False)
def audit_cmd(yaml_file: Path, output: Path | None, min_severity: str, exit_code: bool) -> None:
    """Audit Kubernetes RBAC YAML for dangerous permissions."""
    report = audit_file(yaml_file)
    click.echo(f"Audited {report.resources_audited} RBAC resource(s) from {yaml_file.name}")
    click.echo(f"Findings: {len(report.findings)}")

    _order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = _order.index(min_severity)
    for f in report.findings:
        if f.severity in _order and _order.index(f.severity) >= threshold:
            color = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}[f.severity]
            click.echo(click.style(f"  [{f.severity}]", fg=color) + f" {f.rule_id} — {f.title}")
            click.echo(f"    {f.kind}/{f.resource_name}")

    if output:
        output.write_text(json.dumps(report.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(f.severity in ("CRITICAL", "HIGH") for f in report.findings):
        sys.exit(1)
