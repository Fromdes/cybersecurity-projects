"""Cloud IAM Policy Analyzer — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_91.core import PolicyAnalysis, analyze_policy_file


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Cloud IAM Policy Analyzer — detect overpermissive AWS IAM policies."""


def _print_analysis(analysis: PolicyAnalysis, min_severity: str) -> None:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = order.index(min_severity)
    colors = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}
    for f in analysis.findings:
        if f.severity in order and order.index(f.severity) >= threshold:
            click.echo(
                click.style(f"  [{f.severity}]", fg=colors[f.severity])
                + f" {f.rule_id} — {f.title}"
            )
            click.echo(f"    Sid: {f.statement_sid}")
            click.echo(f"    {f.description}")


@cli.command("analyze")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="MEDIUM", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False)
def analyze_cmd(policy_file: Path, output: Path | None, min_severity: str, exit_code: bool) -> None:
    """Analyze an AWS IAM policy JSON file for dangerous permissions."""
    analysis = analyze_policy_file(policy_file)
    click.echo(f"Policy: {analysis.policy_name}  ({analysis.statement_count} statement(s))")
    click.echo(f"Findings: {len(analysis.findings)}")
    _print_analysis(analysis, min_severity)

    if output:
        output.write_text(json.dumps(analysis.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(f.severity in ("CRITICAL", "HIGH") for f in analysis.findings):
        sys.exit(1)
