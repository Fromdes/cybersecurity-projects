"""S3 Misconfiguration Detector — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_92.core import BucketAnalysis, analyze_policy_file


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """S3 Misconfiguration Detector — analyze S3 bucket policies for security issues."""


def _print_analysis(analysis: BucketAnalysis, min_severity: str) -> None:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = order.index(min_severity)
    colors = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}
    for f in analysis.findings:
        if f.severity in order and order.index(f.severity) >= threshold:
            click.echo(
                click.style(f"  [{f.severity}]", fg=colors[f.severity])
                + f" {f.rule_id} — {f.title}"
            )
            click.echo(f"    Principal: {f.principal}")
            click.echo(f"    {f.description}")


@cli.command("check")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
@click.option("--bucket-name", "-b", default=None, help="Override bucket name for display")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="MEDIUM", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False)
def check_cmd(
    policy_file: Path,
    bucket_name: str | None,
    output: Path | None,
    min_severity: str,
    exit_code: bool,
) -> None:
    """Check an S3 bucket policy JSON file for misconfigurations."""
    analysis = analyze_policy_file(policy_file)
    if bucket_name:
        from project_92.core import analyze_bucket_policy
        import json as _json
        policy = _json.loads(policy_file.read_text())
        analysis = analyze_bucket_policy(policy, bucket_name=bucket_name, source=str(policy_file))
    click.echo(f"Bucket: {analysis.bucket_name}  ({analysis.statement_count} statement(s))")
    click.echo(f"Findings: {len(analysis.findings)}")
    _print_analysis(analysis, min_severity)

    if output:
        output.write_text(json.dumps(analysis.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(f.severity in ("CRITICAL", "HIGH") for f in analysis.findings):
        sys.exit(1)
