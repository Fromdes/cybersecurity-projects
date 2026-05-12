"""Secrets Scanner — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_84.core import BUILTIN_RULES, SecretsScanner, batch_scan


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Secrets Scanner — detect hardcoded credentials in source code."""


@cli.command("scan")
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--no-recursive", is_flag=True, default=False)
@click.option("--min-severity", default="LOW", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False,
              help="Exit with code 1 if secrets are found (useful for CI).")
def scan_cmd(
    target: Path,
    output: Path | None,
    no_recursive: bool,
    min_severity: str,
    exit_code: bool,
) -> None:
    """Scan a file or directory for hardcoded secrets."""
    scanner = SecretsScanner()
    _order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold_idx = _order.index(min_severity)

    if target.is_file():
        result = scanner.scan_file(target)
        results = [result]
        total_findings = len(result.findings)
        click.echo(f"Scanned {target.name}: {result.lines_scanned} lines, {total_findings} finding(s)")
        for finding in result.findings:
            if _order.index(finding.severity) >= threshold_idx:
                _print_finding(finding)
    else:
        summary = batch_scan(scanner, target, recursive=not no_recursive)
        results = summary.results
        click.echo(
            f"Scanned {summary.total_files} file(s): "
            f"{summary.files_with_findings} with findings, "
            f"{summary.total_findings} total secret(s)"
        )
        for result in results:
            for finding in result.findings:
                if _order.index(finding.severity) >= threshold_idx:
                    _print_finding(finding)
        if summary.by_severity:
            click.echo("\nBy severity: " + ", ".join(f"{k}={v}" for k, v in summary.by_severity.items()))

    if output:
        all_findings = [f.to_dict() for r in results for f in r.findings]
        output.write_text(json.dumps(all_findings, indent=2))
        click.echo(f"\nFindings saved to {output}")

    total = sum(len(r.findings) for r in results)
    if exit_code and total > 0:
        sys.exit(1)


def _print_finding(finding: object) -> None:
    from project_84.core import SecretFinding
    if not isinstance(finding, SecretFinding):
        return
    color = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}[finding.severity]
    click.echo(
        click.style(f"[{finding.severity}]", fg=color)
        + f" {finding.rule_name} — {finding.file_path}:{finding.line_number}"
    )
    click.echo(f"  {finding.line_content[:100]}")


@cli.command("rules")
def rules_cmd() -> None:
    """List all built-in secret detection rules."""
    click.echo(f"{'Rule':<30} {'Severity':<10} Description")
    click.echo("─" * 80)
    for rule in BUILTIN_RULES:
        color = {"LOW": "white", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}[rule.severity]
        click.echo(
            click.style(f"{rule.name:<30}", fg=color)
            + f" {rule.severity:<10} {rule.description}"
        )
