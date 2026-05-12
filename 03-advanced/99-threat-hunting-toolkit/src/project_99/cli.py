"""Threat Hunting Toolkit — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_99.core import (
    BUILTIN_RULES,
    HuntReport,
    hunt_directory,
    hunt_file,
    hunt_iocs_in_text,
    load_ioc_file,
    load_rules_file,
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Threat Hunting Toolkit — rule-based hunting across log files."""


@cli.command("hunt")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--rules", "-r", type=click.Path(exists=True, path_type=Path), default=None,
              help="Custom rules JSON file (default: built-in rules)")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--min-severity", default="MEDIUM", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
@click.option("--exit-code", is_flag=True, default=False)
def hunt_cmd(
    path: Path,
    rules: Path | None,
    output: Path | None,
    min_severity: str,
    exit_code: bool,
) -> None:
    """Hunt for threats in a log file or directory."""
    active_rules = load_rules_file(rules) if rules else list(BUILTIN_RULES)
    if path.is_dir():
        report = hunt_directory(path, active_rules)
        click.echo(f"Hunted {report.files_scanned} file(s) in {path}")
    else:
        matches = hunt_file(path, active_rules)
        report = HuntReport(matches=matches, files_scanned=1,
                            rules_applied=len(active_rules), source=str(path))
        click.echo(f"Hunted {path.name}")

    click.echo(f"Matches: {len(report.matches)}  (rules: {report.rules_applied})")
    _print_matches(report, min_severity)

    if output:
        output.write_text(json.dumps(report.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(m.severity in ("CRITICAL", "HIGH") for m in report.matches):
        sys.exit(1)


@cli.command("ioc-scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--iocs", "-i", required=True, type=click.Path(exists=True, path_type=Path),
              help="JSONL file of IOCs ({\"type\": \"ip\", \"value\": \"...\"}).")
def ioc_scan_cmd(path: Path, iocs: Path) -> None:
    """Scan a file for known IOC hits."""
    ioc_list = load_ioc_file(iocs)
    text = path.read_text(encoding="utf-8", errors="replace")
    hits = hunt_iocs_in_text(text, ioc_list)
    click.echo(f"Scanned {path.name} against {len(ioc_list)} IOCs")
    click.echo(f"Hits: {len(hits)}")
    for ioc, lineno, line in hits[:20]:
        click.echo(f"  [{ioc.ioc_type}] {ioc.value}  — line {lineno}: {line[:100]}")


@cli.command("list-rules")
def list_rules_cmd() -> None:
    """List all built-in hunt rules."""
    for rule in BUILTIN_RULES:
        click.echo(f"  {rule.rule_id}  [{rule.severity}]  {rule.name}  ({rule.mitre_technique})")


def _print_matches(report: HuntReport, min_severity: str) -> None:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = order.index(min_severity)
    colors = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}
    for m in report.matches:
        if m.severity in order and order.index(m.severity) >= threshold:
            click.echo(
                click.style(f"  [{m.severity}]", fg=colors.get(m.severity, "white"))
                + f" {m.rule_id} — {m.rule_name}  [{m.mitre_technique}]"
            )
            click.echo(f"    {m.file_path}:{m.line_number}")
            click.echo(f"    {m.line_content[:100]}")
