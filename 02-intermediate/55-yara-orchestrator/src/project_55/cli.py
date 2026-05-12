"""CLI for YARA Rule Engine Orchestrator."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .core import YARA_AVAILABLE, RuleLoader, YARAScanner


@click.group()
def cli() -> None:
    """YARA Rule Engine Orchestrator — compile rules and scan files."""


@cli.command("scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--rules-dir", required=True, type=click.Path(exists=True),
              help="Directory containing .yar/.yara rule files.")
@click.option("--recursive", is_flag=True, default=True, show_default=True)
@click.option("--max-size-mb", default=100, show_default=True)
@click.option("--json-output", is_flag=True)
def scan_cmd(
    target: str, rules_dir: str, recursive: bool, max_size_mb: int, json_output: bool
) -> None:
    """Scan TARGET (file or directory) against YARA rules in RULES_DIR."""
    if not YARA_AVAILABLE:
        click.echo("[error] yara-python is not installed. Run: pip install yara-python", err=True)
        sys.exit(1)

    loader = RuleLoader(rules_dir=Path(rules_dir))
    try:
        compiled = loader.compile()
    except (ImportError, FileNotFoundError) as exc:
        click.echo(f"[error] {exc}", err=True)
        sys.exit(1)

    scanner = YARAScanner(compiled_rules=compiled)
    target_path = Path(target)

    if target_path.is_file():
        matches = scanner.scan_file(target_path)
        if json_output:
            click.echo(json.dumps([
                {"rule": m.rule_name, "tags": list(m.tags), "file": m.file_path}
                for m in matches
            ], indent=2))
        elif matches:
            for m in matches:
                click.echo(f"[MATCH] {m.rule_name} — {m.file_path}")
        else:
            click.echo("[ok] No matches.")
    else:
        report = scanner.scan_directory(
            target_path, recursive=recursive, max_file_size_mb=max_size_mb
        )
        click.echo(report.summary())
        if json_output:
            click.echo(json.dumps([
                {"rule": m.rule_name, "tags": list(m.tags), "file": m.file_path}
                for m in report.matches
            ], indent=2))
        else:
            for m in report.matches:
                click.echo(f"[MATCH] {m.rule_name} — {m.file_path}")

        if report.matches:
            sys.exit(2)


@cli.command("list-rules")
@click.option("--rules-dir", required=True, type=click.Path(exists=True))
def list_rules_cmd(rules_dir: str) -> None:
    """List all rule files in a directory."""
    loader = RuleLoader(rules_dir=Path(rules_dir))
    files = loader.list_rule_files()
    if not files:
        click.echo("No rule files found.")
        return
    for f in files:
        click.echo(str(f))
