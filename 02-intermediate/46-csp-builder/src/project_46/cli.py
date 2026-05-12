"""CLI for CSP Header Builder & Reporter."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .core import CSPBuilder, CSPViolationReport, parse_policy


@click.group()
def cli() -> None:
    """CSP Header Builder & Reporter — build, analyse, and parse CSP policies."""


@cli.command("build")
@click.option("--strict", is_flag=True, default=False, help="Start from strict baseline.")
@click.option("--report-uri", default="", help="Violation report endpoint.")
@click.option("--add", "additions", multiple=True, metavar="DIRECTIVE=VALUE",
              help="Add a source (e.g. script-src=https://cdn.example.com).")
@click.option("--analyse", is_flag=True, default=False, help="Print security warnings.")
def build_cmd(strict: bool, report_uri: str, additions: tuple[str, ...], analyse: bool) -> None:
    """Build and print a CSP header value."""
    builder = CSPBuilder()
    if strict:
        builder.strict()
    for addition in additions:
        if "=" not in addition:
            click.echo(f"[error] Invalid format '{addition}', use DIRECTIVE=VALUE", err=True)
            sys.exit(1)
        directive, _, value = addition.partition("=")
        builder.add(directive.strip(), value.strip())
    if report_uri:
        builder.report_only(report_uri)

    policy = builder.build()
    click.echo(policy.build())

    if analyse:
        warnings = policy.analyse()
        if warnings:
            click.echo("\n[warnings]")
            for w in warnings:
                click.echo(f"  [{w.severity.upper()}] {w.directive}: {w.message}")
        else:
            click.echo("\n[ok] No security warnings found.")


@cli.command("analyse")
@click.argument("policy_string")
def analyse_cmd(policy_string: str) -> None:
    """Analyse an existing CSP policy string for security issues."""
    policy = parse_policy(policy_string)
    warnings = policy.analyse()
    if not warnings:
        click.echo("[ok] No security warnings found.")
        return
    for w in warnings:
        click.echo(f"[{w.severity.upper()}] {w.directive}: {w.message}")


@cli.command("parse-report")
@click.argument("report_file", type=click.Path(exists=True))
def parse_report_cmd(report_file: str) -> None:
    """Parse a CSP violation report JSON file and display it."""
    raw = Path(report_file).read_text(encoding="utf-8")
    report = CSPViolationReport.from_json(raw)
    click.echo(json.dumps(report.__dict__, indent=2))
