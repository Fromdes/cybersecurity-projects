"""CLI for Email Phishing Detector."""

from __future__ import annotations

import sys

import click

from project_72.core import analyse_email


@click.group()
def cli() -> None:
    """Email Phishing Detector — analyse emails for phishing indicators."""


@cli.command()
@click.argument("email_file", type=click.Path(exists=True))
def analyse(email_file: str) -> None:
    """Analyse EMAIL_FILE (raw .eml) for phishing."""
    with open(email_file, "rb") as fh:
        raw = fh.read()

    result = analyse_email(raw)

    click.echo(f"\nPhishing Analysis")
    click.echo(f"  Subject : {result.subject[:60]}")
    click.echo(f"  From    : {result.sender}")
    click.echo(f"  Score   : {result.score}/100")
    click.echo(f"  Verdict : {result.verdict.upper()}")
    click.echo(f"  URLs    : {len(result.urls)}")

    if result.indicators:
        click.echo("\nIndicators:")
        for ind in result.indicators:
            click.echo(f"  [{ind.category.upper():10s}] (+{ind.weight:2d}) {ind.description}")
    else:
        click.echo("\n  No phishing indicators detected.")

    if result.verdict == "phishing":
        sys.exit(1)
