"""CLI for DNS DGA Detector."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .core import analyse_domain_list, classify_domain


@click.command()
@click.argument("input_file", type=click.Path(exists=True), required=False)
@click.option("--domain", "-d", multiple=True, help="Domain to classify.")
@click.option("--threshold", default=0.5, show_default=True, help="DGA confidence threshold.")
@click.option("--show-all", is_flag=True, help="Show benign domains too.")
def cli(
    input_file: str | None,
    domain: tuple[str, ...],
    threshold: float,
    show_all: bool,
) -> None:
    """Detect DGA-generated domains from a list or file."""
    domains: list[str] = list(domain)

    if input_file:
        domains += Path(input_file).read_text(encoding="utf-8").splitlines()

    if not domains:
        click.echo("[error] Provide --domain or INPUT_FILE", err=True)
        sys.exit(1)

    verdicts = analyse_domain_list(domains)
    found_dga = False

    for v in verdicts:
        if v.is_dga or show_all:
            tag = "[DGA]" if v.is_dga else "[OK ]"
            click.echo(
                f"{tag} {v.domain:<40} conf={v.confidence:.2f}  "
                f"ent={v.entropy:.2f}  len={v.length}  {v.reason}"
            )
            if v.is_dga:
                found_dga = True

    if found_dga:
        sys.exit(2)
