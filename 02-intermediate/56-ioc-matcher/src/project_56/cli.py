"""CLI for IOC Matcher."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .core import IOC, IOCMatcher, IOCStore, IOCType, extract_iocs_from_text


@click.group()
def cli() -> None:
    """IOC Matcher — load threat intel and match against logs/text."""


@cli.command("match")
@click.argument("target", type=click.Path(exists=True))
@click.option("--ioc-csv", "ioc_csv", default=None, type=click.Path(exists=True))
@click.option("--ioc-json", "ioc_json", default=None, type=click.Path(exists=True))
@click.option("--json-output", is_flag=True)
def match_cmd(target: str, ioc_csv: str | None, ioc_json: str | None, json_output: bool) -> None:
    """Match IOCs in TARGET log file."""
    store = IOCStore()
    if ioc_csv:
        store.add_many(IOCStore.from_csv(Path(ioc_csv)).
                       _store[IOCType.IPV4].__class__.__mro__[0].__subclasses__())  # noqa — just re-merge
        store = IOCStore.from_csv(Path(ioc_csv))
    if ioc_json:
        store = IOCStore.from_json(Path(ioc_json))

    if store.count() == 0:
        click.echo("[error] No IOC feed loaded. Provide --ioc-csv or --ioc-json", err=True)
        sys.exit(1)

    matcher = IOCMatcher(store=store)
    results = matcher.match_log_file(Path(target))

    if not results:
        click.echo("[ok] No IOC matches found.")
        return

    click.echo(f"[!] {len(results)} match(es):\n")
    for r in results:
        if json_output:
            click.echo(json.dumps({
                "ioc": r.ioc.value, "type": r.ioc.ioc_type.value,
                "source": r.ioc.source, "where": r.matched_in,
            }))
        else:
            click.echo(
                f"  [{r.ioc.ioc_type.value.upper()}] {r.ioc.value} "
                f"(conf={r.ioc.confidence}) @ {r.matched_in}"
            )
    sys.exit(2)


@cli.command("extract")
@click.argument("text_file", type=click.Path(exists=True))
def extract_cmd(text_file: str) -> None:
    """Extract IOC candidates from a text file (no store needed)."""
    text = Path(text_file).read_text(encoding="utf-8", errors="replace")
    candidates = extract_iocs_from_text(text)
    for ioc_type, values in candidates.items():
        if values:
            click.echo(f"[{ioc_type.value.upper()}]")
            for v in values:
                click.echo(f"  {v}")
