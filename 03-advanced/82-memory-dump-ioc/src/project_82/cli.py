"""Memory Dump IOC Extractor — CLI interface."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from project_82.core import IOC_TYPES, IOCExtractor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Memory Dump IOC Extractor — extract IPs, domains, URLs, hashes from memory dumps."""


@cli.command("extract")
@click.argument("dump_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write JSON report to file.")
@click.option("--types", "-t", multiple=True,
              type=click.Choice(list(IOC_TYPES)),
              help="IOC types to display (default: all).")
@click.option("--max-gb", default=4.0, show_default=True, help="Maximum file size in GB.")
def extract_cmd(dump_file: Path, output: Path | None, types: tuple[str, ...], max_gb: float) -> None:
    """Extract IOCs from a memory dump or binary file."""
    extractor = IOCExtractor()
    click.echo(f"Extracting IOCs from {dump_file.name} ({dump_file.stat().st_size:,} bytes) …")
    try:
        result = extractor.extract_from_file(dump_file, max_size_gb=max_gb)
    except ValueError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        raise SystemExit(1) from exc

    click.echo(f"\nSHA256: {result.sha256}")
    click.echo(f"Total IOCs extracted: {result.total_count}")

    show_types = set(types) if types else set(IOC_TYPES)
    click.echo(f"\n{'─'*60}")
    for ioc_type in IOC_TYPES:
        if ioc_type not in show_types:
            continue
        values = sorted(set(result.iocs.get(ioc_type, [])))
        if values:
            click.echo(f"\n[{ioc_type.upper()}] ({len(values)})")
            for v in values[:50]:
                click.echo(f"  {v}")
            if len(values) > 50:
                click.echo(f"  … and {len(values) - 50} more")

    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")


@cli.command("scan-text")
@click.argument("text_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def scan_text_cmd(text_file: Path, output: Path | None) -> None:
    """Extract IOCs from a text or log file."""
    extractor = IOCExtractor()
    data = text_file.read_bytes()
    iocs = extractor.extract_from_bytes(data)
    total = sum(len(v) for v in iocs.values())
    click.echo(f"Scanned {text_file.name} — {total} IOC(s) found")
    for ioc_type, values in iocs.items():
        if values:
            click.echo(f"\n[{ioc_type.upper()}] ({len(values)})")
            for v in sorted(values)[:20]:
                click.echo(f"  {v}")
    if output:
        data_out = {k: sorted(v) for k, v in iocs.items()}
        output.write_text(json.dumps(data_out, indent=2))
        click.echo(f"\nReport saved to {output}")
